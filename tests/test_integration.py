"""End-to-end: provenance records -> checkpoints -> offline audit + anchoring."""

from palisade.anchoring import AnchorMedium, verify_against_anchor
from palisade.checkpoint import verify_chain
from palisade.hashing import sha256
from palisade.log import PalisadeLog
from palisade.records import Artifact, Attestation, CustodyEvent
from palisade.store import ContentStore

from tests.conftest import make_validators


def test_full_provenance_lifecycle():
    validators, registry = make_validators(4, height=4)
    store = ContentStore()
    log = PalisadeLog(n=4, f=1, registry=registry)
    medium = AnchorMedium()

    # 1. An artifact enters the log.
    blob = b"firmware-image-v1.2.3"
    content_hash = store.put(blob)
    artifact = Artifact(content_hash=content_hash, artifact_type="firmware",
                        meta={"vendor": "acme", "part": "PN-4471"})
    art_idx = log.append_record(artifact)

    # 2. A chain of custody accrues.
    log.append_record(CustodyEvent(artifact_hash=content_hash, holder="factory",
                                   action="created", location="Plant-3", timestamp=1))
    log.append_record(CustodyEvent(artifact_hash=content_hash, holder="depot",
                                   action="received", location="KAF", timestamp=2))

    # 3. An independent auditor attests.
    log.append_record(Attestation(target_hash=content_hash, claim="conforms:DFARS-252.246-7007",
                                  attester="independent-auditor"))

    # 4. Close the epoch with a quorum-signed checkpoint and anchor it.
    cert0 = log.checkpoint(validators)
    anchor = medium.anchor(cert0, time=1_700_000_000)

    # 5. Offline audit: a verifier holding only genesis keys checks the chain,
    #    then proves the artifact's inclusion against the checkpoint root.
    assert verify_chain(log.chain, registry, log.quorum)
    incl = log.inclusion_proof(art_idx, size=cert0.body.size)
    assert incl.verify(artifact.canonical(), cert0.body.root)

    # 6. More epochs accrue; the anchored history remains provably extended.
    for e in range(2):
        for i in range(3):
            log.append_record(Artifact(content_hash=sha256(f"x{e}{i}".encode()), artifact_type="doc"))
        log.checkpoint(validators)

    assert verify_chain(log.chain, registry, log.quorum)
    later_proof = log.tree.consistency_proof(cert0.body.size, log.size)
    verdict = verify_against_anchor(anchor, cert0, log.root(), log.size, later_proof.path)
    assert verdict.accepted, verdict.reason

    # 7. The artifact remains provable against the *latest* root too.
    incl_latest = log.inclusion_proof(art_idx, size=log.size)
    assert incl_latest.verify(artifact.canonical(), log.root())


def test_stateful_key_indices_are_disclosed_on_log():
    # K3: every checkpoint signature carries its OTS index on-log.
    validators, registry = make_validators(4)
    log = PalisadeLog(n=4, f=1, registry=registry)
    for epoch in range(3):
        log.append_record(Artifact(content_hash=sha256(str(epoch).encode()), artifact_type="doc"))
        cert = log.checkpoint(validators)
        for vs in cert.signatures:
            # Index advances by one per epoch for each validator.
            assert vs.signature.index == epoch
