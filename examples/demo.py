"""PALISADE end-to-end demonstration.

Run with:  python examples/demo.py

Walks the full lifecycle: provenance records enter a history tree, validators
close an epoch with a quorum-signed checkpoint, the checkpoint is anchored
outward, an auditor proves inclusion offline, and then two failure modes --
validator equivocation (Theorem 1) and OTS index reuse (Proposition 1) -- are
caught and turned into transferable culpability proofs.
"""

from __future__ import annotations

import os

from palisade import (
    Anchor,
    AnchorMedium,
    Artifact,
    Attestation,
    CheckpointBody,
    CheckpointCertificate,
    ContentStore,
    CustodyEvent,
    HardwareModule,
    HashSigner,
    PalisadeLog,
    ReuseMonitor,
    Validator,
    ValidatorRegistry,
    extract_equivocation,
    sha256,
    verify_against_anchor,
    verify_chain,
)


def rule(title: str) -> None:
    print("\n" + "=" * 68)
    print(title)
    print("=" * 68)


def build_validators(n: int, f: int, height: int = 6):
    registry = ValidatorRegistry()
    validators = []
    for i in range(n):
        v = Validator(f"validator-{i}", HardwareModule(os.urandom(32), height=height))
        registry.register(v.id, v.public_key)
        validators.append(v)
    print(f"  registered n={n} validators (f={f}, quorum=2f+1={2*f+1}), "
          f"each holding a hash-based key of capacity 2^{height}={1<<height}")
    return validators, registry


def main() -> None:
    n, f = 4, 1
    rule("1. Deployment: register a closed validator set (contractual membership)")
    validators, registry = build_validators(n, f)
    store = ContentStore()
    log = PalisadeLog(n=n, f=f, registry=registry)
    medium = AnchorMedium()

    rule("2. Records: an artifact, its custody chain, and an auditor attestation")
    blob = b"firmware-image-v1.2.3"
    content_hash = store.put(blob)
    artifact = Artifact(content_hash=content_hash, artifact_type="firmware",
                        meta={"vendor": "acme", "part": "PN-4471"})
    art_idx = log.append_record(artifact)
    log.append_record(CustodyEvent(artifact_hash=content_hash, holder="factory",
                                   action="created", location="Plant-3", timestamp=1))
    log.append_record(CustodyEvent(artifact_hash=content_hash, holder="depot",
                                   action="received", location="KAF", timestamp=2))
    log.append_record(Attestation(target_hash=content_hash,
                                  claim="conforms:DFARS-252.246-7007",
                                  attester="independent-auditor"))
    print(f"  appended {log.size} records; history-tree root = {log.root().hex()[:16]}...")

    rule("3. Checkpoint: validators co-sign the epoch, then anchor it outward")
    cert0 = log.checkpoint(validators)
    anchor = medium.anchor(cert0, time=1_700_000_000)
    print(f"  epoch 0 checkpoint: size={cert0.body.size}, "
          f"signers={cert0.signer_ids()}")
    print(f"  on-log OTS indices (K3): "
          f"{[vs.signature.index for vs in cert0.signatures]}")
    print(f"  H(CP_0) anchored at t=1700000000: {anchor.digest.hex()[:16]}...")

    rule("4. Offline audit: verify chain, then prove the artifact's inclusion")
    print(f"  chain verifies: {verify_chain(log.chain, registry, log.quorum)}")
    incl = log.inclusion_proof(art_idx, size=cert0.body.size)
    print(f"  inclusion proof for artifact ({len(incl.audit_path)} hashes) "
          f"verifies: {incl.verify(artifact.canonical(), cert0.body.root)}")

    rule("5. Theorem 2: an adversary with ALL keys after t_e cannot rewrite")
    for i in range(5):
        log.append_record(Artifact(content_hash=sha256(f"more-{i}".encode()),
                                    artifact_type="doc"))
    log.checkpoint(validators)
    good_proof = log.tree.consistency_proof(cert0.body.size, log.size)
    v_ok = verify_against_anchor(anchor, cert0, log.root(), log.size, good_proof.path)
    print(f"  honest extension accepted: {v_ok.accepted} ({v_ok.reason})")

    forged = PalisadeLog(n=n, f=f, registry=registry)
    for i in range(6):
        forged.append_record(Artifact(content_hash=sha256(f"forged-{i}".encode()),
                                       artifact_type="doc"))
    bogus = forged.tree.consistency_proof(min(cert0.body.size, forged.size), forged.size)
    v_bad = verify_against_anchor(anchor, cert0, forged.root(), forged.size, bogus.path)
    print(f"  forged divergent history accepted: {v_bad.accepted} ({v_bad.reason})")

    rule("6. Theorem 1: two conflicting checkpoints -> culpability proof")
    body_a = CheckpointBody(epoch=9, root=sha256(b"A"), size=100, prev_hash=b"\x00" * 32)
    body_b = CheckpointBody(epoch=9, root=sha256(b"B"), size=100, prev_hash=b"\x00" * 32)
    byz = [0, 1, 2]  # validators 0,1,2 equivocate; validator 3 stays honest
    cert_a = CheckpointCertificate(body_a, [validators[i].sign_checkpoint(body_a) for i in byz])
    cert_b = CheckpointCertificate(body_b, [validators[i].sign_checkpoint(body_b) for i in byz])
    proof = extract_equivocation(cert_a, cert_b, registry)
    print(f"  culprits (>= f+1 = {f+1}): {proof.culprit_ids()}")
    print(f"  proof verifies for any third party: {proof.verify(registry)}")
    print(f"  honest validator-3 implicated: {'validator-3' in proof.culprit_ids()}")

    rule("7. Proposition 1: on-log OTS index reuse is O(1)-detectable")
    seed = os.urandom(32)
    rogue = HashSigner(seed, height=4)
    reg2 = ValidatorRegistry({"rogue": rogue.public_key()})
    monitor = ReuseMonitor()
    monitor.observe("rogue", b"batch-A", rogue.sign_index(0, b"batch-A"))
    reuse = monitor.observe("rogue", b"batch-B", rogue.sign_index(0, b"batch-B"))
    print(f"  reuse of index {reuse.index} detected; proof verifies: "
          f"{reuse.verify(reg2)}")

    rule("8. Algorithm 1: a vote round commits on a 2f+1 quorum")
    from palisade.consensus import Proposal, VoteCollector, cast_vote
    from palisade.hashing import empty_root

    prop = Proposal(epoch=0, view=0, h_prev=empty_root(),
                    records=[Artifact(content_hash=sha256(f"batch-{i}".encode()),
                                      artifact_type="doc") for i in range(3)])
    collector = VoteCollector(registry, quorum=log.quorum)
    for v in validators[:3]:
        collector.add(cast_vote(v, prop, local_root=prop.h_prev))
    commit = collector.try_commit(prop.epoch, prop.view, prop.batch_hash(), prop.h_prev)
    print(f"  committed with {len(commit.votes)} matching votes "
          f"(quorum 2f+1={log.quorum}); verifies: {commit.verify(registry, log.quorum)}")

    # A Byzantine validator double-votes in the same round -> per-round proof.
    prop2 = Proposal(epoch=0, view=0, h_prev=empty_root(),
                     records=[Artifact(content_hash=sha256(b"conflicting"), artifact_type="doc")])
    ev = collector.add(cast_vote(validators[3], prop, local_root=prop.h_prev))
    ev = collector.add(cast_vote(validators[3], prop2, local_root=prop2.h_prev)) or ev
    print(f"  vote-granularity equivocation caught for {ev.validator_id}: "
          f"{ev.verify(registry)}")

    rule("9. Accountable refusal: f+1 non-inclusions turn censorship into evidence")
    from palisade.consensus import collect_censorship_evidence, sign_non_inclusion

    pending = sha256(b"well-formed-but-suppressed-record")
    stmts = [sign_non_inclusion(validators[i], pending, epoch=0) for i in range(f + 1)]
    censored = collect_censorship_evidence(stmts, registry, threshold=f + 1)
    print(f"  {len(stmts)} signed non-inclusions (>= f+1={f+1}); "
          f"evidence verifies: {censored.verify(registry, f + 1)}")

    rule("10. Client batch signing: one signature covers a whole batch (section 9.2)")
    from palisade.batch import BatchAccumulator
    from palisade.signatures import HardwareModule

    device = HardwareModule(os.urandom(32), height=6)
    acc = BatchAccumulator()
    for i in range(1024):
        acc.add(Artifact(content_hash=sha256(f"telemetry-{i}".encode()),
                         artifact_type="telemetry").canonical())
    before = device.next_index
    signed = acc.seal(device.sign_next)
    print(f"  sealed B={signed.size} records with {device.next_index - before} signature; "
          f"per-record proof depth = {len(signed.proof_for(0).audit_path)} hashes")
    print(f"  record 500 proof verifies: {signed.proof_for(500).verify(device.public_key)}")

    rule("Done. Every check above reduced to SHA-256 alone.")


if __name__ == "__main__":
    main()
