"""Anchored fork bound tests (Theorem 2)."""

from palisade.anchoring import AnchorMedium, verify_against_anchor
from palisade.hashing import sha256
from palisade.log import PalisadeLog
from palisade.records import Artifact

from tests.conftest import make_validators


def _artifact(i):
    return Artifact(content_hash=sha256(f"c{i}".encode()), artifact_type="doc")


def _log_with_epoch(validators, registry, n_records):
    log = PalisadeLog(n=4, f=1, registry=registry)
    for i in range(n_records):
        log.append_record(_artifact(i))
    cert = log.checkpoint(validators)
    return log, cert


def test_honest_extension_is_accepted():
    validators, registry = make_validators(4)
    log, cert = _log_with_epoch(validators, registry, 4)
    medium = AnchorMedium()
    anchor = medium.anchor(cert, time=1000)

    # Extend the log honestly, then prove the extension against the anchor.
    for i in range(4, 9):
        log.append_record(_artifact(i))
    later_root = log.root()
    later_size = log.size
    proof = log.tree.consistency_proof(cert.body.size, later_size)

    verdict = verify_against_anchor(anchor, cert, later_root, later_size, proof.path)
    assert verdict.accepted, verdict.reason


def test_divergent_history_is_rejected():
    validators, registry = make_validators(4)
    log, cert = _log_with_epoch(validators, registry, 4)
    medium = AnchorMedium()
    anchor = medium.anchor(cert, time=1000)

    # Adversary builds a DIFFERENT history that does not extend the anchored one.
    forged = PalisadeLog(n=4, f=1, registry=registry)
    for i in range(6):
        forged.append_record(_artifact(1000 + i))  # different records
    forged_root = forged.root()
    # It tries to pass off a consistency proof from its own tree.
    bogus_proof = forged.tree.consistency_proof(min(cert.body.size, forged.size), forged.size)

    verdict = verify_against_anchor(anchor, cert, forged_root, forged.size, bogus_proof.path)
    assert not verdict.accepted


def test_wrong_checkpoint_rejected():
    validators, registry = make_validators(4)
    log, cert = _log_with_epoch(validators, registry, 4)
    medium = AnchorMedium()
    anchor = medium.anchor(cert, time=1000)

    # Present a different checkpoint that does not hash to the anchor.
    other_log, other_cert = _log_with_epoch(*make_validators(4), 4)
    verdict = verify_against_anchor(
        anchor, other_cert, other_log.root(), other_log.size, []
    )
    assert not verdict.accepted
    assert "anchored digest" in verdict.reason


def test_withheld_proof_rejected():
    validators, registry = make_validators(4)
    log, cert = _log_with_epoch(validators, registry, 4)
    medium = AnchorMedium()
    anchor = medium.anchor(cert, time=1000)
    for i in range(4, 9):
        log.append_record(_artifact(i))
    # Case 3: no consistency proof supplied for a longer presented state.
    verdict = verify_against_anchor(anchor, cert, log.root(), log.size, [])
    assert not verdict.accepted
