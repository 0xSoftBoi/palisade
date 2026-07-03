"""Checkpoint and chain tests (Definition 2)."""

from palisade.checkpoint import CheckpointBody, CheckpointCertificate, verify_chain
from palisade.hashing import sha256
from palisade.log import PalisadeLog, quorum_size
from palisade.records import Artifact


def _artifact(i):
    return Artifact(content_hash=sha256(f"c{i}".encode()), artifact_type="doc")


def test_quorum_arithmetic():
    assert quorum_size(4, 1) == 3
    assert quorum_size(7, 2) == 5
    assert quorum_size(13, 4) == 9


def test_checkpoint_verifies_with_quorum(validator_set):
    validators, registry = validator_set
    log = PalisadeLog(n=4, f=1, registry=registry)
    for i in range(5):
        log.append_record(_artifact(i))
    cert = log.checkpoint(validators)
    assert cert.verify(registry, log.quorum)
    assert len(cert.signatures) == 4
    assert cert.body.size == 5


def test_checkpoint_fails_below_quorum(validator_set):
    validators, registry = validator_set
    log = PalisadeLog(n=4, f=1, registry=registry)
    log.append_record(_artifact(0))
    body = log.build_checkpoint_body()
    # Only 2 signatures, quorum is 3.
    cert = CheckpointCertificate(
        body=body, signatures=[validators[0].sign_checkpoint(body), validators[1].sign_checkpoint(body)]
    )
    assert not cert.verify(registry, log.quorum)


def test_checkpoint_rejects_duplicate_signer(validator_set):
    validators, registry = validator_set
    log = PalisadeLog(n=4, f=1, registry=registry)
    log.append_record(_artifact(0))
    body = log.build_checkpoint_body()
    sig = validators[0].sign_checkpoint(body)
    cert = CheckpointCertificate(body=body, signatures=[sig, sig, sig])
    assert not cert.verify(registry, log.quorum)


def test_checkpoint_rejects_unregistered_signer(validator_set):
    validators, registry = validator_set
    from tests.conftest import make_validators

    (rogue,), _ = make_validators(1)
    log = PalisadeLog(n=4, f=1, registry=registry)
    log.append_record(_artifact(0))
    body = log.build_checkpoint_body()
    sigs = [v.sign_checkpoint(body) for v in validators[:2]] + [rogue.sign_checkpoint(body)]
    cert = CheckpointCertificate(body=body, signatures=sigs)
    assert not cert.verify(registry, log.quorum)


def test_checkpoint_chain_verifies(validator_set):
    validators, registry = validator_set
    log = PalisadeLog(n=4, f=1, registry=registry)
    for epoch in range(3):
        for i in range(4):
            log.append_record(_artifact(epoch * 10 + i))
        log.checkpoint(validators)
    assert verify_chain(log.chain, registry, log.quorum)
    assert [c.epoch for c in log.chain] == [0, 1, 2]


def test_chain_rejects_broken_prev_link(validator_set):
    validators, registry = validator_set
    log = PalisadeLog(n=4, f=1, registry=registry)
    for epoch in range(2):
        log.append_record(_artifact(epoch))
        log.checkpoint(validators)
    # Tamper: replace second cert's prev_hash.
    bad_body = CheckpointBody(
        epoch=log.chain[1].epoch,
        root=log.chain[1].body.root,
        size=log.chain[1].body.size,
        prev_hash=b"\x00" * 32,
    )
    log.chain[1] = CheckpointCertificate(body=bad_body, signatures=log.chain[1].signatures)
    assert not verify_chain(log.chain, registry, log.quorum)
