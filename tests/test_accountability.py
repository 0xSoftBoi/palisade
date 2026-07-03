"""Accountability tests: Theorem 1 (equivocation) and Proposition 1 (reuse)."""

import os

from palisade.accountability import ReuseMonitor, extract_equivocation
from palisade.checkpoint import (
    CheckpointBody,
    CheckpointCertificate,
    ValidatorRegistry,
)
from palisade.hashing import sha256
from palisade.signatures import HashSigner

from tests.conftest import make_validators


def _conflicting_certs(validators, signer_ids, epoch=0):
    """Two epoch-`epoch` certificates with different payloads, both signed by
    the same set of validators (i.e. those validators equivocate)."""
    body_a = CheckpointBody(epoch=epoch, root=sha256(b"history-A"), size=10, prev_hash=b"\x00" * 32)
    body_b = CheckpointBody(epoch=epoch, root=sha256(b"history-B"), size=10, prev_hash=b"\x00" * 32)
    sigs_a = [validators[i].sign_checkpoint(body_a) for i in signer_ids]
    sigs_b = [validators[i].sign_checkpoint(body_b) for i in signer_ids]
    return (
        CheckpointCertificate(body=body_a, signatures=sigs_a),
        CheckpointCertificate(body=body_b, signatures=sigs_b),
    )


def test_equivocation_yields_culpability_proof():
    validators, registry = make_validators(4)
    # v0, v1, v2 all equivocate; v3 stays honest.
    cert_a, cert_b = _conflicting_certs(validators, [0, 1, 2])
    proof = extract_equivocation(cert_a, cert_b, registry)
    assert proof is not None
    assert proof.verify(registry)
    assert proof.culprit_ids() == ["validator-0", "validator-1", "validator-2"]


def test_culpability_never_implicates_honest_validator():
    validators, registry = make_validators(4)
    cert_a, cert_b = _conflicting_certs(validators, [0, 1, 2])
    proof = extract_equivocation(cert_a, cert_b, registry)
    assert "validator-3" not in proof.culprit_ids()


def test_at_least_f_plus_one_culprits():
    # n=4, f=1: two verifying quorums (2f+1=3) must intersect in >= f+1 = 2.
    validators, registry = make_validators(4)
    cert_a, cert_b = _conflicting_certs(validators, [0, 1, 2])
    proof = extract_equivocation(cert_a, cert_b, registry)
    assert len(proof.culprits) >= 2


def test_same_payload_is_not_equivocation():
    validators, registry = make_validators(4)
    body = CheckpointBody(epoch=0, root=sha256(b"same"), size=5, prev_hash=b"\x00" * 32)
    cert_a = CheckpointCertificate(body=body, signatures=[validators[0].sign_checkpoint(body)])
    cert_b = CheckpointCertificate(body=body, signatures=[validators[1].sign_checkpoint(body)])
    assert extract_equivocation(cert_a, cert_b, registry) is None


def test_different_epoch_is_not_equivocation():
    validators, registry = make_validators(4)
    a, _ = _conflicting_certs(validators, [0, 1, 2], epoch=0)
    _, b = _conflicting_certs(validators, [0, 1, 2], epoch=1)
    assert extract_equivocation(a, b, registry) is None


def test_forged_proof_does_not_verify():
    # A proof naming a validator who never signed the conflicting body fails.
    validators, registry = make_validators(4)
    cert_a, cert_b = _conflicting_certs(validators, [0, 1, 2])
    proof = extract_equivocation(cert_a, cert_b, registry)
    # Swap in a signature from an honest validator's key -> verification fails
    # because that validator never produced signature_b.
    tampered = proof.culprits[0]
    forged = type(tampered)(
        validator_id="validator-3",
        epoch=tampered.epoch,
        body_a=tampered.body_a,
        signature_a=tampered.signature_a,
        body_b=tampered.body_b,
        signature_b=tampered.signature_b,
    )
    assert not forged.verify(registry)


# --- Proposition 1: OTS index reuse -----------------------------------------

def test_reuse_monitor_flags_repeat_index():
    seed = os.urandom(32)
    signer = HashSigner(seed, height=3)
    registry = ValidatorRegistry({"validator-x": signer.public_key()})
    monitor = ReuseMonitor()

    sig1 = signer.sign_index(0, b"message-one")
    assert monitor.observe("validator-x", b"message-one", sig1) is None

    # Reuse index 0 on a different message.
    sig2 = signer.sign_index(0, b"message-two")
    proof = monitor.observe("validator-x", b"message-two", sig2)
    assert proof is not None
    assert proof.verify(registry)
    assert proof.index == 0


def test_reuse_monitor_ignores_rebroadcast():
    seed = os.urandom(32)
    signer = HashSigner(seed, height=3)
    monitor = ReuseMonitor()
    sig = signer.sign_index(1, b"same")
    assert monitor.observe("v", b"same", sig) is None
    assert monitor.observe("v", b"same", sig) is None  # identical -> not reuse


def test_distinct_indices_not_flagged():
    seed = os.urandom(32)
    signer = HashSigner(seed, height=3)
    monitor = ReuseMonitor()
    assert monitor.observe("v", b"a", signer.sign_index(0, b"a")) is None
    assert monitor.observe("v", b"b", signer.sign_index(1, b"b")) is None
    assert monitor.observe("v", b"c", signer.sign_index(2, b"c")) is None


def test_reuse_proof_matches_theorem1_form():
    # Prop 1 says the reuse pair is "exactly the form in Theorem 1(b)":
    # two valid signatures under one key over distinct messages.
    seed = os.urandom(32)
    signer = HashSigner(seed, height=2)
    registry = ValidatorRegistry({"v": signer.public_key()})
    monitor = ReuseMonitor()
    monitor.observe("v", b"m1", signer.sign_index(0, b"m1"))
    proof = monitor.observe("v", b"m2", signer.sign_index(0, b"m2"))
    assert proof.message_a != proof.message_b
    assert proof.verify(registry)
