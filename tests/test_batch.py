"""Client batch-signing tests (section 9, limitation 2)."""

import os

import pytest

from palisade.batch import BatchAccumulator
from palisade.hashing import sha256
from palisade.records import Artifact
from palisade.signatures import HardwareModule, verify_signature


def _client():
    mod = HardwareModule(os.urandom(32), height=4)
    return mod, mod.public_key


def test_batch_amortizes_one_signature_over_all_records():
    mod, pk = _client()
    acc = BatchAccumulator()
    records = [Artifact(content_hash=sha256(f"r{i}".encode()), artifact_type="doc").canonical()
               for i in range(100)]
    acc.add_all(records)

    before = mod.next_index
    batch = acc.seal(mod.sign_next)
    after = mod.next_index
    assert after - before == 1  # exactly one signature for the whole batch
    assert batch.size == 100


def test_every_record_proof_verifies():
    mod, pk = _client()
    acc = BatchAccumulator()
    for i in range(37):  # non-power-of-two batch
        acc.add(f"record-{i}".encode())
    batch = acc.seal(mod.sign_next)
    for i in range(37):
        proof = batch.proof_for(i)
        assert proof.verify(pk), f"record {i}"


def test_proof_rejects_tampered_record():
    mod, pk = _client()
    acc = BatchAccumulator()
    acc.add_all([f"r{i}".encode() for i in range(8)])
    batch = acc.seal(mod.sign_next)
    proof = batch.proof_for(3)
    tampered = type(proof)(
        record=b"forged",
        index=proof.index,
        batch_size=proof.batch_size,
        audit_path=proof.audit_path,
        batch_root=proof.batch_root,
        signature=proof.signature,
    )
    assert not tampered.verify(pk)


def test_proof_rejects_wrong_public_key():
    mod, pk = _client()
    other = HardwareModule(os.urandom(32), height=4).public_key
    acc = BatchAccumulator()
    acc.add_all([f"r{i}".encode() for i in range(4)])
    batch = acc.seal(mod.sign_next)
    assert not batch.proof_for(0).verify(other)


def test_batch_signature_is_over_the_root():
    mod, pk = _client()
    acc = BatchAccumulator()
    acc.add_all([b"a", b"b", b"c"])
    batch = acc.seal(mod.sign_next)
    assert verify_signature(pk, batch.root, batch.signature)


def test_empty_batch_rejected():
    mod, pk = _client()
    with pytest.raises(ValueError):
        BatchAccumulator().seal(mod.sign_next)
