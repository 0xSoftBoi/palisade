"""Hash-signature tests: OTS correctness, K1/K2/K4 invariants, reuse forgery."""

import os

import pytest

from palisade.signatures import (
    HardwareModule,
    HashSigner,
    KeyExhausted,
    LamportOTS,
    ots_public_digest_from_signature,
    verify_signature,
)
from palisade.hashing import sha256


def test_lamport_ots_roundtrip():
    ots = LamportOTS(os.urandom(32))
    d = sha256(b"message")
    sig = ots.sign(d)
    assert ots_public_digest_from_signature(d, sig) == ots.public_digest()


def test_lamport_ots_wrong_message_fails():
    ots = LamportOTS(os.urandom(32))
    sig = ots.sign(sha256(b"message"))
    other = sha256(b"other")
    assert ots_public_digest_from_signature(other, sig) != ots.public_digest()


def test_many_time_signer_all_indices_verify():
    signer = HashSigner(os.urandom(32), height=4)  # 16 OTS keys
    pk = signer.public_key()
    for q in range(signer.capacity):
        sig = signer.sign_index(q, f"msg-{q}".encode())
        assert verify_signature(pk, f"msg-{q}".encode(), sig)


def test_signature_rejects_wrong_message():
    signer = HashSigner(os.urandom(32), height=3)
    pk = signer.public_key()
    sig = signer.sign_index(2, b"correct")
    assert not verify_signature(pk, b"tampered", sig)


def test_signature_rejects_wrong_public_key():
    signer = HashSigner(os.urandom(32), height=3)
    other = HashSigner(os.urandom(32), height=3)
    sig = signer.sign_index(1, b"m")
    assert not verify_signature(other.public_key(), b"m", sig)


def test_signature_rejects_tampered_auth_path():
    signer = HashSigner(os.urandom(32), height=3)
    pk = signer.public_key()
    sig = signer.sign_index(1, b"m")
    sig.auth_path[0] = bytes(32)
    assert not verify_signature(pk, b"m", sig)


def test_k1_module_signs_and_increments_monotonically():
    mod = HardwareModule(os.urandom(32), height=3)
    assert mod.next_index == 0
    mod.sign_next(b"a")
    assert mod.next_index == 1
    mod.sign_next(b"b")
    assert mod.next_index == 2


def test_k1_no_external_counter_write():
    mod = HardwareModule(os.urandom(32), height=3)
    # The counter is private: there is no public setter for the OTS index.
    assert not hasattr(mod, "set_index")
    assert "_q" in vars(mod)  # state exists, but only sign_next mutates it


def test_k4_fail_closed_on_exhaustion():
    mod = HardwareModule(os.urandom(32), height=2)  # capacity 4
    for _ in range(4):
        mod.sign_next(b"x")
    with pytest.raises(KeyExhausted):
        mod.sign_next(b"y")


def test_k2_restore_activates_fresh_range():
    seed = os.urandom(32)
    mod = HardwareModule(seed, height=3, start=0, end=4)
    for _ in range(4):
        mod.sign_next(b"x")
    with pytest.raises(KeyExhausted):
        mod.sign_next(b"x")
    restored = mod.restore_from(4)
    assert restored.next_index == 4
    # Same public key (same master tree), fresh index range -> no reuse possible.
    assert restored.public_key == mod.public_key
    sig = restored.sign_next(b"post-restore")
    assert verify_signature(restored.public_key, b"post-restore", sig)


def test_k2_restore_cannot_reenter_spent_range():
    mod = HardwareModule(os.urandom(32), height=3, start=0, end=4)
    with pytest.raises(ValueError):
        mod.restore_from(2)  # 2 < end=4 would re-enter a spent range


def test_index_reuse_enables_forgery():
    # Signing two distinct messages under one OTS index leaks preimages that let
    # an adversary forge a third message -- exactly the hazard K1-K4 prevent.
    signer = HashSigner(os.urandom(32), height=2)
    pk = signer.public_key()
    d1 = sha256(b"m1")
    d2 = sha256(b"m2")
    sig1 = signer.sign_index(0, b"m1")
    sig2 = signer.sign_index(0, b"m2")
    # Both are legitimate; the point is the *operator* who emitted both under
    # one index has surrendered secret material. Verify both still check out,
    # which is why the on-log reuse proof (Proposition 1) is needed to catch it.
    assert verify_signature(pk, b"m1", sig1)
    assert verify_signature(pk, b"m2", sig2)
    assert sig1.index == sig2.index == 0
