"""Sigsum interop: does PALISADE's attribution survive a foreign format?

These tests sign real Ed25519 over byte-exact sigsum/C2SP messages. The headline
test is :func:`test_native_predicate_falsely_accuses_honest_witness`, which
records the failure this exercise was run to find.
"""

import base64
import hashlib

import pytest

from palisade.interop.sigsum import (
    Checkpoint,
    ConflictKind,
    Cosignature,
    NoteSignature,
    SigsumFormatError,
    TreeHead,
    WitnessRegistry,
    conflict_verdict,
    conflicts_by_signed_bytes,
    cosignature_message,
    extract_witness_equivocation,
    guaranteed_culprits,
    key_id,
    parse_checkpoint,
    policy_supports_attribution,
)

ed25519 = pytest.importorskip(
    "cryptography.hazmat.primitives.asymmetric.ed25519",
    reason="Ed25519 needed to sign byte-exact sigsum messages",
)
Ed25519PrivateKey = ed25519.Ed25519PrivateKey


def verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


ORIGIN = "sigsum.org/v1/tree/" + "d9" * 32


def _root(tag: bytes) -> bytes:
    return hashlib.sha256(tag).digest()


def _witness(name: str):
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes_raw()
    return name, sk, pk


def _cosign(name, sk, head: TreeHead, timestamp: int) -> Cosignature:
    msg = cosignature_message(head, timestamp)
    return Cosignature(witness=name, tree_head=head, timestamp=timestamp,
                       signature=sk.sign(msg))


# --- format conformance ------------------------------------------------------

def test_tree_head_serialization_is_byte_exact():
    head = TreeHead(origin=ORIGIN, size=15368405, root_hash=_root(b"r"))
    expected = (
        ORIGIN + "\n15368405\n"
        + base64.b64encode(_root(b"r")).decode() + "\n"
    ).encode()
    assert head.serialize() == expected


def test_cosignature_message_matches_c2sp_layout():
    head = TreeHead(origin=ORIGIN, size=15368405, root_hash=_root(b"r"))
    msg = cosignature_message(head, 1679315147)
    lines = msg.decode().split("\n")
    assert lines[0] == "cosignature/v1"
    assert lines[1] == "time 1679315147"
    assert lines[2] == ORIGIN
    assert lines[3] == "15368405"
    assert lines[5] == ""  # trailing newline
    assert msg.endswith(head.serialize())


def test_key_id_matches_c2sp_derivation():
    name, _sk, pk = _witness("witness.example.org")
    expected = hashlib.sha256(
        name.encode() + b"\n" + bytes([0x04]) + pk
    ).digest()[:4]
    assert key_id(name, pk) == expected
    assert len(key_id(name, pk)) == 4


def test_checkpoint_round_trips_through_note_format():
    head = TreeHead(origin=ORIGIN, size=42, root_hash=_root(b"x"))
    name, sk, pk = _witness("w1")
    sig = NoteSignature(name=name, key_id=key_id(name, pk),
                        signature=sk.sign(head.serialize()))
    cp = Checkpoint(tree_head=head, signatures=[sig])
    parsed = parse_checkpoint(cp.serialize())
    assert parsed.tree_head == head
    assert parsed.signatures[0].name == name
    assert parsed.signatures[0].signature == sig.signature


def test_parser_rejects_leading_zero_size():
    bad = (ORIGIN + "\n007\n" + base64.b64encode(_root(b"a")).decode() + "\n\n").encode()
    with pytest.raises(SigsumFormatError):
        parse_checkpoint(bad)


def test_parser_rejects_missing_signature_block():
    bad = (ORIGIN + "\n7\n" + base64.b64encode(_root(b"a")).decode() + "\n").encode()
    with pytest.raises(SigsumFormatError):
        parse_checkpoint(bad)


# --- THE FINDING ------------------------------------------------------------

def test_native_predicate_falsely_accuses_honest_witness():
    """PALISADE's byte-inequality predicate is unsound under sigsum's format.

    A witness cosigns the SAME tree head twice at different times -- entirely
    honest behaviour, and in fact the expected behaviour, since a cosignature is
    a statement about the largest consistent head *as of a given time*. Because
    the timestamp is inside the signed bytes, the two signed messages differ.
    """
    name, sk, pk = _witness("honest-witness")
    head = TreeHead(origin=ORIGIN, size=100, root_hash=_root(b"same"))
    c1 = _cosign(name, sk, head, timestamp=1679315147)
    c2 = _cosign(name, sk, head, timestamp=1679401547)  # a day later

    # Both are valid signatures by the same honest witness over the same head.
    assert c1.verify(pk, verify_ed25519)
    assert c2.verify(pk, verify_ed25519)

    # PALISADE's native predicate: byte-inequality of the signed bodies.
    assert conflicts_by_signed_bytes(c1, c2) is True, (
        "the signed messages differ only in the timestamp -- this is the trap"
    )

    # The corrected predicate correctly finds no conflict.
    assert conflict_verdict(c1.tree_head, c2.tree_head).kind is ConflictKind.NONE

    # And attribution declines to name the honest witness.
    registry = WitnessRegistry({name: pk})
    assert extract_witness_equivocation([c1], [c2], registry, verify_ed25519) == []


def test_genuine_equivocation_is_still_attributed():
    """The corrected predicate does not lose the real detection."""
    name, sk, pk = _witness("byzantine-witness")
    head_a = TreeHead(origin=ORIGIN, size=100, root_hash=_root(b"A"))
    head_b = TreeHead(origin=ORIGIN, size=100, root_hash=_root(b"B"))
    ca = _cosign(name, sk, head_a, timestamp=1679315147)
    cb = _cosign(name, sk, head_b, timestamp=1679315147)

    assert conflict_verdict(head_a, head_b).is_equivocation
    registry = WitnessRegistry({name: pk})
    culprits = extract_witness_equivocation([ca], [cb], registry, verify_ed25519)
    assert len(culprits) == 1
    assert culprits[0].witness == name
    assert culprits[0].verify(registry, verify_ed25519)


def test_different_sizes_are_inconclusive_not_equivocation():
    """Signed statements alone cannot adjudicate a cross-size fork.

    PALISADE's Theorem 1 is self-contained: two certificates plus the registry
    settle it. Sigsum has no epochs, only growing sizes, so that self-containment
    holds only within a size.
    """
    a = TreeHead(origin=ORIGIN, size=100, root_hash=_root(b"A"))
    b = TreeHead(origin=ORIGIN, size=200, root_hash=_root(b"B"))
    verdict = conflict_verdict(a, b)
    assert verdict.kind is ConflictKind.INCONCLUSIVE_NEEDS_CONSISTENCY
    assert not verdict.is_equivocation


def test_different_logs_never_conflict():
    a = TreeHead(origin=ORIGIN, size=100, root_hash=_root(b"A"))
    b = TreeHead(origin="sigsum.org/v1/tree/" + "ab" * 32, size=100, root_hash=_root(b"B"))
    assert conflict_verdict(a, b).kind is ConflictKind.NONE


def test_culpability_proof_is_transferable_and_rejects_forgery():
    name, sk, pk = _witness("byz")
    other_name, other_sk, other_pk = _witness("honest")
    head_a = TreeHead(origin=ORIGIN, size=7, root_hash=_root(b"A"))
    head_b = TreeHead(origin=ORIGIN, size=7, root_hash=_root(b"B"))
    ca = _cosign(name, sk, head_a, 1000)
    cb = _cosign(name, sk, head_b, 1000)
    registry = WitnessRegistry({name: pk, other_name: other_pk})

    proof = extract_witness_equivocation([ca], [cb], registry, verify_ed25519)[0]
    # A third party with only the registry and the proof can check it.
    assert proof.verify(registry, verify_ed25519)

    # Reattributing the same signatures to the honest witness fails.
    from palisade.interop.sigsum import WitnessCulpability
    forged = WitnessCulpability(witness=other_name, origin=ORIGIN, size=7,
                                cosignature_a=ca, cosignature_b=cb)
    assert not forged.verify(registry, verify_ed25519)


def test_only_witnesses_on_both_sides_are_named():
    w_byz, sk_byz, pk_byz = _witness("byz")
    w_a, sk_a, pk_a = _witness("only-a")
    w_b, sk_b, pk_b = _witness("only-b")
    head_a = TreeHead(origin=ORIGIN, size=5, root_hash=_root(b"A"))
    head_b = TreeHead(origin=ORIGIN, size=5, root_hash=_root(b"B"))
    registry = WitnessRegistry({w_byz: pk_byz, w_a: pk_a, w_b: pk_b})

    side_a = [_cosign(w_byz, sk_byz, head_a, 1), _cosign(w_a, sk_a, head_a, 1)]
    side_b = [_cosign(w_byz, sk_byz, head_b, 2), _cosign(w_b, sk_b, head_b, 2)]

    culprits = extract_witness_equivocation(side_a, side_b, registry, verify_ed25519)
    assert [c.witness for c in culprits] == [w_byz]


# --- quorum arithmetic -------------------------------------------------------

def test_palisade_quorum_generalizes_to_k_of_n():
    # PALISADE: n=3f+1, k=2f+1 -> intersection >= f+1.
    for f in range(1, 5):
        n, k = 3 * f + 1, 2 * f + 1
        assert guaranteed_culprits(k, n) == f + 1


def test_minority_quorum_guarantees_no_attribution():
    # The deployment trap: a permissive policy silently loses the property.
    assert guaranteed_culprits(2, 5) == 0
    assert not policy_supports_attribution(2, 5)
    assert policy_supports_attribution(3, 5)


def test_guaranteed_culprits_validates_inputs():
    with pytest.raises(ValueError):
        guaranteed_culprits(5, 3)
    with pytest.raises(ValueError):
        guaranteed_culprits(1, 0)
