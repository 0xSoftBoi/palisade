"""History-tree tests (Definition 1): RFC 6962 vectors, proofs, tamper-evidence."""

import hashlib

import pytest

from palisade.hashing import leaf_hash, node_hash
from palisade.merkle import (
    HistoryTree,
    merkle_tree_hash,
    verify_consistency,
    verify_inclusion,
)


def test_empty_root_is_sha256_of_empty_string():
    assert merkle_tree_hash([]) == hashlib.sha256(b"").digest()


def test_single_leaf_is_rfc6962_leaf_hash():
    assert merkle_tree_hash([b"x"]) == leaf_hash(b"x")


def test_two_leaf_root_is_node_of_leaves():
    expected = node_hash(leaf_hash(b"a"), leaf_hash(b"b"))
    assert merkle_tree_hash([b"a", b"b"]) == expected


def test_root_is_order_sensitive():
    assert merkle_tree_hash([b"a", b"b"]) != merkle_tree_hash([b"b", b"a"])


def _build(n):
    tree = HistoryTree()
    for i in range(n):
        tree.append(f"record-{i}".encode())
    return tree


@pytest.mark.parametrize("n", range(1, 33))
def test_all_inclusion_proofs_verify(n):
    tree = _build(n)
    root = tree.root()
    for i in range(n):
        proof = tree.inclusion_proof(i)
        assert proof.verify(tree.leaf(i), root)


def test_inclusion_proof_rejects_wrong_leaf():
    tree = _build(16)
    root = tree.root()
    proof = tree.inclusion_proof(5)
    assert not proof.verify(b"not-the-record", root)


def test_inclusion_proof_rejects_wrong_root():
    tree = _build(16)
    proof = tree.inclusion_proof(5)
    assert not proof.verify(tree.leaf(5), b"\x00" * 32)


def test_inclusion_proof_rejects_tampered_path():
    tree = _build(16)
    root = tree.root()
    proof = tree.inclusion_proof(5)
    proof.audit_path[0] = bytes(32)
    assert not proof.verify(tree.leaf(5), root)


@pytest.mark.parametrize("n", [1, 2, 3, 5, 8, 13, 21, 32])
def test_all_consistency_proofs_verify(n):
    tree = _build(n)
    second_root = tree.root()
    for m in range(1, n + 1):
        first_root = tree.root_at(m)
        proof = tree.consistency_proof(m, n)
        assert proof.verify(first_root, second_root), f"m={m} n={n}"


def test_consistency_rejects_non_prefix():
    # Two trees that share a size but diverge in contents are not consistent.
    a = HistoryTree()
    b = HistoryTree()
    for i in range(8):
        a.append(f"a-{i}".encode())
        b.append(f"a-{i}".encode())
    # snapshot at size 8, then diverge
    root8 = a.root()
    a.append(b"a-8")
    b.append(b"DIFFERENT")
    proof = a.consistency_proof(8, 9)  # proof for a's own extension
    # The proof binds a's root9, not b's; verifying against b's root must fail.
    assert proof.verify(root8, a.root())
    assert not proof.verify(root8, b.root())


def test_consistency_with_empty_prefix_is_trivial():
    tree = _build(5)
    assert verify_consistency(0, 5, [], hashlib.sha256(b"").digest(), tree.root())


def test_consistency_equal_sizes_requires_equal_roots():
    tree = _build(5)
    assert verify_consistency(5, 5, [], tree.root(), tree.root())
    assert not verify_consistency(5, 5, [], tree.root(), b"\x00" * 32)


def test_verify_inclusion_out_of_range():
    tree = _build(4)
    assert not verify_inclusion(tree.leaf(0), 4, 4, [], tree.root())
