"""Tamper-evident history tree (Definition 1).

A history tree over a record sequence ``L`` with root ``h(L)`` supporting:

* ``pi_incl(r, L)`` -- an O(log|L|) proof that record ``r`` occupies a stated
  position, and
* ``pi_cons(L, L')`` -- an O(log|L'|) proof that ``L`` is a prefix of ``L'``.

Both verify against roots alone. Producing an accepting inclusion proof for a
record/position not in ``L``, or an accepting consistency proof for a
non-prefix pair, implies a collision in ``H`` -- this is the sole security
property the paper's Theorem 2 (anchored fork bound) reduces to.

The construction is RFC 6962 / RFC 9162 (Certificate Transparency), whose proof
machinery Definition 1 adopts verbatim. Generation uses the recursive PATH /
SUBPROOF definitions from the RFC; verification uses the iterative verifiers.
Generating one way and checking the other is a deliberate cross-check.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence

from .hashing import empty_root, leaf_hash, node_hash


def _largest_power_of_two_less_than(n: int) -> int:
    """Return the largest power of two strictly smaller than ``n`` (n >= 2)."""
    if n < 2:
        raise ValueError("n must be >= 2")
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def merkle_tree_hash(leaves: Sequence[bytes]) -> bytes:
    """MTH(D[n]) per RFC 6962 section 2.1.

    ``leaves`` are the raw record bytes (not yet leaf-hashed).
    """
    n = len(leaves)
    if n == 0:
        return empty_root()
    if n == 1:
        return leaf_hash(leaves[0])
    k = _largest_power_of_two_less_than(n)
    return node_hash(merkle_tree_hash(leaves[:k]), merkle_tree_hash(leaves[k:]))


def inclusion_path(m: int, leaves: Sequence[bytes]) -> List[bytes]:
    """PATH(m, D[n]) -- the audit path for leaf index ``m`` (RFC 6962)."""
    n = len(leaves)
    if not 0 <= m < n:
        raise IndexError(f"leaf index {m} out of range for tree size {n}")
    if n == 1:
        return []
    k = _largest_power_of_two_less_than(n)
    if m < k:
        return inclusion_path(m, leaves[:k]) + [merkle_tree_hash(leaves[k:])]
    return inclusion_path(m - k, leaves[k:]) + [merkle_tree_hash(leaves[:k])]


def consistency_path(m: int, leaves: Sequence[bytes]) -> List[bytes]:
    """PROOF(m, D[n]) -- consistency between D[0:m] and D[0:n] (RFC 6962)."""
    n = len(leaves)
    if not 0 < m <= n:
        raise ValueError(f"first size {m} out of range for tree size {n}")
    if m == n:
        return []
    return _subproof(m, leaves, True)


def _subproof(m: int, leaves: Sequence[bytes], b: bool) -> List[bytes]:
    n = len(leaves)
    if m == n:
        return [] if b else [merkle_tree_hash(leaves)]
    k = _largest_power_of_two_less_than(n)
    if m <= k:
        return _subproof(m, leaves[:k], b) + [merkle_tree_hash(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [merkle_tree_hash(leaves[:k])]


def _lsb(x: int) -> int:
    return x & 1


def verify_inclusion(
    leaf: bytes,
    index: int,
    tree_size: int,
    proof: Sequence[bytes],
    root: bytes,
) -> bool:
    """Verify an inclusion proof (RFC 9162 section 2.1.3.2).

    ``leaf`` is the raw record bytes; it is leaf-hashed internally.
    """
    if index >= tree_size or index < 0:
        return False
    fn = index
    sn = tree_size - 1
    r = leaf_hash(leaf)
    for p in proof:
        if sn == 0:
            return False
        if _lsb(fn) == 1 or fn == sn:
            r = node_hash(p, r)
            if _lsb(fn) == 0:
                while True:
                    fn >>= 1
                    sn >>= 1
                    if _lsb(fn) == 1 or fn == 0:
                        break
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(
    first_size: int,
    second_size: int,
    proof: Sequence[bytes],
    first_root: bytes,
    second_root: bytes,
) -> bool:
    """Verify a consistency proof (RFC 9162 section 2.1.4.2)."""
    if first_size > second_size or first_size < 0:
        return False
    if first_size == 0:
        # Every tree is consistent with the empty tree; the proof is empty.
        return len(proof) == 0
    if first_size == second_size:
        return len(proof) == 0 and first_root == second_root

    path = list(proof)
    # If first_size is an exact power of two, first_root is not transmitted in
    # the path (it is derivable); prepend it so the seed logic below is uniform.
    if first_size & (first_size - 1) == 0:
        path = [first_root] + path

    if not path:
        return False

    fn = first_size - 1
    sn = second_size - 1
    while _lsb(fn) == 1:
        fn >>= 1
        sn >>= 1

    fr = path[0]
    sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if _lsb(fn) == 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if _lsb(fn) == 0:
                while True:
                    fn >>= 1
                    sn >>= 1
                    if _lsb(fn) == 1 or fn == 0:
                        break
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1

    return fr == first_root and sr == second_root and sn == 0


@dataclass
class InclusionProof:
    """A portable inclusion proof, verifiable against a root alone."""

    leaf_index: int
    tree_size: int
    audit_path: List[bytes]

    def verify(self, leaf: bytes, root: bytes) -> bool:
        return verify_inclusion(
            leaf, self.leaf_index, self.tree_size, self.audit_path, root
        )


@dataclass
class ConsistencyProof:
    """A portable consistency (prefix) proof, verifiable against two roots."""

    first_size: int
    second_size: int
    path: List[bytes]

    def verify(self, first_root: bytes, second_root: bytes) -> bool:
        return verify_consistency(
            self.first_size, self.second_size, self.path, first_root, second_root
        )


class HistoryTree:
    """An append-only RFC 6962 history tree over raw record byte strings.

    This is the ``L`` of Definition 1. Records are appended in commit order;
    the tree exposes the current root ``h(L)``, inclusion proofs for any past
    record, and consistency proofs between any two sizes it has held.
    """

    def __init__(self) -> None:
        self._leaves: List[bytes] = []

    def __len__(self) -> int:
        return len(self._leaves)

    @property
    def size(self) -> int:
        return len(self._leaves)

    def append(self, record: bytes) -> int:
        """Append raw record bytes, returning the new leaf index."""
        self._leaves.append(bytes(record))
        return len(self._leaves) - 1

    def leaf(self, index: int) -> bytes:
        return self._leaves[index]

    def root(self) -> bytes:
        """Current Merkle tree hash ``h(L)``."""
        return merkle_tree_hash(self._leaves)

    def root_at(self, size: int) -> bytes:
        """Root of the prefix of length ``size`` (0 <= size <= len)."""
        if not 0 <= size <= len(self._leaves):
            raise ValueError(f"size {size} out of range for tree of {len(self)}")
        return merkle_tree_hash(self._leaves[:size])

    def inclusion_proof(self, index: int, size: int | None = None) -> InclusionProof:
        """Inclusion proof for ``index`` against the tree of ``size`` leaves."""
        size = self.size if size is None else size
        path = inclusion_path(index, self._leaves[:size])
        return InclusionProof(leaf_index=index, tree_size=size, audit_path=path)

    def consistency_proof(self, first_size: int, second_size: int | None = None) -> ConsistencyProof:
        """Consistency proof that the prefix of ``first_size`` is a prefix of
        the tree of ``second_size`` leaves."""
        second_size = self.size if second_size is None else second_size
        path = consistency_path(first_size, self._leaves[:second_size])
        return ConsistencyProof(
            first_size=first_size, second_size=second_size, path=path
        )
