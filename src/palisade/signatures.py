"""Hash-based signatures: a real stateful many-time signer over Lamport OTS.

Production PALISADE uses LMS/HSS (SP 800-208) for validators and SLH-DSA
(FIPS 205) for clients. Both reduce to the (second-)preimage and collision
resistance of a standardized hash. This module implements a faithful, minimal
analogue of the *stateful* family (LMS/HSS) entirely from SHA-256 so that the
one self-introduced hazard of the whole design -- one-time-signature index
reuse -- is a concrete, testable object rather than a stub:

* :class:`LamportOTS` is a genuine one-time signature: signing two distinct
  messages under one key leaks secret preimages and enables forgery. That is
  the field failure SP 800-208 exists to prevent.
* :class:`HashSigner` stacks ``2**height`` one-time keys under a Merkle tree,
  yielding a many-time key with an explicit OTS index ``q`` per signature --
  the LMS/HSS structure.
* :class:`HardwareModule` models the FIPS 140-3 boundary of invariant K1: it
  exposes a single ``sign_next`` operation that atomically signs and
  increments, and the index counter is not externally writable. K4
  (fail-closed exhaustion) is enforced by raising once capacity is spent.

Secret keys are derived pseudorandomly from a master seed (as XMSS/LMS derive
per-node secrets), so a height-``h`` key costs O(1) storage, not O(2**h).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from .hashing import DIGEST_SIZE, encode, sha256

# Lamport OTS over a 256-bit message digest: one preimage pair per bit.
_OTS_BITS = 256


def _prf(*parts: bytes) -> bytes:
    out = bytearray(b"PALISADE:sig:prf")
    for p in parts:
        out += len(p).to_bytes(4, "big") + p
    return sha256(bytes(out))


@dataclass(frozen=True)
class OTSSignature:
    """A Lamport signature: per bit, the revealed preimage and the complement
    public-key hash (so the verifier can reconstruct the compressed pubkey)."""

    reveals: List[bytes]      # revealed secret preimage per bit position
    complements: List[bytes]  # H(unrevealed preimage) per bit position


class LamportOTS:
    """A single Lamport one-time keypair derived from ``ots_seed``.

    The public key is compressed to a single 32-byte digest so it can be a
    Merkle leaf; a signature carries the complementary hashes needed to
    reconstruct that digest at verification time.
    """

    def __init__(self, ots_seed: bytes) -> None:
        self._seed = ots_seed

    def _sk(self, i: int, b: int) -> bytes:
        return _prf(self._seed, b"sk", i.to_bytes(2, "big"), bytes([b]))

    def _pk(self, i: int, b: int) -> bytes:
        return sha256(self._sk(i, b))

    def public_digest(self) -> bytes:
        acc = bytearray()
        for i in range(_OTS_BITS):
            acc += self._pk(i, 0)
            acc += self._pk(i, 1)
        return sha256(bytes(acc))

    def sign(self, message_digest: bytes) -> OTSSignature:
        bits = _bits(message_digest)
        reveals = [self._sk(i, bits[i]) for i in range(_OTS_BITS)]
        complements = [self._pk(i, 1 - bits[i]) for i in range(_OTS_BITS)]
        return OTSSignature(reveals=reveals, complements=complements)


def _bits(digest: bytes) -> List[int]:
    if len(digest) * 8 != _OTS_BITS:
        raise ValueError("message digest must be 256 bits")
    out: List[int] = []
    for byte in digest:
        for k in range(7, -1, -1):
            out.append((byte >> k) & 1)
    return out


def ots_public_digest_from_signature(
    message_digest: bytes, sig: OTSSignature
) -> bytes:
    """Reconstruct the compressed OTS public digest from a signature.

    This is what makes reuse detectable and forgery hard: the digest can only
    be reproduced if every revealed preimage hashes into the committed pubkey.
    """
    bits = _bits(message_digest)
    acc = bytearray()
    for i in range(_OTS_BITS):
        revealed_pk = sha256(sig.reveals[i])
        if bits[i] == 0:
            acc += revealed_pk
            acc += sig.complements[i]
        else:
            acc += sig.complements[i]
            acc += revealed_pk
    return sha256(bytes(acc))


# --- Merkle key tree (LMS-style, fixed height) ------------------------------

def _keytree_leaf(index: int, ots_pub_digest: bytes) -> bytes:
    return sha256(b"PALISADE:sig:leaf" + index.to_bytes(4, "big") + ots_pub_digest)


def _keytree_node(left: bytes, right: bytes) -> bytes:
    return sha256(b"PALISADE:sig:node" + left + right)


@dataclass(frozen=True)
class HashSignature:
    """A many-time hash signature: the OTS index ``q`` (disclosed on-log per
    invariant K3), the one-time signature, and the Merkle authentication path
    from the OTS leaf up to the public-key root."""

    index: int
    ots: OTSSignature
    auth_path: List[bytes]


class HashSigner:
    """A stateful many-time signer: ``2**height`` Lamport keys under a Merkle
    tree. Do not use directly for production keys; use :class:`HardwareModule`,
    which enforces the K-invariants around this core."""

    def __init__(self, master_seed: bytes, height: int) -> None:
        if height < 0 or height > 20:
            raise ValueError("height must be in [0, 20] for this reference build")
        self._master = master_seed
        self.height = height
        self.capacity = 1 << height
        self._leaf_cache: dict[int, bytes] = {}

    def _ots(self, index: int) -> LamportOTS:
        return LamportOTS(_prf(self._master, b"ots", index.to_bytes(4, "big")))

    def _leaf(self, index: int) -> bytes:
        if index not in self._leaf_cache:
            self._leaf_cache[index] = _keytree_leaf(index, self._ots(index).public_digest())
        return self._leaf_cache[index]

    def _node(self, level: int, index: int) -> bytes:
        # index is the node index within `level` (level 0 = leaves).
        if level == 0:
            return self._leaf(index)
        left = self._node(level - 1, 2 * index)
        right = self._node(level - 1, 2 * index + 1)
        return _keytree_node(left, right)

    def public_key(self) -> bytes:
        """The Merkle root over all OTS public keys."""
        return self._node(self.height, 0)

    def _auth_path(self, index: int) -> List[bytes]:
        path: List[bytes] = []
        node_index = index
        for level in range(self.height):
            sibling = node_index ^ 1
            path.append(self._node(level, sibling))
            node_index >>= 1
        return path

    def sign_index(self, index: int, message: bytes) -> HashSignature:
        if not 0 <= index < self.capacity:
            raise ValueError(f"OTS index {index} out of range [0,{self.capacity})")
        d = sha256(message)
        ots_sig = self._ots(index).sign(d)
        return HashSignature(index=index, ots=ots_sig, auth_path=self._auth_path(index))


def verify_signature(public_key: bytes, message: bytes, sig: HashSignature) -> bool:
    """Verify a many-time hash signature against a public-key root.

    Checks (1) the OTS reconstructs a leaf and (2) the leaf sits at ``index``
    under ``public_key`` via the authentication path.
    """
    if len(public_key) != DIGEST_SIZE:
        return False
    d = sha256(message)
    try:
        ots_pub = ots_public_digest_from_signature(d, sig.ots)
    except (ValueError, IndexError):
        return False
    node = _keytree_leaf(sig.index, ots_pub)
    node_index = sig.index
    for sibling in sig.auth_path:
        if node_index & 1:
            node = _keytree_node(sibling, node)
        else:
            node = _keytree_node(node, sibling)
        node_index >>= 1
    return node == public_key


def serialize_signature(sig: HashSignature) -> bytes:
    """Canonical, injective serialization of a many-time hash signature."""
    parts = [sig.index.to_bytes(4, "big")]
    parts.extend(sig.ots.reveals)
    parts.extend(sig.ots.complements)
    parts.extend(sig.auth_path)
    return encode(*parts)


def signature_digest(sig: HashSignature) -> bytes:
    """A short digest identifying a signature (for on-log indexing / hashing)."""
    return sha256(b"PALISADE:sig:digest" + serialize_signature(sig))


class KeyExhausted(RuntimeError):
    """Raised by a hardware module that cannot prove fresh OTS state (K4)."""


class HardwareModule:
    """Models the FIPS 140-3 module of invariants K1, K2, K4.

    K1 (hardware monotonicity): the only signing operation is
    :meth:`sign_next`, which atomically signs and increments; the index counter
    ``_q`` is private and there is no setter.

    K2 (partitioned restoration): :meth:`restore_from` starts a fresh module on
    a never-before-activated index range, so re-entry into a spent range is
    impossible by construction. The activation is meant to be recorded on-log.

    K4 (fail-closed exhaustion): once the module's index range is spent it
    raises :class:`KeyExhausted` rather than risking reuse.
    """

    def __init__(self, master_seed: bytes, height: int, *, start: int = 0, end: Optional[int] = None) -> None:
        self._signer = HashSigner(master_seed, height)
        self._start = start
        self._end = self._signer.capacity if end is None else end
        if not 0 <= start <= self._end <= self._signer.capacity:
            raise ValueError("invalid activation range")
        self._q = start

    @property
    def public_key(self) -> bytes:
        return self._signer.public_key()

    @property
    def next_index(self) -> int:
        return self._q

    @property
    def remaining(self) -> int:
        return self._end - self._q

    def sign_next(self, message: bytes) -> HashSignature:
        """K1: atomically sign with the current index and increment.

        Returns a :class:`HashSignature` whose ``index`` field is the OTS index
        just consumed (published on-log per K3). Raises :class:`KeyExhausted`
        (K4) when the activated range is spent.
        """
        if self._q >= self._end:
            raise KeyExhausted(
                f"module range [{self._start},{self._end}) exhausted; refusing to sign"
            )
        q = self._q
        sig = self._signer.sign_index(q, message)
        self._q = q + 1  # atomic sign-and-increment; no external write path
        return sig

    def restore_from(self, activation_start: int) -> "HardwareModule":
        """K2: return a module activated on a fresh, never-used index range.

        ``activation_start`` must be at or beyond this module's end so the
        restored module cannot re-enter a spent index range.
        """
        if activation_start < self._end:
            raise ValueError(
                "restoration must activate a never-before-activated subtree "
                f"(>= {self._end}); got {activation_start}"
            )
        return HardwareModule(
            self._signer._master,
            self._signer.height,
            start=activation_start,
            end=self._signer.capacity,
        )
