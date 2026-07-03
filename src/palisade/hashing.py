"""Domain-separated hashing over SHA-256.

The entire PALISADE record-validity path reduces to the (second-)preimage and
collision resistance of a standardized hash function (SP 800-208, FIPS 205).
This module is the single place that hash is instantiated, so the assumption
surface named in the assumption audit (Table 1 of the paper) is exactly one
line: ``_H = hashlib.sha256``.

Every structured hash is domain-separated by a short ASCII tag so that a digest
computed for one role (e.g. a Merkle leaf) can never be reinterpreted as a
digest for another (e.g. a checkpoint), which would otherwise open a
cross-structure collision path outside the tree-security argument of Def. 1.
"""

from __future__ import annotations

import hashlib
from typing import Iterable

HASH_NAME = "sha256"
DIGEST_SIZE = 32

# RFC 6962 / RFC 9162 tree-hash domain separators. These MUST stay 0x00/0x01 so
# that PALISADE history-tree roots are byte-identical to a Certificate
# Transparency log over the same leaves; the interop is deliberate (the proof
# machinery of Def. 1 is CT's, verbatim).
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def sha256(data: bytes) -> bytes:
    """Raw SHA-256. The only cryptographic primitive PALISADE depends on."""
    return hashlib.sha256(data).digest()


def tagged(tag: str, *parts: bytes) -> bytes:
    """Hash ``parts`` under an unambiguous domain tag.

    Serialization is length-prefixed (see :func:`encode`) so that no two
    distinct tuples of ``parts`` share an encoding; without this, ``H(a) || b``
    and ``H(a || b)`` style ambiguities would reintroduce collisions the audit
    assumes away.
    """
    return sha256(b"PALISADE:" + tag.encode("ascii") + b":" + encode(*parts))


def leaf_hash(data: bytes) -> bytes:
    """RFC 6962 leaf hash: ``SHA-256(0x00 || data)``."""
    return sha256(LEAF_PREFIX + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 interior node hash: ``SHA-256(0x01 || left || right)``."""
    return sha256(NODE_PREFIX + left + right)


def empty_root() -> bytes:
    """MTH of the empty list is ``SHA-256()`` of the empty string (RFC 6962)."""
    return sha256(b"")


def encode(*parts: bytes) -> bytes:
    """Canonical, injective serialization of a tuple of byte strings.

    Each part is prefixed with its length as an 8-byte big-endian integer.
    This is injective over tuples of byte strings, which is what the
    domain-separation argument needs.
    """
    out = bytearray()
    out += len(parts).to_bytes(8, "big")
    for p in parts:
        out += len(p).to_bytes(8, "big")
        out += p
    return bytes(out)


def encode_ints(values: Iterable[int]) -> bytes:
    """Canonically encode a sequence of non-negative integers."""
    vals = list(values)
    parts = [v.to_bytes((v.bit_length() + 7) // 8 or 1, "big") for v in vals]
    return encode(*parts)


def hexdigest(data: bytes) -> str:
    return data.hex()
