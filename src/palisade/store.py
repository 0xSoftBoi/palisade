"""Content-addressed store.

Records reference predecessors by hash, embedding per-artifact provenance DAGs
in one global log (paper section 4). A content-addressed store is the substrate
that makes "reference by hash" meaningful: put returns the address, get is by
address, and any tampering changes the address.
"""

from __future__ import annotations

from typing import Dict, Iterator, Optional

from .hashing import sha256


class ContentStore:
    """An in-memory content-addressed blob store keyed by SHA-256.

    The address of a blob is ``SHA-256(blob)``. Storing the same bytes twice is
    idempotent; retrieving a mutated blob is impossible because the mutation
    changes the address.
    """

    def __init__(self) -> None:
        self._blobs: Dict[bytes, bytes] = {}

    def put(self, data: bytes) -> bytes:
        """Store ``data``, returning its content address (SHA-256 digest)."""
        addr = sha256(data)
        self._blobs.setdefault(addr, bytes(data))
        return addr

    def get(self, addr: bytes) -> Optional[bytes]:
        """Return the blob at ``addr`` or ``None`` if absent."""
        return self._blobs.get(addr)

    def has(self, addr: bytes) -> bool:
        return addr in self._blobs

    def verify(self, addr: bytes) -> bool:
        """Return True iff the stored blob actually hashes to ``addr``."""
        blob = self._blobs.get(addr)
        return blob is not None and sha256(blob) == addr

    def __len__(self) -> int:
        return len(self._blobs)

    def __contains__(self, addr: bytes) -> bool:
        return addr in self._blobs

    def __iter__(self) -> Iterator[bytes]:
        return iter(self._blobs)
