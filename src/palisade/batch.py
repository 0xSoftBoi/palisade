"""Client batch signing (paper section 9, limitation 2).

Signing cost is "converted from a disqualifier into a parameter by batch
signing: a device accumulates B records, signs the root of a B-leaf Merkle tree
once, and attaches a log2(B)-hash path per record." With a ~0.8 s SLH-DSA-128s
signature, B=1024 yields ~1,260 records/s per client core -- covering
telemetry-rate sources without touching the validity path's assumptions.

This module implements that: an accumulator builds a history tree over a batch,
one signature covers the batch root, and each record carries an inclusion path
plus that single signature. Verification is one inclusion check (a handful of
hashes) plus one signature verification against the batch root.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Sequence

from .merkle import merkle_tree_hash, verify_inclusion
from .merkle import inclusion_path as _inclusion_path
from .signatures import HashSignature, verify_signature


@dataclass(frozen=True)
class SignedBatch:
    """A batch of record bytes whose Merkle root carries a single signature."""

    records: List[bytes]
    root: bytes
    signature: HashSignature

    @property
    def size(self) -> int:
        return len(self.records)

    def proof_for(self, index: int) -> "BatchRecordProof":
        """The portable per-record proof: the record, its inclusion path to the
        batch root, and the one batch signature."""
        path = _inclusion_path(index, self.records)
        return BatchRecordProof(
            record=self.records[index],
            index=index,
            batch_size=len(self.records),
            audit_path=path,
            batch_root=self.root,
            signature=self.signature,
        )


@dataclass(frozen=True)
class BatchRecordProof:
    """Proof that one record was signed as part of a batch.

    Amortizes one expensive client signature over the whole batch: verification
    is an O(log B) inclusion check plus a single signature verification.
    """

    record: bytes
    index: int
    batch_size: int
    audit_path: List[bytes]
    batch_root: bytes
    signature: HashSignature

    def verify(self, public_key: bytes) -> bool:
        included = verify_inclusion(
            self.record, self.index, self.batch_size, self.audit_path, self.batch_root
        )
        if not included:
            return False
        return verify_signature(public_key, self.batch_root, self.signature)


class BatchAccumulator:
    """Accumulates record bytes, then seals them with one signature.

    ``sign_fn`` is any callable mapping the batch-root bytes to a
    :class:`HashSignature` -- e.g. a client's ``HardwareModule.sign_next`` or a
    stateless signer's ``sign``. The client pays one signature per batch,
    regardless of batch size.
    """

    def __init__(self) -> None:
        self._records: List[bytes] = []

    def __len__(self) -> int:
        return len(self._records)

    def add(self, record: bytes) -> int:
        self._records.append(bytes(record))
        return len(self._records) - 1

    def add_all(self, records: Sequence[bytes]) -> None:
        for r in records:
            self.add(r)

    def root(self) -> bytes:
        return merkle_tree_hash(self._records)

    def seal(self, sign_fn: Callable[[bytes], HashSignature]) -> SignedBatch:
        if not self._records:
            raise ValueError("cannot seal an empty batch")
        root = self.root()
        signature = sign_fn(root)
        return SignedBatch(records=list(self._records), root=root, signature=signature)
