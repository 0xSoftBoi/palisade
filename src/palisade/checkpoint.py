"""Checkpoint certificates and the checkpoint chain (Definition 2).

For epoch ``e``::

    CP_e = (e, h_e, |L_e|, H(CP_{e-1}), Sigma_e)

with ``h_e = h(L_e)`` and ``Sigma_e`` a set of >= 2f+1 LMS signatures by
distinct registered validators over the first four fields. Honest validators
sign at most one ``(h_e, |L_e|)`` per epoch, and only for the log their
protocol instance committed.

Checkpoint chains are the ledger's portable spine: a verifier holding genesis
keys checks the chain, then audits any record via ``pi_incl`` and any epoch
pair via ``pi_cons``, offline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .hashing import DIGEST_SIZE, encode, tagged
from .signatures import (
    HashSignature,
    serialize_signature,
    signature_digest,
    verify_signature,
)

GENESIS_PREV = b"\x00" * DIGEST_SIZE


class ValidatorRegistry:
    """Maps validator ids to their registered many-time public keys.

    Membership is contractual and closed per deployment (paper section 3); this
    registry is the ground truth every verifier is assumed to hold.
    """

    def __init__(self, keys: Optional[Dict[str, bytes]] = None) -> None:
        self._keys: Dict[str, bytes] = dict(keys or {})

    def register(self, validator_id: str, public_key: bytes) -> None:
        if validator_id in self._keys:
            raise ValueError(f"validator {validator_id!r} already registered")
        self._keys[validator_id] = public_key

    def public_key(self, validator_id: str) -> Optional[bytes]:
        return self._keys.get(validator_id)

    def __contains__(self, validator_id: str) -> bool:
        return validator_id in self._keys

    def __len__(self) -> int:
        return len(self._keys)

    def ids(self) -> List[str]:
        return sorted(self._keys)


@dataclass(frozen=True)
class CheckpointBody:
    """The first four fields of a checkpoint -- what validators sign."""

    epoch: int
    root: bytes
    size: int
    prev_hash: bytes

    def canonical(self) -> bytes:
        return tagged(
            "checkpoint:body:v1",
            self.epoch.to_bytes(8, "big"),
            self.root,
            self.size.to_bytes(8, "big"),
            self.prev_hash,
        )

    def payload(self) -> tuple:
        """The (h_e, |L_e|) payload whose uniqueness Theorem 1 concerns."""
        return (self.root, self.size)


@dataclass(frozen=True)
class ValidatorSignature:
    validator_id: str
    signature: HashSignature

    def digest(self) -> bytes:
        return signature_digest(self.signature)


@dataclass
class CheckpointCertificate:
    """A checkpoint body plus a quorum of distinct validator signatures."""

    body: CheckpointBody
    signatures: List[ValidatorSignature] = field(default_factory=list)

    @property
    def epoch(self) -> int:
        return self.body.epoch

    def signer_ids(self) -> List[str]:
        return sorted(vs.validator_id for vs in self.signatures)

    def cert_hash(self) -> bytes:
        """H(CP_e): binds the body and the set of contributing signatures, so
        the chain's ``prev_hash`` pins both content and attesters."""
        parts = [self.body.canonical()]
        for vs in sorted(self.signatures, key=lambda s: s.validator_id):
            parts.append(encode(vs.validator_id.encode("utf-8"), vs.digest()))
        return tagged("checkpoint:cert:v1", *parts)

    def verify(self, registry: ValidatorRegistry, quorum: int) -> bool:
        """Verify the certificate against the registry.

        Checks: distinct registered signers, each signature valid over the
        body, and at least ``quorum`` (= 2f+1) of them.
        """
        body_bytes = self.body.canonical()
        seen: set[str] = set()
        valid = 0
        for vs in self.signatures:
            if vs.validator_id in seen:
                return False  # a certificate must not double-count a signer
            pk = registry.public_key(vs.validator_id)
            if pk is None:
                return False
            if not verify_signature(pk, body_bytes, vs.signature):
                return False
            seen.add(vs.validator_id)
            valid += 1
        return valid >= quorum


def verify_chain(
    chain: List[CheckpointCertificate],
    registry: ValidatorRegistry,
    quorum: int,
    *,
    genesis_prev: bytes = GENESIS_PREV,
) -> bool:
    """Verify a checkpoint chain is well-formed: contiguous epochs, each
    certificate a valid quorum, and each ``prev_hash`` matching the previous
    certificate's ``cert_hash`` (the portable spine of Definition 2)."""
    prev = genesis_prev
    expected_epoch: Optional[int] = None
    for cert in chain:
        if not cert.verify(registry, quorum):
            return False
        if cert.body.prev_hash != prev:
            return False
        if expected_epoch is not None and cert.epoch != expected_epoch:
            return False
        prev = cert.cert_hash()
        expected_epoch = cert.epoch + 1
    return True
