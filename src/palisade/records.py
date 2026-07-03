"""Schema-checked record types over a content-addressed store (paper section 4).

Records come in three schema-checked types:

* ``Artifact(h_content, type, meta)``
* ``CustodyEvent(h_artifact, holder, action, loc/time, sigma_holder)``
* ``Attestation(h_target, claim, sigma_attester)``

Client signatures ``sigma`` are produced under SLH-DSA (FIPS 205) in a
production deployment; here they carry a pluggable :class:`~palisade.signatures`
signature. Records reference predecessors by hash, embedding per-artifact
provenance DAGs in one global log.

Validation is a fixed, versioned schema check: there is no virtual machine and
no general contract layer, by design -- each absence is attack surface removed
from an accreditation package. :func:`schema_valid` is that fixed check.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional

from .hashing import DIGEST_SIZE, encode, tagged

RECORD_TYPES = ("Artifact", "CustodyEvent", "Attestation")

# Actions permitted on a CustodyEvent. A closed vocabulary, versioned with the
# schema -- not an extensible contract language.
CUSTODY_ACTIONS = (
    "created",
    "received",
    "transferred",
    "inspected",
    "modified",
    "decommissioned",
)


class SchemaError(ValueError):
    """Raised when a record fails the fixed, versioned schema check."""


def _require_digest(name: str, value: bytes) -> None:
    if not isinstance(value, (bytes, bytearray)) or len(value) != DIGEST_SIZE:
        raise SchemaError(f"{name} must be a {DIGEST_SIZE}-byte digest")


@dataclass(frozen=True)
class Artifact:
    """An artifact: a content hash, a type tag, and metadata."""

    type: str = "Artifact"
    content_hash: bytes = b""
    artifact_type: str = ""
    meta: Dict[str, str] = field(default_factory=dict)

    def canonical(self) -> bytes:
        meta_parts = b"".join(
            encode(k.encode("utf-8"), v.encode("utf-8"))
            for k, v in sorted(self.meta.items())
        )
        return tagged(
            "record:Artifact:v1",
            self.content_hash,
            self.artifact_type.encode("utf-8"),
            meta_parts,
        )


@dataclass(frozen=True)
class CustodyEvent:
    """A chain-of-custody event over an artifact."""

    type: str = "CustodyEvent"
    artifact_hash: bytes = b""
    holder: str = ""
    action: str = ""
    location: str = ""
    timestamp: int = 0
    prev_event_hash: Optional[bytes] = None
    signature: Optional[bytes] = None

    def signing_body(self) -> bytes:
        """The bytes the holder signs (everything but the signature itself)."""
        return tagged(
            "record:CustodyEvent:v1",
            self.artifact_hash,
            self.holder.encode("utf-8"),
            self.action.encode("utf-8"),
            self.location.encode("utf-8"),
            self.timestamp.to_bytes(8, "big"),
            self.prev_event_hash or b"",
        )

    def canonical(self) -> bytes:
        return tagged("record:CustodyEvent:body+sig:v1", self.signing_body(), self.signature or b"")


@dataclass(frozen=True)
class Attestation:
    """A signed claim about a target record."""

    type: str = "Attestation"
    target_hash: bytes = b""
    claim: str = ""
    attester: str = ""
    signature: Optional[bytes] = None

    def signing_body(self) -> bytes:
        return tagged(
            "record:Attestation:v1",
            self.target_hash,
            self.claim.encode("utf-8"),
            self.attester.encode("utf-8"),
        )

    def canonical(self) -> bytes:
        return tagged("record:Attestation:body+sig:v1", self.signing_body(), self.signature or b"")


Record = object  # Artifact | CustodyEvent | Attestation


def schema_valid(record) -> bool:
    """The fixed, versioned schema check (Alg. 1 line 1: ``SchemaValid``).

    Returns True iff ``record`` is a well-formed record of one of the three
    known types. Raises nothing; a malformed record simply is not valid.
    """
    try:
        _validate(record)
        return True
    except SchemaError:
        return False


def _validate(record) -> None:
    if isinstance(record, Artifact):
        _require_digest("content_hash", record.content_hash)
        if not record.artifact_type:
            raise SchemaError("Artifact.artifact_type must be non-empty")
        if not isinstance(record.meta, dict):
            raise SchemaError("Artifact.meta must be a dict")
        for k, v in record.meta.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise SchemaError("Artifact.meta keys/values must be strings")
    elif isinstance(record, CustodyEvent):
        _require_digest("artifact_hash", record.artifact_hash)
        if not record.holder:
            raise SchemaError("CustodyEvent.holder must be non-empty")
        if record.action not in CUSTODY_ACTIONS:
            raise SchemaError(f"CustodyEvent.action must be one of {CUSTODY_ACTIONS}")
        if not isinstance(record.timestamp, int) or record.timestamp < 0:
            raise SchemaError("CustodyEvent.timestamp must be a non-negative int")
        if record.prev_event_hash is not None:
            _require_digest("prev_event_hash", record.prev_event_hash)
    elif isinstance(record, Attestation):
        _require_digest("target_hash", record.target_hash)
        if not record.claim:
            raise SchemaError("Attestation.claim must be non-empty")
        if not record.attester:
            raise SchemaError("Attestation.attester must be non-empty")
    else:
        raise SchemaError(f"unknown record type: {type(record).__name__}")


def validate(record) -> None:
    """Like :func:`schema_valid` but raises :class:`SchemaError` on failure."""
    _validate(record)
