"""PALISADE: an assumption-minimal, hash-based accountable log for long-horizon
provenance.

The entire record-validity path reduces to the (second-)preimage and collision
resistance of a standardized hash function. No curves, pairings, lattices,
token, or virtual machine appear anywhere a verifier must trust.

Public surface:

* :mod:`palisade.merkle` -- the tamper-evident history tree (Definition 1).
* :mod:`palisade.records` -- Artifact / CustodyEvent / Attestation (section 4).
* :mod:`palisade.signatures` -- stateful hash-based signatures with the K1-K4
  hardware boundary (section 6).
* :mod:`palisade.checkpoint` -- checkpoint certificates and chain (Definition 2).
* :mod:`palisade.accountability` -- culpability proofs (Theorem 1, Proposition 1).
* :mod:`palisade.anchoring` -- the anchored fork bound (Theorem 2).
* :mod:`palisade.log` -- the checkpointed replicated log.
"""

from __future__ import annotations

from .accountability import (
    CulpabilityProof,
    EquivocationEvidence,
    IndexReuseProof,
    ReuseMonitor,
    extract_equivocation,
)
from .anchoring import Anchor, AnchorMedium, ForkVerdict, verify_against_anchor
from .checkpoint import (
    CheckpointBody,
    CheckpointCertificate,
    ValidatorRegistry,
    ValidatorSignature,
    verify_chain,
)
from .hashing import sha256
from .log import PalisadeLog, Validator, quorum_size
from .merkle import (
    ConsistencyProof,
    HistoryTree,
    InclusionProof,
    merkle_tree_hash,
    verify_consistency,
    verify_inclusion,
)
from .records import Artifact, Attestation, CustodyEvent, schema_valid, validate
from .signatures import (
    HardwareModule,
    HashSignature,
    HashSigner,
    KeyExhausted,
    verify_signature,
)
from .store import ContentStore

__version__ = "0.3.0"

__all__ = [
    "Anchor",
    "AnchorMedium",
    "Artifact",
    "Attestation",
    "CheckpointBody",
    "CheckpointCertificate",
    "ConsistencyProof",
    "ContentStore",
    "CulpabilityProof",
    "CustodyEvent",
    "EquivocationEvidence",
    "ForkVerdict",
    "HardwareModule",
    "HashSignature",
    "HashSigner",
    "HistoryTree",
    "IndexReuseProof",
    "InclusionProof",
    "KeyExhausted",
    "PalisadeLog",
    "ReuseMonitor",
    "Validator",
    "ValidatorRegistry",
    "ValidatorSignature",
    "extract_equivocation",
    "merkle_tree_hash",
    "quorum_size",
    "schema_valid",
    "sha256",
    "validate",
    "verify_against_anchor",
    "verify_chain",
    "verify_consistency",
    "verify_inclusion",
    "verify_signature",
]
