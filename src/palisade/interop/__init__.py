"""Interoperability adapters: PALISADE's accountability layer on foreign logs.

The positioning review (docs/POSITIONING.md) concluded that PALISADE's base log
layer duplicates deployed prior art, and that its defensible contribution is
the accountability layer. This package tests that conclusion by retargeting
that layer onto an externally specified format.

Adapters take signature verification as a callback, so the core package retains
its zero-dependency, hash-only character even when the foreign log is not.
"""

from __future__ import annotations

from .sigsum import (
    Checkpoint,
    ConflictKind,
    ConflictVerdict,
    Cosignature,
    NoteSignature,
    SigsumFormatError,
    TreeHead,
    WitnessCulpability,
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

__all__ = [
    "Checkpoint",
    "ConflictKind",
    "ConflictVerdict",
    "Cosignature",
    "NoteSignature",
    "SigsumFormatError",
    "TreeHead",
    "WitnessCulpability",
    "WitnessRegistry",
    "conflict_verdict",
    "conflicts_by_signed_bytes",
    "cosignature_message",
    "extract_witness_equivocation",
    "guaranteed_culprits",
    "key_id",
    "parse_checkpoint",
    "policy_supports_attribution",
]
