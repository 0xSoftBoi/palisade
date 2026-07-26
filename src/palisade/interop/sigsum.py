"""Sigsum / C2SP interop: PALISADE's culpability layer on someone else's log.

This module tests the load-bearing claim of `docs/POSITIONING.md`: that
PALISADE's real contribution is *transferable attribution* (Theorem 1(b)) and
that it could ride on top of an existing transparency log rather than replacing
one. Here that claim makes contact with a real, externally specified format --
the sigsum checkpoint and the C2SP `tlog-cosignature` witness cosignature --
instead of PALISADE's own `CheckpointBody`.

Formats implemented (see docs/SIGSUM_INTEROP.md for citations):

A checkpoint note body is three newline-terminated lines::

    sigsum.org/v1/tree/<64 hex chars, the log's key hash>
    <tree size, decimal, no leading zeros>
    <base64 of the 32-byte Merkle root>

A witness cosignature signs a *five*-line message: the body above, prefixed
with a domain-separation line and a timestamp line::

    cosignature/v1
    time <POSIX seconds, decimal>
    <origin>
    <size>
    <base64 root>

Signature lines in a note are ``"— " + name + " " + base64(keyid||sig)``
where the 4-byte key ID is ``SHA-256(name || "\\n" || 0x04 || pubkey)[:4]``
for Ed25519.

**The finding this module exists to record.** Because the timestamp sits
*inside* the signed bytes, two honest cosignatures by one witness over the same
tree head at different times have different signed bodies. PALISADE's native
:func:`palisade.accountability.extract_equivocation` treats byte-inequality of
the signed bodies as the conflict predicate, so ported naively it raises a
**false accusation against an honest witness** -- violating the half of
Theorem 1(b) that matters most ("never implicating an honest validator").
:func:`conflict_verdict` implements the corrected predicate: compare the
*tree head*, not the signed bytes.

This module deliberately takes signature verification as a callback so the core
package keeps its zero-dependency, hash-only character; sigsum is Ed25519, which
PALISADE's assumption audit does not admit into its own validity path.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, List, Optional, Sequence, Tuple

SIGSUM_ORIGIN_PREFIX = "sigsum.org/v1/tree/"
COSIGNATURE_HEADER = "cosignature/v1"
NOTE_SIG_PREFIX = "— "  # em dash + space
ED25519_KEY_TYPE = 0x04

# A verifier: (public_key, message, signature) -> bool.
VerifyFn = Callable[[bytes, bytes, bytes], bool]


class SigsumFormatError(ValueError):
    """Raised when input does not conform to the sigsum/C2SP note format."""


# --- tree heads and checkpoints ---------------------------------------------

@dataclass(frozen=True)
class TreeHead:
    """A sigsum tree head: the three-line signed note body."""

    origin: str
    size: int
    root_hash: bytes

    def __post_init__(self) -> None:
        if len(self.root_hash) != 32:
            raise SigsumFormatError("root hash must be 32 bytes")
        if self.size < 0:
            raise SigsumFormatError("size must be non-negative")

    def serialize(self) -> bytes:
        """The note body, exactly as signed (with trailing newline)."""
        return (
            f"{self.origin}\n{self.size}\n"
            f"{base64.b64encode(self.root_hash).decode('ascii')}\n"
        ).encode("utf-8")

    def identity(self) -> Tuple[str, int, bytes]:
        """The tuple that determines whether two heads *conflict*.

        This -- not the signed bytes -- is the correct basis for an
        equivocation predicate, because the signed bytes also carry a
        per-signature timestamp.
        """
        return (self.origin, self.size, self.root_hash)


@dataclass(frozen=True)
class NoteSignature:
    """One ``— name base64(keyid||sig)`` line from a note."""

    name: str
    key_id: bytes
    signature: bytes

    def serialize(self) -> str:
        payload = base64.b64encode(self.key_id + self.signature).decode("ascii")
        return f"{NOTE_SIG_PREFIX}{self.name} {payload}"


@dataclass(frozen=True)
class Checkpoint:
    """A parsed signed note: a tree head plus its signature lines."""

    tree_head: TreeHead
    signatures: List[NoteSignature]

    def serialize(self) -> bytes:
        body = self.tree_head.serialize()
        lines = "".join(s.serialize() + "\n" for s in self.signatures)
        return body + b"\n" + lines.encode("utf-8")


def key_id(name: str, public_key: bytes, key_type: int = ED25519_KEY_TYPE) -> bytes:
    """C2SP key ID: ``SHA-256(name || 0x0A || key_type || pubkey)[:4]``."""
    h = hashlib.sha256()
    h.update(name.encode("utf-8"))
    h.update(b"\n")
    h.update(bytes([key_type]))
    h.update(public_key)
    return h.digest()[:4]


def parse_checkpoint(data: bytes) -> Checkpoint:
    """Parse a signed-note checkpoint. Strict: malformed input raises."""
    sep = data.find(b"\n\n")
    if sep == -1:
        raise SigsumFormatError("no blank line separating note body from signatures")
    body = data[: sep + 1]
    sig_block = data[sep + 2 :]

    body_lines = body.decode("utf-8").split("\n")
    # trailing newline yields a final empty element
    if len(body_lines) < 4 or body_lines[-1] != "":
        raise SigsumFormatError("checkpoint body must be three newline-terminated lines")
    origin, size_s, root_s = body_lines[0], body_lines[1], body_lines[2]

    if size_s != str(int(size_s)) or not size_s.isdigit():
        raise SigsumFormatError("size must be decimal with no leading zeros")
    try:
        root = base64.b64decode(root_s, validate=True)
    except Exception as exc:  # noqa: BLE001 - surface as a format error
        raise SigsumFormatError(f"root hash is not valid base64: {exc}") from exc

    tree_head = TreeHead(origin=origin, size=int(size_s), root_hash=root)

    signatures: List[NoteSignature] = []
    for line in sig_block.decode("utf-8").split("\n"):
        if not line:
            continue
        if not line.startswith(NOTE_SIG_PREFIX):
            raise SigsumFormatError(f"bad signature line: {line!r}")
        rest = line[len(NOTE_SIG_PREFIX) :]
        try:
            name, payload_s = rest.split(" ", 1)
        except ValueError as exc:
            raise SigsumFormatError(f"bad signature line: {line!r}") from exc
        payload = base64.b64decode(payload_s, validate=True)
        if len(payload) < 4:
            raise SigsumFormatError("signature payload shorter than key ID")
        signatures.append(
            NoteSignature(name=name, key_id=payload[:4], signature=payload[4:])
        )
    return Checkpoint(tree_head=tree_head, signatures=signatures)


# --- cosignatures ------------------------------------------------------------

def cosignature_message(tree_head: TreeHead, timestamp: int) -> bytes:
    """The exact five-line message a witness signs (C2SP tlog-cosignature)."""
    if timestamp < 0:
        raise SigsumFormatError("timestamp must be non-negative")
    prefix = f"{COSIGNATURE_HEADER}\ntime {timestamp}\n".encode("utf-8")
    return prefix + tree_head.serialize()


@dataclass(frozen=True)
class Cosignature:
    """A witness's timestamped cosignature over a tree head."""

    witness: str
    tree_head: TreeHead
    timestamp: int
    signature: bytes

    def signed_message(self) -> bytes:
        return cosignature_message(self.tree_head, self.timestamp)

    def verify(self, public_key: bytes, verify_fn: VerifyFn) -> bool:
        return verify_fn(public_key, self.signed_message(), self.signature)


class WitnessRegistry:
    """Witness name -> public key. The verifier's own trusted key set."""

    def __init__(self, keys: Optional[Dict[str, bytes]] = None) -> None:
        self._keys: Dict[str, bytes] = dict(keys or {})

    def register(self, name: str, public_key: bytes) -> None:
        if name in self._keys:
            raise ValueError(f"witness {name!r} already registered")
        self._keys[name] = public_key

    def public_key(self, name: str) -> Optional[bytes]:
        return self._keys.get(name)

    def names(self) -> List[str]:
        return sorted(self._keys)

    def __len__(self) -> int:
        return len(self._keys)


# --- the conflict predicate --------------------------------------------------

class ConflictKind(Enum):
    NONE = "none"
    #: Same log and size, different root -- provable from the two statements
    #: alone, exactly like PALISADE's Theorem 1(b).
    EQUIVOCATION = "equivocation"
    #: Same log, different sizes. These may still be a fork, but the two signed
    #: statements alone cannot show it: adjudicating requires a consistency
    #: proof between the two roots. Not self-contained evidence.
    INCONCLUSIVE_NEEDS_CONSISTENCY = "inconclusive_needs_consistency"


@dataclass(frozen=True)
class ConflictVerdict:
    kind: ConflictKind
    reason: str

    @property
    def is_equivocation(self) -> bool:
        return self.kind is ConflictKind.EQUIVOCATION


def conflict_verdict(a: TreeHead, b: TreeHead) -> ConflictVerdict:
    """Decide whether two tree heads conflict. **The corrected predicate.**

    Compares tree-head identity, never the signed bytes -- signed bytes carry a
    timestamp, so byte-inequality is not evidence of anything.
    """
    if a.origin != b.origin:
        return ConflictVerdict(ConflictKind.NONE, "different logs; not comparable")
    if a.size != b.size:
        return ConflictVerdict(
            ConflictKind.INCONCLUSIVE_NEEDS_CONSISTENCY,
            "same log, different sizes: a fork is possible but needs a "
            "consistency proof to establish; signatures alone do not suffice",
        )
    if a.root_hash == b.root_hash:
        return ConflictVerdict(ConflictKind.NONE, "identical tree head")
    return ConflictVerdict(
        ConflictKind.EQUIVOCATION,
        "same log and size with different roots: split view",
    )


def conflicts_by_signed_bytes(a: Cosignature, b: Cosignature) -> bool:
    """PALISADE's *native* predicate, ported naively: byte-inequality.

    Retained deliberately so the test suite can demonstrate that this predicate
    produces false accusations against honest witnesses under sigsum's format.
    Do not use it for attribution.
    """
    return a.signed_message() != b.signed_message()


# --- attribution -------------------------------------------------------------

@dataclass(frozen=True)
class WitnessCulpability:
    """A transferable proof that one witness cosigned a split view.

    The sigsum analogue of :class:`palisade.accountability.EquivocationEvidence`:
    verifiable by any third party from these two cosignatures and the witness's
    registered key, and -- with the corrected predicate -- never satisfiable by
    an honest witness.
    """

    witness: str
    origin: str
    size: int
    cosignature_a: Cosignature
    cosignature_b: Cosignature

    def verify(self, registry: WitnessRegistry, verify_fn: VerifyFn) -> bool:
        pk = registry.public_key(self.witness)
        if pk is None:
            return False
        if self.cosignature_a.witness != self.witness or self.cosignature_b.witness != self.witness:
            return False
        verdict = conflict_verdict(self.cosignature_a.tree_head, self.cosignature_b.tree_head)
        if not verdict.is_equivocation:
            return False
        return self.cosignature_a.verify(pk, verify_fn) and self.cosignature_b.verify(pk, verify_fn)


def extract_witness_equivocation(
    cosignatures_a: Sequence[Cosignature],
    cosignatures_b: Sequence[Cosignature],
    registry: WitnessRegistry,
    verify_fn: VerifyFn,
) -> List[WitnessCulpability]:
    """Attribute a split view to the witnesses who cosigned both sides.

    The direct analogue of :func:`palisade.accountability.extract_equivocation`,
    retargeted onto sigsum cosignatures. Returns one proof per culpable witness;
    an empty list means no witness is provably culpable.
    """
    by_witness_a: Dict[str, Cosignature] = {c.witness: c for c in cosignatures_a}
    culprits: List[WitnessCulpability] = []
    for cb in cosignatures_b:
        ca = by_witness_a.get(cb.witness)
        if ca is None:
            continue
        if not conflict_verdict(ca.tree_head, cb.tree_head).is_equivocation:
            continue
        pk = registry.public_key(cb.witness)
        if pk is None:
            continue
        if ca.verify(pk, verify_fn) and cb.verify(pk, verify_fn):
            culprits.append(
                WitnessCulpability(
                    witness=cb.witness,
                    origin=ca.tree_head.origin,
                    size=ca.tree_head.size,
                    cosignature_a=ca,
                    cosignature_b=cb,
                )
            )
    return culprits


def guaranteed_culprits(k: int, n: int) -> int:
    """Witnesses guaranteed attributable under a ``k``-of-``n`` quorum policy.

    PALISADE fixes the quorum at 2f+1 of n>=3f+1, giving an intersection of at
    least f+1. Sigsum instead lets each client pick a quorum policy, so the
    guarantee generalizes to the intersection bound ``2k - n``.

    The consequence is a real deployment constraint: a policy with ``k <= n/2``
    guarantees **no** attributable witness, so PALISADE's headline property
    silently evaporates. Callers should refuse such policies.
    """
    if n <= 0 or not 0 <= k <= n:
        raise ValueError("require 0 <= k <= n and n > 0")
    return max(0, 2 * k - n)


def policy_supports_attribution(k: int, n: int) -> bool:
    """True iff a ``k``-of-``n`` policy guarantees at least one culprit."""
    return guaranteed_culprits(k, n) >= 1
