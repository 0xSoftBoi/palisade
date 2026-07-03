"""External anchoring and the anchored fork bound (Theorem 2, section 5.2).

Per epoch, ``H(CP_e)`` may be anchored outward -- to a public chain, a KSI-class
service, or any widely witnessed medium in the Haber-Stornetta tradition.

Theorem 2: if ``H(CP_e)`` is anchored at time ``t_e`` in a medium the verifier
trusts for integrity and time, then an adversary controlling *all* validators
after ``t_e`` cannot convince a verifier holding the anchor of any history
diverging at or before epoch ``e``, unless it finds a collision in ``H`` (or
forges the anchor medium). Signature power gained after ``t_e`` is irrelevant:
no signature can alter what the anchored digest binds.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence

from .checkpoint import CheckpointCertificate
from .merkle import verify_consistency


@dataclass(frozen=True)
class Anchor:
    digest: bytes  # H(CP_e)
    epoch: int
    time: int      # anchoring time t_e, per the trusted medium


class AnchorMedium:
    """A witnessed medium trusted for integrity and time.

    Real deployments anchor into a public chain or KSI-class service; this is
    an append-only, tamper-evident stand-in used to state and test Theorem 2.
    Once written, an anchor is immutable here (the trust assumption of the
    theorem: the verifier trusts the medium for integrity and time).
    """

    def __init__(self) -> None:
        self._anchors: List[Anchor] = []

    def anchor(self, cert: CheckpointCertificate, time: int) -> Anchor:
        a = Anchor(digest=cert.cert_hash(), epoch=cert.epoch, time=time)
        self._anchors.append(a)
        return a

    def latest(self) -> Optional[Anchor]:
        return self._anchors[-1] if self._anchors else None

    def for_epoch(self, epoch: int) -> Optional[Anchor]:
        for a in reversed(self._anchors):
            if a.epoch == epoch:
                return a
        return None


@dataclass(frozen=True)
class ForkVerdict:
    accepted: bool
    reason: str


def verify_against_anchor(
    anchor: Anchor,
    presented_cert: CheckpointCertificate,
    presented_root: bytes,
    presented_size: int,
    consistency_proof: Sequence[bytes],
) -> ForkVerdict:
    """Decide whether a presented later state is admissible under an anchor.

    Enforces the three-part verifier demand of Theorem 2's proof:

    1. ``presented_cert`` must hash to the anchored digest (else a collision was
       claimed -- rejected);
    2. a consistency proof must carry the anchored checkpoint's root
       ``h*_e`` forward to the presented state (else non-prefix -- rejected);
    3. no proof means rejection by policy.

    Any accepted state provably extends the anchored history; nothing an
    adversary signs after ``t_e`` can change that.
    """
    if presented_cert.cert_hash() != anchor.digest:
        return ForkVerdict(False, "presented checkpoint does not match anchored digest")
    if presented_size < presented_cert.body.size:
        return ForkVerdict(False, "presented state is shorter than the anchored checkpoint")
    if presented_size == presented_cert.body.size:
        ok = presented_root == presented_cert.body.root
        return ForkVerdict(ok, "root matches anchored checkpoint" if ok else "root diverges from anchor")
    ok = verify_consistency(
        presented_cert.body.size,
        presented_size,
        list(consistency_proof),
        presented_cert.body.root,
        presented_root,
    )
    if not ok:
        return ForkVerdict(False, "no valid consistency proof from anchored checkpoint to presented state")
    return ForkVerdict(True, "presented state provably extends the anchored history")
