"""Accountability: transferable culpability proofs (Theorem 1, Proposition 1).

Two mechanisms turn misbehavior into evidence any third party can check offline:

* **Equivocation (Theorem 1).** Two verifying checkpoint certificates for the
  same epoch with different ``(h_e, |L_e|)`` cannot exist unless >= f+1
  validators signed both -- and the paired signatures *are* the proof, never
  implicating an honest validator.

* **Index reuse (Proposition 1).** Under on-log index disclosure (K3), any
  reuse of an OTS index ``q`` by a validator produces two published signatures
  under that validator's key with equal ``q`` on distinct messages. That pair
  is O(1)-detectable and is itself a transferable culpability proof of exactly
  the Theorem 1(b) form.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .checkpoint import CheckpointCertificate, ValidatorRegistry, ValidatorSignature
from .signatures import HashSignature, verify_signature


# --- Theorem 1: equivocation over conflicting checkpoints -------------------

@dataclass(frozen=True)
class EquivocationEvidence:
    """One validator's culpability: two valid signatures over conflicting
    epoch-``e`` checkpoint bodies.

    .. warning::
       **Format invariant.** ``verify`` treats byte-inequality of ``body_a`` and
       ``body_b`` as proof that the two statements conflict. That is sound here
       only because PALISADE's canonical encodings are injective on the claim
       *and carry no per-signature metadata* -- so differing bytes imply a
       differing claim.

       This assumption does not travel. Porting this evidence type to a format
       whose signed bytes include per-signature metadata (a timestamp, a nonce)
       makes the predicate unsound in the worst direction: two honest signatures
       over the *same* claim at different times differ in bytes and would be
       accepted as evidence, falsely implicating an honest signer and breaking
       the half of Theorem 1(b) that matters most.

       ``palisade.interop.sigsum`` demonstrates exactly this against the C2SP
       cosignature format, and shows the corrected approach: compare the
       *claim*, never the signed bytes. See ``docs/SIGSUM_INTEROP.md``.
    """

    validator_id: str
    epoch: int
    body_a: bytes
    signature_a: HashSignature
    body_b: bytes
    signature_b: HashSignature

    def verify(self, registry: ValidatorRegistry) -> bool:
        pk = registry.public_key(self.validator_id)
        if pk is None:
            return False
        # Sound only under the format invariant documented above.
        if self.body_a == self.body_b:
            return False  # not conflicting -> not evidence
        return verify_signature(pk, self.body_a, self.signature_a) and verify_signature(
            pk, self.body_b, self.signature_b
        )


@dataclass(frozen=True)
class CulpabilityProof:
    """A transferable proof implicating >= f+1 validators for equivocation."""

    epoch: int
    culprits: List[EquivocationEvidence]

    def culprit_ids(self) -> List[str]:
        return sorted(c.validator_id for c in self.culprits)

    def verify(self, registry: ValidatorRegistry) -> bool:
        """Any third party can check this from the two certificates and the
        registry; it never implicates an honest validator."""
        if not self.culprits:
            return False
        seen: set[str] = set()
        for c in self.culprits:
            if c.epoch != self.epoch or c.validator_id in seen:
                return False
            if not c.verify(registry):
                return False
            seen.add(c.validator_id)
        return True


def extract_equivocation(
    cert_a: CheckpointCertificate,
    cert_b: CheckpointCertificate,
    registry: ValidatorRegistry,
) -> Optional[CulpabilityProof]:
    """Derive a culpability proof from two conflicting certificates.

    Returns ``None`` if the certificates are not a genuine equivocation (same
    epoch, different ``(h_e, |L_e|)`` payload). The returned proof implicates
    exactly the validators who signed both conflicting bodies -- the >= f+1
    intersection of Theorem 1.
    """
    if cert_a.epoch != cert_b.epoch:
        return None
    if cert_a.body.payload() == cert_b.body.payload():
        return None  # same payload -> not conflicting

    body_a = cert_a.body.canonical()
    body_b = cert_b.body.canonical()

    sigs_a: Dict[str, ValidatorSignature] = {
        vs.validator_id: vs for vs in cert_a.signatures
    }
    culprits: List[EquivocationEvidence] = []
    for vs_b in cert_b.signatures:
        vs_a = sigs_a.get(vs_b.validator_id)
        if vs_a is None:
            continue
        pk = registry.public_key(vs_b.validator_id)
        if pk is None:
            continue
        # Only count a validator whose *both* signatures actually verify.
        if verify_signature(pk, body_a, vs_a.signature) and verify_signature(
            pk, body_b, vs_b.signature
        ):
            culprits.append(
                EquivocationEvidence(
                    validator_id=vs_b.validator_id,
                    epoch=cert_a.epoch,
                    body_a=body_a,
                    signature_a=vs_a.signature,
                    body_b=body_b,
                    signature_b=vs_b.signature,
                )
            )
    if not culprits:
        return None
    return CulpabilityProof(epoch=cert_a.epoch, culprits=culprits)


# --- Proposition 1: OTS index reuse -----------------------------------------

@dataclass(frozen=True)
class IndexReuseProof:
    """Two signatures under one validator key sharing an OTS index but over
    distinct messages: a transferable culpability proof (Proposition 1)."""

    validator_id: str
    index: int
    message_a: bytes
    signature_a: HashSignature
    message_b: bytes
    signature_b: HashSignature

    def verify(self, registry: ValidatorRegistry) -> bool:
        pk = registry.public_key(self.validator_id)
        if pk is None:
            return False
        if self.message_a == self.message_b:
            return False
        if self.signature_a.index != self.index or self.signature_b.index != self.index:
            return False
        return verify_signature(pk, self.message_a, self.signature_a) and verify_signature(
            pk, self.message_b, self.signature_b
        )


class ReuseMonitor:
    """Detects OTS index reuse in O(1) per signature (Proposition 1).

    Feed it every published ``(validator_id, message, signature)``. Because K3
    puts the OTS index on-log, a repeat index on a distinct message is flagged
    on arrival. K1 rules out benign duplication, so a flag means the module
    boundary was bypassed -- misbehavior -- or a forgery (negligible).
    """

    def __init__(self) -> None:
        self._seen: Dict[Tuple[str, int], Tuple[bytes, HashSignature]] = {}

    def observe(
        self, validator_id: str, message: bytes, signature: HashSignature
    ) -> Optional[IndexReuseProof]:
        key = (validator_id, signature.index)
        prior = self._seen.get(key)
        if prior is None:
            self._seen[key] = (message, signature)
            return None
        prior_message, prior_sig = prior
        if prior_message == message:
            return None  # identical re-broadcast, not reuse
        return IndexReuseProof(
            validator_id=validator_id,
            index=signature.index,
            message_a=prior_message,
            signature_a=prior_sig,
            message_b=message,
            signature_b=signature,
        )
