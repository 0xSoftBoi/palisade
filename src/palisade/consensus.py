"""The replication round: votes, commits, and accountable refusal (section 5).

Rounds follow the PBFT/Tendermint pattern: a rotating proposer batches
schema-valid records; validators vote with LMS signatures over
``(e, view, H(batch), h_prev)``; 2f+1 matching votes commit, extending the
history tree (Algorithm 1). The full view-change state machine is textbook and
out of scope; what is implemented here is the accountable surface:

* commit on a 2f+1 matching-vote quorum, with each vote's OTS index on-log (K3);
* **vote-granularity equivocation** -- two votes by one validator for the same
  ``(e, view)`` over different batches yield a culpability proof, attributing
  equivocation per round, not merely per epoch (Theorem 1, final sentence);
* **accountable refusal** -- signed non-inclusion statements from f+1 validators
  for a well-formed record pending beyond a bound convert censorship into
  evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .accountability import EquivocationEvidence
from .checkpoint import ValidatorRegistry
from .hashing import sha256, tagged
from .records import schema_valid
from .signatures import HashSignature, verify_signature


def batch_hash(records: Sequence[bytes]) -> bytes:
    """H(batch): a domain-separated hash over the ordered record bytes."""
    return tagged("consensus:batch:v1", *records)


def vote_body(epoch: int, view: int, batch_h: bytes, h_prev: bytes) -> bytes:
    """The bytes a validator signs when voting (Algorithm 1, line 2)."""
    return tagged(
        "consensus:vote:v1",
        epoch.to_bytes(8, "big"),
        view.to_bytes(8, "big"),
        batch_h,
        h_prev,
    )


@dataclass(frozen=True)
class Proposal:
    """A proposer's batch for one ``(epoch, view)`` extending ``h_prev``.

    ``records`` are typed record objects (Artifact / CustodyEvent /
    Attestation); the batch is hashed over their canonical encodings.
    """

    epoch: int
    view: int
    records: List[object]
    h_prev: bytes

    def canonical_records(self) -> List[bytes]:
        return [r.canonical() for r in self.records]

    def batch_hash(self) -> bytes:
        return batch_hash(self.canonical_records())


@dataclass(frozen=True)
class Vote:
    validator_id: str
    epoch: int
    view: int
    batch_h: bytes
    h_prev: bytes
    signature: HashSignature  # carries the on-log OTS index (K3)

    def body(self) -> bytes:
        return vote_body(self.epoch, self.view, self.batch_h, self.h_prev)

    def matches(self, other: "Vote") -> bool:
        return (
            self.epoch == other.epoch
            and self.view == other.view
            and self.batch_h == other.batch_h
            and self.h_prev == other.h_prev
        )


def cast_vote(
    validator, proposal: Proposal, local_root: bytes
) -> Optional[Vote]:
    """Algorithm 1: vote iff the batch is schema-valid and ``h_prev`` matches
    the local root; then HSM sign-and-increment over the vote body.

    Returns ``None`` (an abstention) when the guard fails, exactly as line 1 of
    Algorithm 1 returns without voting.
    """
    if proposal.h_prev != local_root:
        return None
    if not all(schema_valid(r) for r in proposal.records):
        return None
    body = vote_body(proposal.epoch, proposal.view, proposal.batch_hash(), proposal.h_prev)
    sig = validator.sign(body)
    return Vote(
        validator_id=validator.id,
        epoch=proposal.epoch,
        view=proposal.view,
        batch_h=proposal.batch_hash(),
        h_prev=proposal.h_prev,
        signature=sig,
    )


@dataclass(frozen=True)
class CommitCertificate:
    """A committed batch: 2f+1 matching votes over one ``(e, view)`` proposal."""

    epoch: int
    view: int
    batch_h: bytes
    h_prev: bytes
    votes: List[Vote]

    def verify(self, registry: ValidatorRegistry, quorum: int) -> bool:
        seen: set[str] = set()
        body = vote_body(self.epoch, self.view, self.batch_h, self.h_prev)
        count = 0
        for v in self.votes:
            if v.validator_id in seen:
                return False
            pk = registry.public_key(v.validator_id)
            if pk is None or not verify_signature(pk, body, v.signature):
                return False
            if not (v.epoch == self.epoch and v.view == self.view and v.batch_h == self.batch_h and v.h_prev == self.h_prev):
                return False
            seen.add(v.validator_id)
            count += 1
        return count >= quorum


class VoteCollector:
    """Collects votes for a round, commits on quorum, and flags equivocation.

    Feeding two conflicting votes from one validator for the same ``(e, view)``
    returns an :class:`EquivocationEvidence` -- vote-granularity accountability.
    """

    def __init__(self, registry: ValidatorRegistry, quorum: int) -> None:
        self._registry = registry
        self._quorum = quorum
        # (epoch, view, batch_h, h_prev) -> {validator_id: Vote}
        self._by_proposal: Dict[Tuple[int, int, bytes, bytes], Dict[str, Vote]] = {}
        # (epoch, view) -> {validator_id: Vote} for equivocation detection
        self._by_round: Dict[Tuple[int, int], Dict[str, Vote]] = {}

    def add(self, vote: Vote) -> Optional[EquivocationEvidence]:
        """Add a vote. Returns equivocation evidence if this vote conflicts
        with a prior vote from the same validator in the same round."""
        pk = self._registry.public_key(vote.validator_id)
        if pk is None or not verify_signature(pk, vote.body(), vote.signature):
            raise ValueError("vote signature does not verify")

        round_key = (vote.epoch, vote.view)
        prior = self._by_round.setdefault(round_key, {}).get(vote.validator_id)
        if prior is not None and not prior.matches(vote):
            return EquivocationEvidence(
                validator_id=vote.validator_id,
                epoch=vote.epoch,
                body_a=prior.body(),
                signature_a=prior.signature,
                body_b=vote.body(),
                signature_b=vote.signature,
            )
        self._by_round[round_key][vote.validator_id] = vote

        pkey = (vote.epoch, vote.view, vote.batch_h, vote.h_prev)
        self._by_proposal.setdefault(pkey, {})[vote.validator_id] = vote
        return None

    def try_commit(
        self, epoch: int, view: int, batch_h: bytes, h_prev: bytes
    ) -> Optional[CommitCertificate]:
        votes = self._by_proposal.get((epoch, view, batch_h, h_prev), {})
        if len(votes) < self._quorum:
            return None
        cert = CommitCertificate(
            epoch=epoch, view=view, batch_h=batch_h, h_prev=h_prev,
            votes=list(votes.values()),
        )
        return cert if cert.verify(self._registry, self._quorum) else None


# --- Accountable refusal (section 5) ----------------------------------------

def refusal_body(record_hash: bytes, epoch: int) -> bytes:
    return tagged("consensus:refusal:v1", record_hash, epoch.to_bytes(8, "big"))


@dataclass(frozen=True)
class NonInclusion:
    """A validator's signed statement that a well-formed record remains
    un-included past the agreed bound."""

    validator_id: str
    record_hash: bytes
    epoch: int
    signature: HashSignature

    def body(self) -> bytes:
        return refusal_body(self.record_hash, self.epoch)

    def verify(self, registry: ValidatorRegistry) -> bool:
        pk = registry.public_key(self.validator_id)
        return pk is not None and verify_signature(pk, self.body(), self.signature)


def sign_non_inclusion(validator, record_hash: bytes, epoch: int) -> NonInclusion:
    body = refusal_body(record_hash, epoch)
    return NonInclusion(
        validator_id=validator.id,
        record_hash=record_hash,
        epoch=epoch,
        signature=validator.sign(body),
    )


@dataclass(frozen=True)
class CensorshipEvidence:
    """f+1 non-inclusion statements for one record: censorship as evidence."""

    record_hash: bytes
    epoch: int
    statements: List[NonInclusion]

    def verify(self, registry: ValidatorRegistry, threshold: int) -> bool:
        """Valid iff at least ``threshold`` (= f+1) distinct validators signed a
        non-inclusion for this record and epoch."""
        seen: set[str] = set()
        for s in self.statements:
            if s.validator_id in seen:
                return False
            if s.record_hash != self.record_hash or s.epoch != self.epoch:
                return False
            if not s.verify(registry):
                return False
            seen.add(s.validator_id)
        return len(seen) >= threshold


def collect_censorship_evidence(
    statements: Sequence[NonInclusion],
    registry: ValidatorRegistry,
    threshold: int,
) -> Optional[CensorshipEvidence]:
    """Assemble censorship evidence if f+1 valid, distinct non-inclusions agree
    on one (record, epoch)."""
    if not statements:
        return None
    record_hash = statements[0].record_hash
    epoch = statements[0].epoch
    evidence = CensorshipEvidence(record_hash=record_hash, epoch=epoch, statements=list(statements))
    return evidence if evidence.verify(registry, threshold) else None
