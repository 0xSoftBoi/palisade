"""Consensus-round tests: votes, commit quorum, vote equivocation, refusal."""

import pytest

from palisade.consensus import (
    Proposal,
    Vote,
    VoteCollector,
    cast_vote,
    collect_censorship_evidence,
    sign_non_inclusion,
)
from palisade.hashing import empty_root, sha256
from palisade.records import Artifact

from tests.conftest import make_validators


def _proposal(epoch=0, view=0, h_prev=None, n_records=3):
    records = [Artifact(content_hash=sha256(f"r{i}".encode()), artifact_type="doc")
               for i in range(n_records)]
    return Proposal(epoch=epoch, view=view, records=records,
                    h_prev=h_prev if h_prev is not None else empty_root())


def test_vote_guard_rejects_wrong_prev_root():
    validators, _ = make_validators(4)
    prop = _proposal(h_prev=empty_root())
    # local root differs from h_prev -> abstain (Alg. 1 line 1)
    assert cast_vote(validators[0], prop, local_root=sha256(b"different")) is None


def test_quorum_commit():
    validators, registry = make_validators(4)  # n=4, f=1 -> quorum 3
    prop = _proposal()
    collector = VoteCollector(registry, quorum=3)
    for v in validators[:3]:
        vote = cast_vote(v, prop, local_root=prop.h_prev)
        assert collector.add(vote) is None
    cert = collector.try_commit(prop.epoch, prop.view, prop.batch_hash(), prop.h_prev)
    assert cert is not None
    assert cert.verify(registry, 3)


def test_no_commit_below_quorum():
    validators, registry = make_validators(4)
    prop = _proposal()
    collector = VoteCollector(registry, quorum=3)
    for v in validators[:2]:
        collector.add(cast_vote(v, prop, local_root=prop.h_prev))
    assert collector.try_commit(prop.epoch, prop.view, prop.batch_hash(), prop.h_prev) is None


def test_vote_equivocation_detected():
    validators, registry = make_validators(4)
    byz = validators[0]
    prop_a = _proposal(n_records=2)
    prop_b = _proposal(n_records=5)  # different batch, same epoch/view/h_prev
    assert prop_a.batch_hash() != prop_b.batch_hash()

    collector = VoteCollector(registry, quorum=3)
    assert collector.add(cast_vote(byz, prop_a, local_root=prop_a.h_prev)) is None
    evidence = collector.add(cast_vote(byz, prop_b, local_root=prop_b.h_prev))
    assert evidence is not None
    assert evidence.validator_id == byz.id
    assert evidence.verify(registry)  # transferable, per-round culpability


def test_matching_revote_is_not_equivocation():
    validators, registry = make_validators(4)
    prop = _proposal()
    collector = VoteCollector(registry, quorum=3)
    v1 = cast_vote(validators[0], prop, local_root=prop.h_prev)
    # Re-signing the same proposal in the same round consumes a new OTS index
    # but is not a conflicting vote (same batch).
    v2 = cast_vote(validators[0], prop, local_root=prop.h_prev)
    assert collector.add(v1) is None
    assert collector.add(v2) is None  # same (e,view,batch,h_prev) -> no conflict


def test_collector_rejects_invalid_signature():
    validators, registry = make_validators(4)
    prop = _proposal()
    good = cast_vote(validators[0], prop, local_root=prop.h_prev)
    forged = Vote(
        validator_id=validators[1].id,  # claim a different signer
        epoch=good.epoch, view=good.view, batch_h=good.batch_h,
        h_prev=good.h_prev, signature=good.signature,
    )
    collector = VoteCollector(registry, quorum=3)
    with pytest.raises(ValueError):
        collector.add(forged)


# --- Accountable refusal ----------------------------------------------------

def test_censorship_evidence_from_f_plus_one():
    validators, registry = make_validators(4)  # f=1 -> threshold f+1 = 2
    record_hash = sha256(b"pending-record")
    stmts = [sign_non_inclusion(validators[i], record_hash, epoch=5) for i in range(2)]
    evidence = collect_censorship_evidence(stmts, registry, threshold=2)
    assert evidence is not None
    assert evidence.verify(registry, threshold=2)


def test_censorship_evidence_below_threshold():
    validators, registry = make_validators(4)
    record_hash = sha256(b"pending")
    stmts = [sign_non_inclusion(validators[0], record_hash, epoch=5)]
    assert collect_censorship_evidence(stmts, registry, threshold=2) is None


def test_censorship_rejects_duplicate_signer():
    validators, registry = make_validators(4)
    record_hash = sha256(b"pending")
    s = sign_non_inclusion(validators[0], record_hash, epoch=5)
    from palisade.consensus import CensorshipEvidence
    ev = CensorshipEvidence(record_hash=record_hash, epoch=5, statements=[s, s])
    assert not ev.verify(registry, threshold=2)  # one validator, counted once
