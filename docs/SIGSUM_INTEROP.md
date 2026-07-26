# Does the culpability proof survive contact with sigsum?

*Experiment report, July 2026. Code: `src/palisade/interop/sigsum.py`,
`tests/test_interop_sigsum.py`.*

## Why this was run

[`docs/POSITIONING.md`](POSITIONING.md) concluded that PALISADE's log layer
duplicates deployed prior art, and that its defensible contribution is the
**accountability layer** — a transferable proof naming ≥ f+1 specific culpable
validators. The natural consequence was to stop reinventing the log and instead
run that layer on top of an existing one.

That is a claim, not a fact. This experiment tested it the cheap way: retarget
the attribution logic onto [sigsum](https://www.sigsum.org/)'s real checkpoint
and witness-cosignature format and see what breaks. Failing here is much
cheaper than failing after building a view-change state machine.

**Result: the claim mostly survives, but one defect was found — and it is the
worst kind.** The naive port falsely accuses honest witnesses.

## The formats (implemented byte-exactly)

A sigsum checkpoint note body is three newline-terminated lines:

```
sigsum.org/v1/tree/<64 hex chars: the log's key hash>
<tree size, decimal, no leading zeros>
<base64 of the 32-byte Merkle root>
```

A witness cosignature does **not** sign that body directly. Per
[C2SP `tlog-cosignature`](https://github.com/C2SP/C2SP/blob/main/tlog-cosignature.md),
it signs a five-line message:

```
cosignature/v1
time 1679315147
sigsum.org/v1/tree/<...>
15368405
31JQUq8EyQx5lpqtKRqryJzA+77WD2xmTyuB4uIlXeE=
```

Signature lines are `— <name> base64(keyID || sig)`, with the 4-byte key ID
being `SHA-256(name || 0x0A || 0x04 || pubkey)[:4]` for Ed25519. All of this is
implemented and round-tripped in the test suite, signed with real Ed25519.

## Finding 1 — the naive port falsely accuses honest witnesses ⚠️

**The timestamp is inside the signed bytes.**

A sigsum cosignature is semantically *"as of this time, the largest consistent
tree head I have seen is X."* A witness therefore re-cosigns the **same** tree
head repeatedly as time passes. That is not merely permitted, it is the
expected steady-state behaviour.

PALISADE's `EquivocationEvidence.verify` establishes "these two statements
conflict" by testing **byte-inequality of the two signed bodies**. Under
PALISADE's own format that is sound: its canonical encoding is injective on the
claim and carries no per-signature metadata, so different bytes ⟹ different
claim.

Under sigsum's format it is unsound, in the worst direction:

```
msg@t1: 'cosignature/v1\ntime 1679315147\n<origin>\n100\nCWcRXygTo1Qe...=\n'
msg@t2: 'cosignature/v1\ntime 1679401547\n<origin>\n100\nCWcRXygTo1Qe...=\n'

bytes differ?                     True
same tree head?                   True

PALISADE native predicate  =>  CONFLICT   (false accusation)
corrected predicate        =>  none
```

Two honest signatures, same claim, different times — and the predicate names
the witness as a culprit. This breaks precisely the half of Theorem 1(b) that
carries the weight: *"never implicating an honest validator."* A false
accusation against a supplier is worse than a missed detection, because it is
actioned.

**The fix** is to compare the *claim*, never the signed bytes:

```python
def conflict_verdict(a: TreeHead, b: TreeHead) -> ConflictVerdict:
    if a.origin != b.origin:   return NONE          # different logs
    if a.size   != b.size:     return INCONCLUSIVE  # see Finding 2
    if a.root_hash == b.root_hash: return NONE      # identical head
    return EQUIVOCATION                             # split view
```

Regression tests pin both directions: the honest pair is no longer accused, and
genuine equivocation (same size, different roots) is still attributed.

**Scope of the defect.** PALISADE's *theorem* is not wrong, and its native
implementation is not wrong — `extract_equivocation` already compares payload
tuples, and `VoteCollector` compares vote tuples. The defect is that the
`EquivocationEvidence` type encodes an **unstated, format-specific assumption**
in its own soundness check. The paper states Theorem 1(b) as though the
predicate were universal ("any two conflicting signed votes are a culpability
proof"); it is not — it is a property of the encoding. That assumption is now
documented in the type itself.

## Finding 2 — self-containment holds only within a tree size

PALISADE's Theorem 1 is *self-contained*: two certificates plus the registry
settle the matter, with no extra evidence and no live state. That property is
what makes the proof transferable to a third party such as a contracting
officer.

Sigsum has no epochs — only a monotonically growing tree size. So:

| Case | Verdict | Self-contained? |
|---|---|---|
| Same log, same size, different roots | **Equivocation** | ✅ yes — the two cosignatures suffice |
| Same log, different sizes | **Inconclusive** | ❌ no — needs a consistency proof |
| Different logs | No conflict | — |

A witness that cosigns `(size=100, rootA)` and later `(size=200, rootB)` where
the 200-tree does *not* extend the 100-tree has genuinely forked — but the two
signed statements alone cannot show it. Adjudicating requires a consistency
proof between the roots, i.e. cooperation from the log or an auditor holding
the tree.

This is a real narrowing when porting: PALISADE's per-epoch structure buys
self-containment that a size-indexed log does not give for free. The adapter
returns `INCONCLUSIVE_NEEDS_CONSISTENCY` rather than silently reporting "no
conflict," so the distinction cannot be lost by accident.

## Finding 3 — the f+1 guarantee is a policy parameter, not a constant

PALISADE fixes n ≥ 3f+1 with a 2f+1 quorum, so two conflicting quorums
intersect in ≥ f+1 validators. Sigsum instead lets each **client** choose a
witness quorum policy, so the guarantee generalizes to the intersection bound:

```
guaranteed_culprits(k, n) = max(0, 2k - n)
```

Substituting PALISADE's parameters recovers the paper exactly: `k = 2f+1`,
`n = 3f+1` ⟹ `f+1`. (Tested for f = 1..4.)

The deployment trap is that a permissive policy **silently destroys the
property**: a 2-of-5 quorum gives `max(0, 4-5) = 0` guaranteed culprits. The
log still resists split-view in the ordinary sense, but nobody is provably
attributable — the entire value proposition evaporates with no error message.
`policy_supports_attribution(k, n)` exists so a deployment can refuse such a
policy at configuration time rather than discovering it during an incident.

**This is a genuinely useful export.** It converts "PALISADE gives f+1
accountability" into a checkable predicate over *someone else's* quorum policy.

## What this means for the project

**The core thesis held.** Attribution is separable from the log. The adapter is
~300 lines with no changes to PALISADE's log layer, which is unsurprising given
that `tests/test_rfc6962_vectors.py` already pins that layer to the RFC 6962
vectors sigsum's ecosystem uses.

**But "just port Theorem 1" was too glib.** Three things needed real work:
a format-specific conflict predicate (Finding 1), an explicit inconclusive
verdict (Finding 2), and quorum arithmetic parameterized by a foreign policy
(Finding 3). None was visible from the paper.

**Revised positioning.** The defensible pitch is narrower and more concrete
than "an accountable PQ log":

> A witness-accountability layer for transparency logs: turn split-view
> *detection* into a transferable proof naming specific culpable witnesses,
> with a checkable condition on whether your quorum policy can support
> attribution at all.

That is useful to the existing sigsum/Trillian ecosystem *today*, independent
of the post-quantum argument — which matters, because
[`POSITIONING.md`](POSITIONING.md) found the PQ procurement pull is a forecast
rather than a current requirement.

## Honest limits of this experiment

- The adapter is tested against the **published specification**, not against a
  live sigsum log or the `sigsum-go` implementation. Spec conformance is not
  the same as wire conformance; a real interop test against `sigsum-go` output
  is the obvious next check.
- Only Ed25519 cosignatures are handled. C2SP also specifies ML-DSA-44, which
  PALISADE's assumption audit would reject anyway — worth noting as a tension:
  the ecosystem's PQ path is lattice-based, exactly as `POSITIONING.md` found.
- Sigsum's actual witness protocol (consistency-proof exchange, HTTP endpoints)
  is not implemented; this covers the cosignature artifacts only.
- No claim is made that sigsum has a vulnerability. Sigsum's own design does
  not use the flawed predicate — the defect found here is in **PALISADE's**
  logic when ported, and it was found before it reached anything real.

## Sources

- [sigsum log design documentation](https://git.glasklar.is/sigsum/project/documentation/-/raw/main/log.md)
- [C2SP `tlog-cosignature` specification](https://github.com/C2SP/C2SP/blob/main/tlog-cosignature.md)
- [C2SP `tlog-witness` specification](https://github.com/C2SP/C2SP/blob/main/tlog-witness.md)
- [Sigsum project](https://www.sigsum.org/)
