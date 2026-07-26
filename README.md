# PALISADE

**An assumption-minimal, hash-based accountable log for long-horizon provenance.**

Every widely deployed blockchain authenticates its history with elliptic-curve
signatures that NIST IR 8547 deprecates after 2030 and CNSA 2.0 excludes from
new national-security acquisitions after January 1, 2027. For ledgers whose
records are *evidence* — parts provenance, software supply chains, chain of
custody — that is a validity cliff: a retroactively forgeable signature is
retroactively non-evidence.

PALISADE is a replicated append-only log whose entire record-validity path
reduces to the **(second-)preimage and collision resistance of a standardized
hash function**. No curves, pairings, lattices, token, or virtual machine
appear anywhere a verifier must trust. This repository is a working reference
implementation of the primitive described in the working paper (v0.3).

> This is a reference implementation for study and experimentation. The
> signature layer is a faithful, hash-only *analogue* of LMS/HSS and SLH-DSA
> built from SHA-256; a production deployment uses FIPS 140-3-validated LMS/HSS
> (SP 800-208) and SLH-DSA (FIPS 205). See [Status](#status).

### What is actually new here

Append-only hash logs are a solved problem — RFC 6962, Trillian, sigsum, and
Guardtime KSI all ship, and this log layer is deliberately
[byte-compatible with them](tests/test_rfc6962_vectors.py). Two things are not
solved elsewhere, and they are what this project is really about:

1. **Transferable culpability, not just equivocation resistance.** A cosigned
   log (sigsum) makes split-view *hard*; PALISADE emits a proof that names
   **≥ f+1 specific validators**, checkable by any third party, that never
   implicates an honest one — at vote granularity, not just per epoch.
   Detection without attribution supports no contractual remedy.
2. **Stateful hash-based keys engineered inside a BFT protocol.** CNSA 2.0
   lists LMS/XMSS today, but index reuse voids them — the field failure
   SP 800-208 exists to prevent. K1–K4 plus Proposition 1 make reuse
   structurally impossible in the happy path and O(1)-detectable-with-proof
   otherwise.

For the full landscape review — including what this project concedes to prior
art, and where the compliance thesis is a forecast rather than a current
requirement — see **[docs/POSITIONING.md](docs/POSITIONING.md)**.

Claim (1) was then **tested against a foreign format** by retargeting the
attribution logic onto sigsum's real checkpoint and C2SP witness-cosignature
formats (`palisade.interop.sigsum`). The thesis held — attribution *is*
separable from the log — but the naive port had a serious defect: because
sigsum puts a timestamp inside the signed bytes, PALISADE's byte-inequality
conflict predicate **falsely accuses honest witnesses**. Findings, the
corrected predicate, and the resulting narrower positioning are written up in
**[docs/SIGSUM_INTEROP.md](docs/SIGSUM_INTEROP.md)**.

## What's here

Everything is pure-Python standard library — the only cryptographic dependency
is `hashlib.sha256`, which *is* the point: the assumption surface is one line.

| Module | Paper element | What it provides |
|---|---|---|
| `palisade.merkle` | Definition 1 | RFC 6962 history tree: inclusion proofs `π_incl`, consistency proofs `π_cons`, and their verifiers |
| `palisade.store` | §4 | Content-addressed blob store |
| `palisade.records` | §4 | `Artifact` / `CustodyEvent` / `Attestation` with a fixed, versioned schema check (no VM, no contract layer) |
| `palisade.signatures` | §6 | Lamport OTS under a Merkle many-time signer; `HardwareModule` enforcing invariants **K1** (atomic sign-and-increment), **K2** (partitioned restoration), **K4** (fail-closed exhaustion) |
| `palisade.checkpoint` | Definition 2 | Checkpoint certificates `CP_e = (e, h_e, |L_e|, H(CP_{e-1}), Σ_e)` and the checkpoint chain (the portable spine) |
| `palisade.consensus` | §5, Alg. 1 | The vote/commit round: 2f+1-quorum commits, **vote-granularity equivocation** proofs, and **accountable refusal** (censorship → evidence) |
| `palisade.batch` | §9.2 | Client batch signing — one signature over a B-leaf tree, `log₂B`-hash path per record |
| `palisade.accountability` | Theorem 1, Proposition 1 | Transferable culpability proofs from conflicting checkpoints; **K3** on-log OTS-index reuse detection |
| `palisade.anchoring` | Theorem 2 | External anchoring and the anchored fork bound |
| `palisade.log` | Defs 1–2 | The checkpointed replicated log tying records, epochs, and checkpoints together |
| `palisade.codec` | Def. 2 | Deterministic, strict wire encoding for certificates, signatures, and proofs |
| `palisade.verifier` | Def. 2 | `AuditBundle` + `OfflineVerifier`: check a chain, record inclusions, and epoch consistency from bytes and a trusted registry alone |
| `palisade.cli` | Def. 2 | `palisade` command — produce, inspect, and verify audit bundles |
| `palisade.interop.sigsum` | Thm. 1 ported | Attribution retargeted onto sigsum/C2SP checkpoints; corrected conflict predicate and `k`-of-`n` quorum arithmetic |

### Guarantees, and where they are exercised

- **Tamper-evidence (Def. 1).** Forging an inclusion or consistency proof
  implies a SHA-256 collision. `tests/test_merkle.py` checks all proofs against
  the RFC 6962 construction and rejects every tampering.
- **Ecosystem conformance.** Roots, inclusion paths, and consistency proofs are
  pinned to the **published RFC 6962 reference vectors**, so the log layer is
  byte-identical to a CT-class log and the accountability layer above it could
  sit on an existing Trillian/sigsum log. `tests/test_rfc6962_vectors.py`.
- **Checkpoint uniqueness + (f+1)-accountability (Thm. 1).** Two conflicting
  epoch-`e` certificates yield a proof implicating ≥ f+1 validators, verifiable
  by any third party, never implicating an honest validator.
  `tests/test_accountability.py`.
- **Anchored fork bound (Thm. 2).** An adversary controlling *all* validators
  after an anchor time cannot convince a holder of the anchor of any divergent
  history, absent a collision. `tests/test_anchoring.py`.
- **Stateful-key reuse is detectable (Prop. 1).** Under on-log index disclosure
  (K3), any OTS index reuse is O(1)-detectable and is itself a culpability
  proof. `tests/test_accountability.py`, `tests/test_signatures.py`.
- **Vote-granularity accountability + censorship-as-evidence (§5).** Two votes
  by one validator in a round yield a per-round culpability proof; f+1 signed
  non-inclusions for a pending record convert refusal into transferable
  evidence. `tests/test_consensus.py`.
- **Signing cost is a parameter, not a wall (§9.2).** Batch signing amortizes
  one client signature over a whole batch (B=1024 → one signature, a 10-hash
  path per record). `tests/test_batch.py`.
- **The spine is portable and offline-verifiable (Def. 2).** A chain, registry,
  and proofs serialize to bytes, cross a process boundary, and re-verify
  against the verifier's *own* genesis keys — no operator, network, or live
  state. `tests/test_codec.py`, `tests/test_verifier.py`, `tests/test_cli.py`.

## Quick start

```bash
pip install -e ".[dev]"
python -m pytest          # 155 tests
python examples/demo.py   # full lifecycle walkthrough

# Portable spine, from the command line:
palisade demo-bundle bundle.plsd   # produce a self-contained audit bundle
palisade inspect bundle.plsd       # summarize its checkpoints and claims
palisade verify  bundle.plsd       # verify offline; exit 0 = ACCEPT
```

### A minimal session

```python
import os
from palisade import (Artifact, PalisadeLog, Validator, ValidatorRegistry,
                      HardwareModule, verify_chain, sha256)

# A closed set of n=4 validators, f=1 (n >= 3f+1), each with a hash-based key.
registry = ValidatorRegistry()
validators = []
for i in range(4):
    v = Validator(f"validator-{i}", HardwareModule(os.urandom(32), height=6))
    registry.register(v.id, v.public_key)
    validators.append(v)

log = PalisadeLog(n=4, f=1, registry=registry)
idx = log.append_record(Artifact(content_hash=sha256(b"firmware"),
                                 artifact_type="firmware"))

cert = log.checkpoint(validators)               # quorum-signed checkpoint
assert verify_chain(log.chain, registry, log.quorum)

proof = log.inclusion_proof(idx, size=cert.body.size)
assert proof.verify(log.tree.leaf(idx), cert.body.root)   # offline audit
```

## Design notes

- **Domain separation.** Every structured hash is tagged and length-prefixed
  (`palisade.hashing`) so a digest for one role can never be reinterpreted as a
  digest for another — closing cross-structure collision paths the security
  argument assumes away. History-tree hashes deliberately keep RFC 6962's
  `0x00`/`0x01` prefixes so roots are byte-identical to a Certificate
  Transparency log over the same leaves.
- **The stateful-key hazard is a first-class object.** LMS/HSS security is void
  if any one-time index is reused. Rather than hide this, the `HardwareModule`
  makes the counter unwritable from outside (K1), starts restorations on fresh
  index ranges (K2), publishes every index (K3), and fails closed on exhaustion
  (K4); `ReuseMonitor` turns any violation into evidence (Prop. 1).

## Status

Implemented and tested: the history tree, records, checkpoints and chain, the
vote/commit round with vote-granularity accountability and accountable refusal,
client batch signing, accountability proofs, anchoring, a stateful
hash-signature layer with the K-invariants, and a strict wire codec with an
offline audit-bundle verifier and CLI.

Deliberately **not** implemented in this reference build (they are textbook or
out of scope per the paper): the PBFT/Tendermint **view-change / leader-rotation
state machine** (single-round vote → commit is modeled; view changes and
liveness under a faulty proposer are not), network transport, persistent
storage, and production LMS/HSS + SLH-DSA key formats. The signature layer here
is a hash-only analogue used to exercise the invariants end-to-end.

The path from artifact to system — swap the toy signer for `cisco/hash-sigs`
(LMS/HSS) and a real SLH-DSA binding, then retarget the accountability layer
onto an existing sigsum/Trillian log rather than the built-in tree — is set out
in [docs/POSITIONING.md](docs/POSITIONING.md), along with an honest accounting
of what this project concedes to prior art.

## License

Apache-2.0 (code). The working paper is CC BY 4.0.
