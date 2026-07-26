# Positioning: what PALISADE actually contributes

*Landscape review, July 2026. This document exists to keep the project honest
about what is novel here and what is not. It concedes the crowded parts of the
design space and defends only what survives scrutiny.*

## 1. The problem is real

The regulatory drivers are not invented:

- **CNSA 2.0** requires quantum-resistant algorithms in new national-security-system
  acquisitions from **January 1, 2027**, and already places software/firmware
  signing in an exclusive-use window where **LMS/XMSS are the listed choices**.
- **NIST IR 8547** deprecates 112-bit classical algorithms (ECDSA P-256, and in
  practice the secp256k1/Ed25519 schemes under every production chain) after
  2030, disallowed after 2035.
- The **EU PQC roadmap** puts high-risk systems on PQC by end-2030.

And the specific concern — that *long-lived evidence* is a harder case than
payments, because a retroactively forgeable signature is retroactively
non-evidence — is being staked out independently. See *Post-Quantum-Resilient
Audit Evidence for Long-Lived Regulated Systems* (arXiv:2512.00110, Dec 2025),
which targets the same ground: decades-long audit evidence over Merkle
structures and transparency logs.

Meanwhile the transparency-log ecosystem is actively migrating: Sigstore has
[three PQC approaches in flight for Rekor](https://blog.sigstore.dev/post-quantum-2025/),
and Let's Encrypt is rolling out Merkle Tree Certificates.

**Verdict: the problem is legitimate and time-boxed.** This is the strongest
part of the thesis.

## 2. What is *not* novel — concede it plainly

Every building block already ships, and several are more mature than anything
in this repository:

| Component | Prior art | Status |
|---|---|---|
| LMS/HSS signatures | [`cisco/hash-sigs`](https://github.com/cisco/hash-sigs) | Production C, RFC 8554 |
| History tree / inclusion + consistency proofs | RFC 6962, [Trillian](https://transparency.dev/) | Deployed at internet scale |
| Minimal log + **cosigned checkpoints** | [**sigsum**](https://transparency.dev/summit2024/sigsum.html) | Deployed; witness quorum defeats split-view |
| Hash-only Merkle aggregation + public anchoring | Guardtime KSI | Deployed at national scale |
| Public XMSS-signed chain | [QRL](https://www.theqrl.org/) | Mainnet since 2018 |
| Attestation formats | in-toto, SLSA, SBOM/EO 14028 | Standardized |

**sigsum is the uncomfortable one.** Its witness-cosigning model — a quorum of
independent witnesses cosigning each checkpoint so a client requiring *k*
cosignatures cannot be split-viewed — is structurally very close to PALISADE's
validator-cosigned checkpoints. Anyone evaluating this project will find sigsum,
and the project must have an answer for it.

There is also a **market-timing caveat**: the DFARS/CMMC pull described in the
paper's compliance mapping is a *forecast*, not a current line item. CMMC and
the DFARS acquisition rule reference SP 800-171 Rev 2, which specifies
**classical** cryptography. PQC requirements flow to contractors only when
SP 800-171 is updated, and no firm timeline exists.

## 3. What survives — defend only this

Two contributions withstand the comparison:

### 3.1 Transferable culpability, not just equivocation resistance

sigsum's witness quorum makes split-view *hard*. It does not produce an
artifact that **assigns blame to a named party**. PALISADE's Theorem 1 yields a
proof that:

- implicates **≥ f+1 specific, registered validators**,
- is verifiable by **any third party** from the two certificates and the
  registry alone,
- **never implicates an honest validator**, and
- works at **vote granularity**, not merely per epoch.

For the target buyer — a program office that must *attribute* a failure to a
contractor, not merely detect that one occurred — attribution is the product.
Detection without attribution does not support a contractual remedy.

### 3.2 Stateful-key hazard engineered inside a BFT protocol

CNSA 2.0 lists LMS/XMSS *today*, but stateful schemes are the recognized field
hazard: reuse one OTS index and security is void, which is why SP 800-208
confines them to controlled environments. Running stateful keys inside a
replicated protocol — where restoration, view changes, and crash recovery all
threaten index reuse — is the part nobody has packaged.

PALISADE's K1–K4 plus Proposition 1 make reuse **structurally impossible in the
happy path and O(1)-detectable-with-proof otherwise**: hardware sign-and-increment
(K1), restoration onto never-activated subtrees (K2), on-log index disclosure
(K3), fail-closed exhaustion (K4).

**This is the most defensible novelty in the project** — it is the intersection
nobody occupies, and it is the piece a FIPS 140-3 / SP 800-208 accreditation
package would actually need written down.

## 4. The assumption-minimality bet, stated as a bet

PALISADE refuses lattices and reduces the entire validity path to SHA-2. The
mainstream is going the other way: every Sigstore PQC approach uses ML-DSA;
Let's Encrypt's MTC uses hash-based batching for *size*, not to shrink the
assumption set.

This is a deliberate minority position, not an oversight. It is right for
buyers who ask "what fails if a hardness estimate moves?" and wrong for buyers
who want general-purpose performance. The project should **say so**, rather than
implying hash-only is the obvious default.

## 5. Consequences for this repository

The base layer should not be reinvented. Two facts make that concrete:

1. **The log layer here is already ecosystem-compatible.** `tests/test_rfc6962_vectors.py`
   pins PALISADE's roots, inclusion paths, and consistency paths to the
   published RFC 6962 reference vectors. A PALISADE history tree is
   byte-identical to a CT-class log over the same leaves.
2. Therefore the accountability layer (§3.1) and the stateful-key layer (§3.2)
   can, in principle, sit **on top of** a Trillian- or sigsum-class log rather
   than replacing it.

The honest framing is therefore **not** "a new ledger." It is:

> The accountability and stateful-key-safety layer that sigsum-class
> transparency logs lack, with a CNSA 2.0 / SP 800-208 / FIPS 205 compliance
> mapping.

### Current status of the code

This repository is a **reference implementation**, not a deployable system. In
particular the signature layer is a hash-only *analogue* (Lamport OTS under a
Merkle many-time signer) built to exercise K1–K4 end to end. It is **not**
LMS/HSS, not FIPS-validated, and not interoperable with `cisco/hash-sigs`.
There is no networking, no persistence, no view-change, and no HSM.

To move from artifact to system, in priority order:

1. Replace the toy signer with **`cisco/hash-sigs` (LMS/HSS)** and a real
   **SLH-DSA** (FIPS 205) binding for clients.
2. Retarget the checkpoint/accountability layer onto an existing log
   (sigsum or Trillian) instead of the built-in tree.
3. Lead every external description with §3.1 and §3.2 — not with "hash-based
   append-only log," which reads as a solved problem.

## 6. What the paper gets right beyond the crypto

The working paper names its closest relatives, corrects its own v0.2 error in
public, and publishes abandonment criteria. That intellectual honesty is rarer
than the cryptography and is worth preserving in whatever this becomes.

---

## Sources

- [Sigstore & Post-Quantum Cryptography (2025)](https://blog.sigstore.dev/post-quantum-2025/)
- [Post-Quantum-Resilient Audit Evidence for Long-Lived Regulated Systems (arXiv:2512.00110)](https://arxiv.org/pdf/2512.00110)
- [Sigsum — minimal transparency log with witness cosigning](https://transparency.dev/summit2024/sigsum.html)
- [Trillian / transparency.dev — logs as a verifiable transport layer](https://transparency.dev/articles/logs-a-verifiable-transport-layer/)
- [cisco/hash-sigs — LMS/HSS reference implementation](https://github.com/cisco/hash-sigs)
- [QRL — post-quantum blockchain](https://www.theqrl.org/the-definitive-guide-to-post-quantum-blockchain-security/)
- [CNSA 2.0 compliance guide (2026)](https://www.qcecuring.com/blog/cnsa-2-0-compliance-guide-2026)
- [Let's Encrypt Merkle Tree Certificates rollout](https://www.techtimes.com/articles/317788/20260604/post-quantum-tls-certificates-lets-encrypt-plans-merkle-tree-rollout-that-shrinks-handshakes.htm)
