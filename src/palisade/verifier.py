"""Offline verification of a portable audit bundle.

This is the verifier of Definition 2 made standalone: "a verifier holding
genesis keys checks the chain, then audits any record via pi_incl and any epoch
pair via pi_cons, offline." An :class:`AuditBundle` packages a checkpoint chain,
the validator registry, record-inclusion claims, and epoch-consistency claims
into a single byte string. :class:`OfflineVerifier` consumes those bytes and a
*trusted* registry (the verifier's own genesis keys) and returns a structured
verdict -- with no access to the log operator, the network, or any live state.

That the verifier can supply its own registry rather than trusting the one in
the bundle is the whole point: culpability and history verification route
through keys the verifier already holds, not through whoever produced the bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .checkpoint import CheckpointCertificate, ValidatorRegistry, verify_chain
from .codec import (
    MAGIC,
    VERSION,
    CodecError,
    _Reader,
    _Writer,
    _read_certificate,
    _read_consistency,
    _read_inclusion,
    _read_registry,
    _write_certificate,
    _write_consistency,
    _write_inclusion,
    _write_registry,
)
from .merkle import ConsistencyProof, InclusionProof


@dataclass(frozen=True)
class InclusionClaim:
    """A claim that ``record`` sits at ``proof.leaf_index`` in the checkpoint
    committed at ``epoch``."""

    record: bytes
    epoch: int
    proof: InclusionProof


@dataclass(frozen=True)
class ConsistencyClaim:
    """A claim that the checkpoint at ``first_epoch`` is a prefix of the one at
    ``second_epoch``."""

    first_epoch: int
    second_epoch: int
    proof: ConsistencyProof


@dataclass
class AuditBundle:
    """A self-contained, portable audit package."""

    registry: ValidatorRegistry
    f: int
    chain: List[CheckpointCertificate] = field(default_factory=list)
    inclusions: List[InclusionClaim] = field(default_factory=list)
    consistencies: List[ConsistencyClaim] = field(default_factory=list)

    @property
    def quorum(self) -> int:
        return 2 * self.f + 1

    def to_bytes(self) -> bytes:
        w = _Writer()
        w._buf += MAGIC
        w.u8(VERSION)
        w.u32(self.f)
        _write_registry(w, self.registry)
        w.u32(len(self.chain))
        for cert in self.chain:
            _write_certificate(w, cert)
        w.u32(len(self.inclusions))
        for inc in self.inclusions:
            w.blob(inc.record).u64(inc.epoch)
            _write_inclusion(w, inc.proof)
        w.u32(len(self.consistencies))
        for cc in self.consistencies:
            w.u64(cc.first_epoch).u64(cc.second_epoch)
            _write_consistency(w, cc.proof)
        return w.getvalue()

    @classmethod
    def from_bytes(cls, data: bytes) -> "AuditBundle":
        r = _Reader(data)
        if r._take(len(MAGIC)) != MAGIC:
            raise CodecError("bad magic; not a PALISADE audit bundle")
        version = r.u8()
        if version != VERSION:
            raise CodecError(f"unsupported bundle version {version}")
        f = r.u32()
        registry = _read_registry(r)
        chain = [_read_certificate(r) for _ in range(r.u32())]
        inclusions = []
        for _ in range(r.u32()):
            record = r.blob()
            epoch = r.u64()
            proof = _read_inclusion(r)
            inclusions.append(InclusionClaim(record=record, epoch=epoch, proof=proof))
        consistencies = []
        for _ in range(r.u32()):
            fe = r.u64()
            se = r.u64()
            proof = _read_consistency(r)
            consistencies.append(ConsistencyClaim(first_epoch=fe, second_epoch=se, proof=proof))
        r.finish()
        return cls(registry=registry, f=f, chain=chain,
                   inclusions=inclusions, consistencies=consistencies)


def build_audit_bundle(
    log,
    inclusions=(),
    consistencies=(),
) -> AuditBundle:
    """Assemble a portable :class:`AuditBundle` from a live :class:`PalisadeLog`.

    ``inclusions`` is an iterable of ``(epoch, leaf_index)`` pairs and
    ``consistencies`` an iterable of ``(first_epoch, second_epoch)`` pairs. Each
    proof is generated against the *checkpoint* size for that epoch, so it
    verifies against the checkpoint root a third party already trusts.
    """
    by_epoch = {c.epoch: c for c in log.chain}
    inc_claims: List[InclusionClaim] = []
    for epoch, index in inclusions:
        cert = by_epoch[epoch]
        proof = log.tree.inclusion_proof(index, size=cert.body.size)
        inc_claims.append(InclusionClaim(record=log.tree.leaf(index), epoch=epoch, proof=proof))
    cons_claims: List[ConsistencyClaim] = []
    for first_epoch, second_epoch in consistencies:
        first = by_epoch[first_epoch]
        second = by_epoch[second_epoch]
        proof = log.tree.consistency_proof(first.body.size, second.body.size)
        cons_claims.append(
            ConsistencyClaim(first_epoch=first_epoch, second_epoch=second_epoch, proof=proof)
        )
    return AuditBundle(
        registry=log.registry, f=log.f, chain=list(log.chain),
        inclusions=inc_claims, consistencies=cons_claims,
    )


@dataclass(frozen=True)
class ClaimResult:
    kind: str
    ok: bool
    reason: str
    detail: str = ""


@dataclass
class BundleVerdict:
    chain_ok: bool
    registry_source: str  # "trusted" or "embedded"
    results: List[ClaimResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.chain_ok and all(r.ok for r in self.results)

    def summary(self) -> str:
        passed = sum(1 for r in self.results if r.ok)
        return (f"chain={'ok' if self.chain_ok else 'FAIL'} "
                f"registry={self.registry_source} "
                f"claims={passed}/{len(self.results)} "
                f"=> {'ACCEPT' if self.ok else 'REJECT'}")


class OfflineVerifier:
    """Verifies an :class:`AuditBundle` against a trusted registry, offline."""

    def verify_bundle(
        self,
        bundle: AuditBundle,
        trusted_registry: Optional[ValidatorRegistry] = None,
    ) -> BundleVerdict:
        registry = trusted_registry if trusted_registry is not None else bundle.registry
        source = "trusted" if trusted_registry is not None else "embedded"
        quorum = bundle.quorum

        chain_ok = verify_chain(bundle.chain, registry, quorum)
        by_epoch: Dict[int, CheckpointCertificate] = {c.epoch: c for c in bundle.chain}

        results: List[ClaimResult] = []

        for inc in bundle.inclusions:
            cert = by_epoch.get(inc.epoch)
            if cert is None:
                results.append(ClaimResult("inclusion", False, "no checkpoint for epoch",
                                           f"epoch={inc.epoch}"))
                continue
            if inc.proof.tree_size != cert.body.size:
                results.append(ClaimResult("inclusion", False, "proof size != checkpoint size",
                                           f"epoch={inc.epoch} idx={inc.proof.leaf_index}"))
                continue
            ok = inc.proof.verify(inc.record, cert.body.root)
            results.append(ClaimResult("inclusion", ok,
                                       "record proven in checkpoint" if ok else "inclusion proof failed",
                                       f"epoch={inc.epoch} idx={inc.proof.leaf_index}"))

        for cc in bundle.consistencies:
            first = by_epoch.get(cc.first_epoch)
            second = by_epoch.get(cc.second_epoch)
            if first is None or second is None:
                results.append(ClaimResult("consistency", False, "missing checkpoint(s)",
                                           f"{cc.first_epoch}->{cc.second_epoch}"))
                continue
            if cc.proof.first_size != first.body.size or cc.proof.second_size != second.body.size:
                results.append(ClaimResult("consistency", False, "proof sizes != checkpoint sizes",
                                           f"{cc.first_epoch}->{cc.second_epoch}"))
                continue
            ok = cc.proof.verify(first.body.root, second.body.root)
            results.append(ClaimResult("consistency", ok,
                                       "prefix relation proven" if ok else "consistency proof failed",
                                       f"{cc.first_epoch}->{cc.second_epoch}"))

        return BundleVerdict(chain_ok=chain_ok, registry_source=source, results=results)
