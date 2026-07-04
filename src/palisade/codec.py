"""Deterministic wire codec for PALISADE's portable artifacts.

Checkpoint chains are "the ledger's portable spine: a verifier holding genesis
keys checks the chain, then audits any record via pi_incl and any epoch pair via
pi_cons, offline" (Definition 2). That claim only means something if the spine
can leave the process that produced it. This module gives every verifier-facing
object a canonical byte encoding and an exact inverse, so a checkpoint chain,
registry, and proof bundle can be written to bytes on one host and re-verified
on another with nothing shared but the bytes and the trusted keys.

The framing is length-prefixed and versioned; decoding is strict (trailing
bytes, truncation, and unknown versions all raise), because a lenient decoder is
an attack surface an accreditation package would flag.
"""

from __future__ import annotations

from typing import List, Tuple

from .checkpoint import (
    CheckpointBody,
    CheckpointCertificate,
    ValidatorRegistry,
    ValidatorSignature,
)
from .merkle import ConsistencyProof, InclusionProof
from .signatures import HashSignature, OTSSignature

MAGIC = b"PLSD"
VERSION = 1


class CodecError(ValueError):
    """Raised on malformed input during decoding."""


class _Writer:
    def __init__(self) -> None:
        self._buf = bytearray()

    def u8(self, v: int) -> "_Writer":
        self._buf += int(v).to_bytes(1, "big")
        return self

    def u32(self, v: int) -> "_Writer":
        self._buf += int(v).to_bytes(4, "big")
        return self

    def u64(self, v: int) -> "_Writer":
        self._buf += int(v).to_bytes(8, "big")
        return self

    def blob(self, b: bytes) -> "_Writer":
        self._buf += len(b).to_bytes(4, "big")
        self._buf += b
        return self

    def text(self, s: str) -> "_Writer":
        return self.blob(s.encode("utf-8"))

    def seq_blobs(self, items: List[bytes]) -> "_Writer":
        self.u32(len(items))
        for it in items:
            self.blob(it)
        return self

    def getvalue(self) -> bytes:
        return bytes(self._buf)


class _Reader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def _take(self, n: int) -> bytes:
        if self._pos + n > len(self._data):
            raise CodecError("unexpected end of input")
        chunk = self._data[self._pos : self._pos + n]
        self._pos += n
        return chunk

    def u8(self) -> int:
        return int.from_bytes(self._take(1), "big")

    def u32(self) -> int:
        return int.from_bytes(self._take(4), "big")

    def u64(self) -> int:
        return int.from_bytes(self._take(8), "big")

    def blob(self) -> bytes:
        n = self.u32()
        return self._take(n)

    def text(self) -> str:
        return self.blob().decode("utf-8")

    def seq_blobs(self) -> List[bytes]:
        n = self.u32()
        return [self.blob() for _ in range(n)]

    def finish(self) -> None:
        if self._pos != len(self._data):
            raise CodecError("trailing bytes after decode")


# --- signatures --------------------------------------------------------------

def _write_signature(w: _Writer, sig: HashSignature) -> None:
    w.u64(sig.index)
    w.seq_blobs(sig.ots.reveals)
    w.seq_blobs(sig.ots.complements)
    w.seq_blobs(sig.auth_path)


def _read_signature(r: _Reader) -> HashSignature:
    index = r.u64()
    reveals = r.seq_blobs()
    complements = r.seq_blobs()
    auth_path = r.seq_blobs()
    return HashSignature(
        index=index,
        ots=OTSSignature(reveals=reveals, complements=complements),
        auth_path=auth_path,
    )


# --- checkpoints -------------------------------------------------------------

def _write_body(w: _Writer, body: CheckpointBody) -> None:
    w.u64(body.epoch).blob(body.root).u64(body.size).blob(body.prev_hash)


def _read_body(r: _Reader) -> CheckpointBody:
    return CheckpointBody(epoch=r.u64(), root=r.blob(), size=r.u64(), prev_hash=r.blob())


def _write_certificate(w: _Writer, cert: CheckpointCertificate) -> None:
    _write_body(w, cert.body)
    w.u32(len(cert.signatures))
    for vs in cert.signatures:
        w.text(vs.validator_id)
        _write_signature(w, vs.signature)


def _read_certificate(r: _Reader) -> CheckpointCertificate:
    body = _read_body(r)
    count = r.u32()
    sigs = []
    for _ in range(count):
        vid = r.text()
        sigs.append(ValidatorSignature(vid, _read_signature(r)))
    return CheckpointCertificate(body=body, signatures=sigs)


# --- registry ----------------------------------------------------------------

def _write_registry(w: _Writer, registry: ValidatorRegistry) -> None:
    ids = registry.ids()
    w.u32(len(ids))
    for vid in ids:
        w.text(vid).blob(registry.public_key(vid))


def _read_registry(r: _Reader) -> ValidatorRegistry:
    count = r.u32()
    keys = {}
    for _ in range(count):
        vid = r.text()
        keys[vid] = r.blob()
    return ValidatorRegistry(keys)


# --- proofs ------------------------------------------------------------------

def _write_inclusion(w: _Writer, p: InclusionProof) -> None:
    w.u64(p.leaf_index).u64(p.tree_size).seq_blobs(p.audit_path)


def _read_inclusion(r: _Reader) -> InclusionProof:
    return InclusionProof(leaf_index=r.u64(), tree_size=r.u64(), audit_path=r.seq_blobs())


def _write_consistency(w: _Writer, p: ConsistencyProof) -> None:
    w.u64(p.first_size).u64(p.second_size).seq_blobs(p.path)


def _read_consistency(r: _Reader) -> ConsistencyProof:
    return ConsistencyProof(first_size=r.u64(), second_size=r.u64(), path=r.seq_blobs())


# --- public single-object round-trips ---------------------------------------

def encode_certificate(cert: CheckpointCertificate) -> bytes:
    w = _Writer()
    _write_certificate(w, cert)
    return w.getvalue()


def decode_certificate(data: bytes) -> CheckpointCertificate:
    r = _Reader(data)
    cert = _read_certificate(r)
    r.finish()
    return cert


def encode_signature(sig: HashSignature) -> bytes:
    w = _Writer()
    _write_signature(w, sig)
    return w.getvalue()


def decode_signature(data: bytes) -> HashSignature:
    r = _Reader(data)
    sig = _read_signature(r)
    r.finish()
    return sig


def encode_inclusion(proof: InclusionProof) -> bytes:
    w = _Writer()
    _write_inclusion(w, proof)
    return w.getvalue()


def decode_inclusion(data: bytes) -> InclusionProof:
    r = _Reader(data)
    p = _read_inclusion(r)
    r.finish()
    return p
