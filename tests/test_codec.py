"""Wire-codec round-trip and strictness tests."""

import pytest

from palisade.codec import (
    CodecError,
    decode_certificate,
    decode_inclusion,
    decode_signature,
    encode_certificate,
    encode_inclusion,
    encode_signature,
)
from palisade.hashing import sha256
from palisade.log import PalisadeLog
from palisade.records import Artifact

from tests.conftest import make_validators


def _log_with_checkpoint():
    validators, registry = make_validators(4)
    log = PalisadeLog(n=4, f=1, registry=registry)
    for i in range(6):
        log.append_record(Artifact(content_hash=sha256(f"c{i}".encode()), artifact_type="doc"))
    cert = log.checkpoint(validators)
    return log, cert, registry


def test_signature_round_trip():
    log, cert, _ = _log_with_checkpoint()
    sig = cert.signatures[0].signature
    assert decode_signature(encode_signature(sig)) == sig


def test_certificate_round_trip_preserves_hash_and_verification():
    log, cert, registry = _log_with_checkpoint()
    blob = encode_certificate(cert)
    restored = decode_certificate(blob)
    # Structural equality of the body and identical certificate hash.
    assert restored.body == cert.body
    assert restored.cert_hash() == cert.cert_hash()
    assert restored.verify(registry, quorum=3)


def test_certificate_encoding_is_deterministic():
    log, cert, _ = _log_with_checkpoint()
    assert encode_certificate(cert) == encode_certificate(cert)


def test_inclusion_round_trip_and_verifies():
    log, cert, _ = _log_with_checkpoint()
    proof = log.inclusion_proof(2, size=cert.body.size)
    restored = decode_inclusion(encode_inclusion(proof))
    assert restored == proof
    assert restored.verify(log.tree.leaf(2), cert.body.root)


def test_decode_rejects_trailing_bytes():
    log, cert, _ = _log_with_checkpoint()
    blob = encode_certificate(cert)
    with pytest.raises(CodecError):
        decode_certificate(blob + b"\x00")


def test_decode_rejects_truncation():
    log, cert, _ = _log_with_checkpoint()
    blob = encode_certificate(cert)
    with pytest.raises(CodecError):
        decode_certificate(blob[:-4])
