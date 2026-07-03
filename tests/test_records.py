"""Record schema tests (section 4)."""

from palisade.hashing import sha256
from palisade.records import (
    Artifact,
    Attestation,
    CustodyEvent,
    schema_valid,
    validate,
)
import pytest
from palisade.records import SchemaError


H = sha256(b"content")


def test_valid_artifact():
    a = Artifact(content_hash=H, artifact_type="firmware", meta={"vendor": "acme"})
    assert schema_valid(a)
    validate(a)


def test_artifact_requires_digest():
    a = Artifact(content_hash=b"short", artifact_type="firmware")
    assert not schema_valid(a)
    with pytest.raises(SchemaError):
        validate(a)


def test_artifact_requires_type():
    a = Artifact(content_hash=H, artifact_type="")
    assert not schema_valid(a)


def test_valid_custody_event():
    e = CustodyEvent(
        artifact_hash=H, holder="depot-7", action="received", location="KAF", timestamp=100
    )
    assert schema_valid(e)


def test_custody_event_rejects_unknown_action():
    e = CustodyEvent(artifact_hash=H, holder="x", action="teleported", timestamp=1)
    assert not schema_valid(e)


def test_custody_event_rejects_negative_time():
    e = CustodyEvent(artifact_hash=H, holder="x", action="received", timestamp=-1)
    assert not schema_valid(e)


def test_valid_attestation():
    at = Attestation(target_hash=H, claim="SLSA-3", attester="auditor")
    assert schema_valid(at)


def test_attestation_requires_claim():
    at = Attestation(target_hash=H, claim="", attester="auditor")
    assert not schema_valid(at)


def test_unknown_type_invalid():
    assert not schema_valid(object())


def test_canonical_is_deterministic_and_distinct():
    a = Artifact(content_hash=H, artifact_type="firmware", meta={"a": "1", "b": "2"})
    a2 = Artifact(content_hash=H, artifact_type="firmware", meta={"b": "2", "a": "1"})
    assert a.canonical() == a2.canonical()  # meta order-independent
    b = Artifact(content_hash=H, artifact_type="document", meta={"a": "1", "b": "2"})
    assert a.canonical() != b.canonical()
