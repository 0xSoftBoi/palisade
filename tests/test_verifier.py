"""Offline audit-bundle verification tests (Definition 2, portable spine)."""

import pytest

from palisade.codec import CodecError
from palisade.hashing import sha256
from palisade.log import PalisadeLog
from palisade.records import Artifact
from palisade.verifier import AuditBundle, OfflineVerifier, build_audit_bundle

from tests.conftest import make_validators


def _multi_epoch_log():
    validators, registry = make_validators(4)
    log = PalisadeLog(n=4, f=1, registry=registry)
    epochs = []
    for e in range(3):
        for i in range(4):
            log.append_record(Artifact(content_hash=sha256(f"e{e}-{i}".encode()),
                                       artifact_type="doc"))
        epochs.append(log.checkpoint(validators))
    return log, registry


def test_bundle_round_trips_through_bytes():
    log, registry = _multi_epoch_log()
    bundle = build_audit_bundle(log, inclusions=[(0, 1), (2, 9)],
                                consistencies=[(0, 1), (0, 2)])
    restored = AuditBundle.from_bytes(bundle.to_bytes())
    assert restored.to_bytes() == bundle.to_bytes()


def test_offline_verifier_accepts_valid_bundle():
    log, registry = _multi_epoch_log()
    bundle = build_audit_bundle(log, inclusions=[(0, 1), (1, 5)],
                                consistencies=[(0, 1), (1, 2)])
    blob = bundle.to_bytes()

    # A third party reconstructs from bytes and verifies against ITS OWN keys.
    received = AuditBundle.from_bytes(blob)
    verdict = OfflineVerifier().verify_bundle(received, trusted_registry=registry)
    assert verdict.ok, verdict.summary()
    assert verdict.registry_source == "trusted"
    assert verdict.chain_ok
    assert all(r.ok for r in verdict.results)


def test_verifier_rejects_wrong_trusted_registry():
    log, registry = _multi_epoch_log()
    bundle = build_audit_bundle(log, inclusions=[(0, 1)])
    other_validators, other_registry = make_validators(4)  # unrelated keys
    verdict = OfflineVerifier().verify_bundle(bundle, trusted_registry=other_registry)
    assert not verdict.ok
    assert not verdict.chain_ok  # signatures don't verify under foreign keys


def test_verifier_flags_tampered_inclusion_record():
    log, registry = _multi_epoch_log()
    bundle = build_audit_bundle(log, inclusions=[(0, 1)])
    from palisade.verifier import InclusionClaim
    bad = InclusionClaim(record=b"forged-record", epoch=0, proof=bundle.inclusions[0].proof)
    bundle.inclusions = [bad]
    verdict = OfflineVerifier().verify_bundle(bundle, trusted_registry=registry)
    assert not verdict.ok
    assert any(r.kind == "inclusion" and not r.ok for r in verdict.results)


def test_verifier_flags_forged_consistency():
    log, registry = _multi_epoch_log()
    # Claim epoch 2 is a prefix of epoch 0 (backwards) -> proof won't verify.
    bundle = build_audit_bundle(log, consistencies=[(0, 2)])
    cc = bundle.consistencies[0]
    from palisade.verifier import ConsistencyClaim
    swapped = ConsistencyClaim(first_epoch=2, second_epoch=0, proof=cc.proof)
    bundle.consistencies = [swapped]
    verdict = OfflineVerifier().verify_bundle(bundle, trusted_registry=registry)
    assert not verdict.ok


def test_bundle_from_bytes_rejects_bad_magic():
    with pytest.raises(CodecError):
        AuditBundle.from_bytes(b"XXXX\x01garbage")


def test_embedded_registry_verification():
    # Without a trusted registry the verifier uses the embedded one (trust on
    # first use); this still checks internal consistency of the bundle.
    log, registry = _multi_epoch_log()
    bundle = build_audit_bundle(log, inclusions=[(2, 10)], consistencies=[(0, 2)])
    verdict = OfflineVerifier().verify_bundle(AuditBundle.from_bytes(bundle.to_bytes()))
    assert verdict.ok
    assert verdict.registry_source == "embedded"
