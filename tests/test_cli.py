"""CLI smoke tests: produce, inspect, and verify an audit bundle."""

import os

from palisade.cli import main


def test_demo_bundle_and_verify_roundtrip(tmp_path, capsys):
    path = tmp_path / "bundle.plsd"
    assert main(["demo-bundle", str(path)]) == 0
    assert path.exists() and path.stat().st_size > 0

    assert main(["inspect", str(path)]) == 0
    assert main(["verify", str(path)]) == 0
    out = capsys.readouterr().out
    assert "ACCEPT" in out


def test_verify_detects_tampered_bundle(tmp_path, capsys):
    path = tmp_path / "bundle.plsd"
    main(["demo-bundle", str(path)])
    data = bytearray(path.read_bytes())
    # Flip a byte deep in the payload (past the header) to corrupt a signature
    # or root; verification must reject.
    data[len(data) // 2] ^= 0xFF
    path.write_bytes(bytes(data))

    rc = main(["verify", str(path)])
    # Either the decode fails (rc 2) or verification rejects (rc 1); never 0.
    assert rc != 0
