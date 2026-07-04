"""Command-line interface for PALISADE audit bundles.

The portable spine (Definition 2) is only useful if it can cross a process
boundary. This CLI is the operational face of that: produce a self-contained
audit bundle on one host, verify it offline on another with nothing but the
bytes (and, optionally, the verifier's own trusted keys).

Usage::

    python -m palisade.cli demo-bundle out.plsd     # produce a sample bundle
    python -m palisade.cli verify out.plsd          # verify offline
    python -m palisade.cli inspect out.plsd         # summarize contents
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from .hashing import sha256
from .log import PalisadeLog, Validator
from .records import Artifact
from .signatures import HardwareModule
from .checkpoint import ValidatorRegistry
from .verifier import AuditBundle, OfflineVerifier, build_audit_bundle


def _build_demo_log(n: int = 4, f: int = 1, epochs: int = 3, per_epoch: int = 4):
    registry = ValidatorRegistry()
    validators: List[Validator] = []
    for i in range(n):
        v = Validator(f"validator-{i}", HardwareModule(os.urandom(32), height=6))
        registry.register(v.id, v.public_key)
        validators.append(v)
    log = PalisadeLog(n=n, f=f, registry=registry)
    for e in range(epochs):
        for j in range(per_epoch):
            log.append_record(Artifact(content_hash=sha256(f"e{e}-{j}".encode()),
                                       artifact_type="doc",
                                       meta={"epoch": str(e), "seq": str(j)}))
        log.checkpoint(validators)
    return log


def cmd_demo_bundle(args: argparse.Namespace) -> int:
    log = _build_demo_log()
    last = log.chain[-1].epoch
    bundle = build_audit_bundle(
        log,
        inclusions=[(0, 1), (last, log.chain[last].body.size - 1)],
        consistencies=[(0, last)],
    )
    data = bundle.to_bytes()
    with open(args.output, "wb") as fh:
        fh.write(data)
    print(f"wrote {len(data)} bytes to {args.output}: "
          f"{len(bundle.chain)} checkpoints, {len(bundle.inclusions)} inclusion "
          f"and {len(bundle.consistencies)} consistency claim(s)")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    with open(args.bundle, "rb") as fh:
        data = fh.read()
    try:
        bundle = AuditBundle.from_bytes(data)
    except ValueError as exc:
        print(f"decode error: {exc}", file=sys.stderr)
        return 2
    verdict = OfflineVerifier().verify_bundle(bundle)
    print(verdict.summary())
    for r in verdict.results:
        mark = "ok " if r.ok else "FAIL"
        print(f"  [{mark}] {r.kind}: {r.reason} ({r.detail})")
    return 0 if verdict.ok else 1


def cmd_inspect(args: argparse.Namespace) -> int:
    with open(args.bundle, "rb") as fh:
        bundle = AuditBundle.from_bytes(fh.read())
    print(f"validators (f={bundle.f}, quorum={bundle.quorum}): {bundle.registry.ids()}")
    print(f"checkpoints: {len(bundle.chain)}")
    for c in bundle.chain:
        print(f"  epoch {c.epoch}: size={c.body.size} "
              f"root={c.body.root.hex()[:16]}... signers={c.signer_ids()}")
    print(f"inclusion claims: {len(bundle.inclusions)}")
    print(f"consistency claims: {len(bundle.consistencies)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="palisade", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p_demo = sub.add_parser("demo-bundle", help="produce a sample audit bundle")
    p_demo.add_argument("output", help="output .plsd path")
    p_demo.set_defaults(func=cmd_demo_bundle)

    p_verify = sub.add_parser("verify", help="verify an audit bundle offline")
    p_verify.add_argument("bundle", help="input .plsd path")
    p_verify.set_defaults(func=cmd_verify)

    p_inspect = sub.add_parser("inspect", help="summarize an audit bundle")
    p_inspect.add_argument("bundle", help="input .plsd path")
    p_inspect.set_defaults(func=cmd_inspect)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
