"""Command-line entry point.

    aep-verify vectors [DIR]                      run the published conformance vectors
    aep-verify chain FILE --key KEY [options]     verify an artifact sequence
    aep-verify bundle FILE --key KEY              re-verify a DisputeBundle and apply the §6.2 gate
    aep-verify canon FILE                         print canonical bytes and SHA-256 of a JSON file

Exit status: 0 when everything passed / is valid, 1 when a check failed, 2 on bad input.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .bundle import BundleFormatError, verify_bundle
from .canonical import CanonicalizationError, canonicalize, parse_json, sha256_of
from .chain import ChainFormatError, verify_chain
from .keys import KeyFormatError, load_public_key
from .vectors import format_report, run_vectors

DEFAULT_VECTORS = Path(__file__).resolve().parent.parent / "vectors" / "v1.0.3-rc.2"


def _read_json(path: str):
    try:
        return parse_json(Path(path).read_bytes())
    except OSError as exc:
        raise SystemExit(f"cannot read {path}: {exc}") from exc
    except CanonicalizationError as exc:
        raise SystemExit(f"{path}: {exc}") from exc


def _key(source: str):
    try:
        return load_public_key(source)
    except (KeyFormatError, OSError, ValueError) as exc:
        raise SystemExit(f"public key: {exc}") from exc


def cmd_vectors(args: argparse.Namespace) -> int:
    directory = Path(args.dir) if args.dir else DEFAULT_VECTORS
    if not directory.is_dir():
        raise SystemExit(f"not a directory: {directory}")
    cases = run_vectors(directory)
    if args.json:
        print(json.dumps([c.__dict__ for c in cases], indent=2))
    else:
        print(format_report(cases))
    return 1 if any(c.status == "FAIL" for c in cases) else 0


def cmd_chain(args: argparse.Namespace) -> int:
    data = _read_json(args.file)
    records = data.get("artifacts") if isinstance(data, dict) else data
    if not isinstance(records, list):
        raise SystemExit(
            "chain file must be a JSON array of artifacts or an object with 'artifacts'"
        )
    transaction_type = args.transaction_type
    sealed = args.sealed_hash
    if isinstance(data, dict):
        transaction_type = transaction_type or data.get("transaction_type")
        sealed = sealed or data.get("sealed_bundle_hash")
    try:
        result = verify_chain(
            records,
            _key(args.key),
            transaction_type=transaction_type,
            sealed_bundle_hash=sealed,
            spec_version=args.spec_version,
            expected_merchant_id=args.merchant_id,
        )
    except ChainFormatError as exc:
        raise SystemExit(f"malformed chain: {exc}") from exc
    _emit(result.to_dict(), args.json, result.errors, result.warnings)
    return 0 if result.valid else 1


def cmd_bundle(args: argparse.Namespace) -> int:
    bundle = _read_json(args.file)
    try:
        outcome = verify_bundle(bundle, _key(args.key), expected_merchant_id=args.merchant_id)
    except BundleFormatError as exc:
        raise SystemExit(f"malformed bundle: {exc}") from exc
    payload = outcome.to_dict()
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        v = outcome.verification
        print(f"exportable: {outcome.exportable}")
        for reason in outcome.gate_reasons:
            print(f"  gate: {reason}")
        print(
            f"valid={v.valid} hash_chain_intact={v.hash_chain_intact} "
            f"signatures_valid={v.signatures_valid} chain_complete={v.chain_complete} "
            f"artifacts_verified={v.artifacts_verified}"
        )
        for line in outcome.embedded_disagreements:
            print(f"  disagreement: {line}")
        for line in outcome.errors + v.errors:
            print(f"  error: {line}")
        for line in outcome.warnings + v.warnings:
            print(f"  warning: {line}")
    return 0 if outcome.exportable else 1


def cmd_canon(args: argparse.Namespace) -> int:
    value = _read_json(args.file)
    try:
        canonical = canonicalize(value)
    except CanonicalizationError as exc:
        raise SystemExit(f"{args.file}: {exc}") from exc
    sys.stdout.buffer.write(canonical)
    sys.stdout.buffer.write(b"\n")
    print(sha256_of(value))
    print(f"{len(canonical)} bytes")
    return 0


def _emit(payload: dict, as_json: bool, errors: list[str], warnings: list[str]) -> None:
    if as_json:
        print(json.dumps(payload, indent=2))
        return
    keys = (
        "valid",
        "hash_chain_intact",
        "signatures_valid",
        "chain_complete",
        "artifacts_verified",
        "spec_version",
        "evidence_tier",
    )
    print(" ".join(f"{k}={payload[k]}" for k in keys))
    ext = payload["x_aep_verify"]
    print(
        f"total_artifacts={ext['total_artifacts']} expected={ext['expected_artifact_count']} "
        f"protocol={ext['protocol']} seal={ext['sealed_bundle_hash']} "
        f"seal_valid={ext['seal_valid']}"
    )
    for line in errors:
        print(f"  error: {line}")
    for line in warnings:
        print(f"  warning: {line}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aep-verify", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("vectors", help="run the published §6.3 conformance vectors")
    p.add_argument("dir", nargs="?", help=f"vector directory (default: {DEFAULT_VECTORS})")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_vectors)

    p = sub.add_parser("chain", help="verify an ordered artifact sequence")
    p.add_argument("file")
    p.add_argument("--key", required=True, help="base64 Ed25519 public key, or a keys.json path")
    p.add_argument("--transaction-type")
    p.add_argument("--sealed-hash")
    p.add_argument("--spec-version")
    p.add_argument("--merchant-id", help="reject chains for any other merchant_id (§2.7)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_chain)

    p = sub.add_parser("bundle", help="re-verify a DisputeBundle and apply the §6.2 export gate")
    p.add_argument("file")
    p.add_argument("--key", required=True)
    p.add_argument("--merchant-id")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_bundle)

    p = sub.add_parser("canon", help="print the §4.1 canonical bytes and SHA-256 of a JSON file")
    p.add_argument("file")
    p.set_defaults(func=cmd_canon)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except SystemExit as exc:
        if isinstance(exc.code, str):
            print(exc.code, file=sys.stderr)
            return 2
        raise


if __name__ == "__main__":
    sys.exit(main())
