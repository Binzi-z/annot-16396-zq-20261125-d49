"""Command line interface.

Subcommands
------------
(no command) / ``all`` : run the full verification harness and write reports.
``scale``              : run only the 60k-edge consistency check.
``verify <file>``      : independently verify a certificate or sealed envelope.
``selftest``           : run the unittest suite.
"""

from __future__ import annotations

import argparse
import json
import sys
import unittest
from pathlib import Path

from .canon import canonical_dumps
from .certificate import verify_certificate
from .scale60k import run_scale_check
from .seal import verify_envelope
from .verify_all import ROOT, run_all


def _print(obj) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))


def cmd_verify(path: str) -> int:
    p = Path(path)
    if not p.exists():
        print(f"file not found: {p}", file=sys.stderr)
        return 2
    try:
        obj = json.loads(p.read_bytes().decode("utf-8"))
        if not isinstance(obj, dict):
            print("verification result: VALID=False (top-level JSON is not an object)")
            return 1
        if "envelope_hash" in obj or str(obj.get("schema", "")).startswith("perm-proof/seal"):
            result = verify_envelope(obj)
        else:
            result = verify_certificate(obj)
        print(canonical_dumps(result))
        return 0 if result.get("valid") else 1
    except Exception as exc:  # noqa: BLE001 - CLI must report, not crash raw
        print(f"verification failed to parse/run: {exc!r}", file=sys.stderr)
        return 2


def cmd_selftest() -> int:
    tests_dir = ROOT / "tests"
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(tests_dir), pattern="test_*.py",
                            top_level_dir=str(ROOT))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="permission_proof",
        description="Offline permission proof / minimum emergency exceptions (stdlib only).",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("all", help="run full end-to-end verification harness")
    sub.add_parser("scale", help="run the 60,000-role-edge consistency check")

    v = sub.add_parser("verify", help="verify a certificate / sealed envelope JSON")
    v.add_argument("path")

    sub.add_parser("selftest", help="run unittest suite")
    return parser


def main(argv: list[str] | None = None) -> int:
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command in (None, "all"):
        report = run_all()
        print(
            f"overall_ok={report['ok']} "
            f"passed={report['summary']['passed']}/{report['summary']['total_checks']}"
        )
        return 0 if report["ok"] else 1
    if args.command == "scale":
        rep = run_scale_check()
        _print(rep)
        return 0 if rep["ok"] else 1
    if args.command == "verify":
        return cmd_verify(args.path)
    if args.command == "selftest":
        return cmd_selftest()
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
