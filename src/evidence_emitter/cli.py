# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Command line: emit a package from a subject JSON file, or verify a package.

    evidence-emit  <subject.json> [--kind KIND] [--context context.json] [-o out.json]
    evidence-verify <package.json>

Both default to the non-production dev signer. A production run supplies key
material to the library API, not the CLI: signing keys are not passed on a
command line.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from .components import EvidenceContext
from .package import EvidencePackage, emit
from .verify import verify


def _load(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def emit_main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(prog="evidence-emit", description="Emit a governance evidence package (dev signer).")
    ap.add_argument("subject", help="path to the subject JSON (an a2a-compliance decision or a privacy-shield ScanReport)")
    ap.add_argument("--kind", default=None, help="override subject-kind detection")
    ap.add_argument("--context", default=None, help="path to a JSON object of EvidenceContext fields")
    ap.add_argument("--components", default=None, help="comma-separated component allowlist")
    ap.add_argument("-o", "--out", default=None, help="write the package here (default: stdout)")
    args = ap.parse_args(argv)

    context = EvidenceContext(**_load(args.context)) if args.context else None
    components = args.components.split(",") if args.components else None
    package = emit(_load(args.subject), kind=args.kind, components=components, context=context)

    text = json.dumps(package.to_dict(), indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        print(text)
    return 0


def verify_main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(prog="evidence-verify", description="Verify a governance evidence package offline (dev signer).")
    ap.add_argument("package", help="path to a package (DSSE envelope) JSON file")
    args = ap.parse_args(argv)

    report = verify(EvidencePackage.from_dict(_load(args.package)))
    print(report.summary())
    for sv in report.sections:
        mark = "ok" if sv.ok else "FAIL"
        print(f"  [{mark}] {sv.component} ({sv.status})")
        for f in sv.findings:
            print(f"      - {f['severity']}: {f['code']}: {f['detail']}")
    for f in report.findings:
        print(f"  - {f['severity']}: {f['code']}: {f['detail']}")
    return 0 if report.ok else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(emit_main())
