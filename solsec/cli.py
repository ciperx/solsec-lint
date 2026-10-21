"""CLI: ``solsec-lint <path...> [--format json|md|both] [-o DIR]``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .analyzer import audit_paths, TOOL_NAME, TOOL_VERSION
from .report import to_json, to_markdown
from .rules import SEVERITY_ORDER


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="solsec-lint",
        description="Static security linter for Solidity (reentrancy, unchecked calls, "
                    "tx.origin, arithmetic, initializers, access control, delegatecall).",
    )
    ap.add_argument("paths", nargs="+", help="Solidity files or directories")
    ap.add_argument("--format", choices=["json", "md", "both"], default="json")
    ap.add_argument("-o", "--out", help="output directory (default: stdout for json, ./solsec-report.md for md)")
    ap.add_argument("--fail-on", default="high",
                    choices=["critical", "high", "medium", "low", "info", "never"],
                    help="exit 1 when a finding at or above this severity exists (default: high)")
    ap.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    args = ap.parse_args(argv)

    try:
        result = audit_paths(args.paths)
    except FileNotFoundError as exc:
        print(f"solsec-lint: path not found: {exc}", file=sys.stderr)
        return 2

    out_dir = Path(args.out) if args.out else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    if args.format in ("json", "both"):
        text = to_json(result)
        if out_dir:
            (out_dir / "solsec-report.json").write_text(text + "\n", encoding="utf-8")
            print(f"wrote {out_dir / 'solsec-report.json'}")
        else:
            print(text)

    if args.format in ("md", "both"):
        text = to_markdown(result)
        if out_dir:
            (out_dir / "solsec-report.md").write_text(text, encoding="utf-8")
            print(f"wrote {out_dir / 'solsec-report.md'}")
        else:
            print(text)

    s = result["summary"]
    print(f"solsec-lint: {s['files_scanned']} file(s), {s['findings']} finding(s) "
          f"[critical {s['by_severity']['critical']}, high {s['by_severity']['high']}, "
          f"medium {s['by_severity']['medium']}]", file=sys.stderr)

    if args.fail_on == "never":
        return 0
    threshold = SEVERITY_ORDER[args.fail_on]
    worst = max((SEVERITY_ORDER[f["severity"]]
                 for fr in result["files"] for f in fr["findings"]), default=-1)
    return 1 if worst >= threshold else 0


if __name__ == "__main__":
    raise SystemExit(main())
