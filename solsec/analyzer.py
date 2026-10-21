"""Orchestration: run every rule over one or more Solidity files."""

from __future__ import annotations

import os
from pathlib import Path

from .rules import RULES, SEVERITY_ORDER, Context, Finding

TOOL_NAME = "solsec-lint"
TOOL_VERSION = "1.0.0"


def audit_source(src: str, path: str = "<memory>") -> list[Finding]:
    ctx = Context.build(path, src)
    findings: list[Finding] = []
    for _rule_id, fn in RULES:
        try:
            findings.extend(fn(ctx))
        except Exception as exc:  # a broken rule must never hide other findings
            findings.append(Finding(
                rule="SOL-000", title="Rule crashed", severity="info", line=1,
                message=f"{fn.__name__} raised {type(exc).__name__}: {exc}",
                fix="Report this as a tool bug.", confidence="low",
                function="", contract="",
            ))
    # dedupe on (rule, line, function)
    seen = set()
    unique = []
    for f in findings:
        key = (f.rule, f.line, f.function, f.title)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    unique.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.line, f.rule))
    return unique


def audit_file(path: str) -> list[Finding]:
    return audit_source(Path(path).read_text(encoding="utf-8", errors="replace"), str(path))


def audit_paths(paths: list[str], recursive: bool = True) -> dict:
    files: list[str] = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            pattern = "**/*.sol" if recursive else "*.sol"
            files.extend(sorted(str(x) for x in path.glob(pattern)))
        elif path.is_file():
            files.append(str(path))
        else:
            raise FileNotFoundError(p)

    results = []
    counts = {k: 0 for k in SEVERITY_ORDER}
    for fp in files:
        findings = audit_file(fp)
        for f in findings:
            counts[f.severity] += 1
        results.append({
            "file": os.path.relpath(fp),
            "findings": [f.to_dict() for f in findings],
            "counts": _counts(findings),
        })
    total = len([f for r in results for f in r["findings"]])
    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "files": results,
        "summary": {
            "files_scanned": len(results),
            "findings": total,
            "by_severity": counts,
            "passed": total == 0,
        },
    }


def _counts(findings: list[Finding]) -> dict:
    c = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        c[f.severity] += 1
    return c
