"""Tests for solsec-lint. Run with: pytest -q"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(ROOT))

from solsec import audit_file, audit_paths, audit_source, to_json, to_markdown  # noqa: E402
from solsec.lexer import find_functions, mask  # noqa: E402

VULN = sorted((FIX / "vulnerable").glob("*.sol"))
SAFE = sorted((FIX / "safe").glob("*.sol"))

# fixture -> rule that must be reported in it
EXPECTED = {
    "Reentrancy.sol": "SOL-001",
    "UncheckedCall.sol": "SOL-002",
    "TxOriginAuth.sol": "SOL-003",
    "IntegerOverflow.sol": "SOL-004",
    "RoundingShare.sol": "SOL-004",
    "UncheckedMath.sol": "SOL-004",
    "UnprotectedInit.sol": "SOL-005",
    "MissingAccessControl.sol": "SOL-006",
    "DelegatecallProxy.sol": "SOL-007",
    "SelfDestruct.sol": "SOL-008",
    "KitchenSink.sol": "SOL-001",
}


def test_fixture_count():
    assert len(VULN) >= 6, f"expected >=6 vulnerable fixtures, found {len(VULN)}"
    assert len(SAFE) >= 5, f"expected >=5 safe fixtures, found {len(SAFE)}"
    assert len(VULN) + len(SAFE) >= 8


@pytest.mark.parametrize("path", VULN, ids=lambda p: p.name)
def test_vulnerable_fixture_triggers_expected_rule(path):
    rules = {f.rule for f in audit_file(str(path))}
    assert EXPECTED[path.name] in rules, f"{path.name} produced {sorted(rules)}"


@pytest.mark.parametrize("path", SAFE, ids=lambda p: p.name)
def test_safe_fixture_is_clean(path):
    findings = audit_file(str(path))
    assert findings == [], [(f.rule, f.line, f.title) for f in findings]


def test_kitchen_sink_hits_every_rule_family():
    rules = {f.rule for f in audit_file(str(FIX / "vulnerable" / "KitchenSink.sol"))}
    assert rules >= {"SOL-001", "SOL-002", "SOL-003", "SOL-004",
                     "SOL-005", "SOL-006", "SOL-007", "SOL-008"}


def test_reentrancy_line_points_at_the_call():
    findings = [f for f in audit_file(str(FIX / "vulnerable" / "Reentrancy.sol"))
                if f.rule == "SOL-001"]
    assert findings, "reentrancy not detected"
    f = findings[0]
    src = (FIX / "vulnerable" / "Reentrancy.sol").read_text().splitlines()
    assert ".call{value:" in src[f.line - 1]
    assert f.severity == "critical"
    assert "checks-effects-interactions" in f.fix.lower()
    assert f.function == "withdraw"


def test_unchecked_call_lines_are_accurate():
    path = FIX / "vulnerable" / "UncheckedCall.sol"
    lines = path.read_text().splitlines()
    findings = [f for f in audit_file(str(path)) if f.rule == "SOL-002"]
    assert len(findings) == 3
    for f in findings:
        assert "call" in lines[f.line - 1] or "send" in lines[f.line - 1]


def test_checked_calls_not_reported():
    assert [f for f in audit_file(str(FIX / "safe" / "CheckedCall.sol"))
            if f.rule == "SOL-002"] == []


def test_tx_origin_reported_per_occurrence():
    findings = [f for f in audit_file(str(FIX / "vulnerable" / "TxOriginAuth.sol"))
                if f.rule == "SOL-003"]
    assert len(findings) == 2
    assert all(f.severity == "high" for f in findings)


def test_tx_origin_in_comment_is_ignored():
    # CleanToken's doc comment mentions tx.origin and delegatecall
    rules = {f.rule for f in audit_file(str(FIX / "safe" / "CleanToken.sol"))}
    assert "SOL-003" not in rules
    assert "SOL-007" not in rules


def test_initializer_guard_not_flagged():
    risky = audit_file(str(FIX / "vulnerable" / "UnprotectedInit.sol"))
    assert any(f.rule == "SOL-005" and f.severity == "critical" for f in risky)
    assert not any(f.rule == "SOL-005"
                   for f in audit_file(str(FIX / "safe" / "ProtectedInit.sol")))


def test_delegatecall_immutable_target_not_flagged():
    assert not any(f.rule == "SOL-007"
                   for f in audit_file(str(FIX / "safe" / "DelegatecallProxy.sol")))
    vuln = [f for f in audit_file(str(FIX / "vulnerable" / "DelegatecallProxy.sol"))
            if f.rule == "SOL-007"]
    assert len(vuln) == 2 and all(f.severity == "critical" for f in vuln)


def test_rounding_div_before_mul():
    findings = [f for f in audit_file(str(FIX / "vulnerable" / "RoundingShare.sol"))
                if f.rule == "SOL-004"]
    assert findings
    assert all("multiply" in f.fix.lower() for f in findings)


def test_overflow_rule_requires_old_pragma():
    rules = {f.rule for f in audit_file(str(FIX / "vulnerable" / "IntegerOverflow.sol"))}
    assert "SOL-004" in rules
    assert "SOL-004" not in {f.rule for f in audit_file(str(FIX / "safe" / "SafeShares.sol"))}


def test_lexer_masks_comments_and_strings_but_keeps_offsets():
    src = 'contract A {\n  // tx.origin here\n  string s = "delegatecall";\n}\n'
    clean = mask(src)
    assert len(clean) == len(src)
    assert "tx.origin" not in clean
    assert "delegatecall" not in clean
    assert clean.count("\n") == src.count("\n")


def test_functions_parsed_with_bodies():
    src = (FIX / "vulnerable" / "Reentrancy.sol").read_text()
    funcs = find_functions(mask(src))
    names = [f.name for f in funcs]
    assert "deposit" in names and "withdraw" in names
    w = next(f for f in funcs if f.name == "withdraw")
    assert w.body.strip().startswith("uint256 amount")
    assert w.end_line > w.start_line


def test_json_schema_is_complete():
    result = audit_paths([str(FIX / "vulnerable")])
    data = json.loads(to_json(result))
    assert data["tool"] == "solsec-lint"
    assert data["summary"]["files_scanned"] == len(VULN)
    assert data["summary"]["findings"] > 0
    allowed = {"critical", "high", "medium", "low", "info"}
    for fr in data["files"]:
        for f in fr["findings"]:
            assert set(f) >= {"rule", "title", "severity", "line", "message", "fix", "function"}
            assert f["severity"] in allowed
            assert isinstance(f["line"], int) and f["line"] >= 1
            assert f["fix"]
            assert len(f["message"]) > 20


def test_findings_sorted_by_severity_then_line():
    from solsec.rules import SEVERITY_ORDER
    findings = audit_file(str(FIX / "vulnerable" / "KitchenSink.sol"))
    ranks = [SEVERITY_ORDER[f.severity] for f in findings]
    assert ranks == sorted(ranks, reverse=True)


def test_no_duplicate_findings():
    findings = audit_file(str(FIX / "vulnerable" / "KitchenSink.sol"))
    keys = [(f.rule, f.line, f.function, f.title) for f in findings]
    assert len(keys) == len(set(keys))


def test_markdown_report_renders_findings_and_fixes():
    md = to_markdown(audit_paths([str(FIX / "vulnerable" / "Reentrancy.sol")]))
    assert md.startswith("# ")
    assert "SOL-001" in md
    assert "CRITICAL" in md
    assert "**Fix:**" in md
    assert "```solidity" in md
    assert "Reentrancy.sol:" in md


def test_markdown_report_clean_file():
    md = to_markdown(audit_paths([str(FIX / "safe" / "CleanToken.sol")]))
    assert "No findings" in md


def test_cli_json_output_and_exit_code(tmp_path):
    out = tmp_path / "out"
    proc = subprocess.run(
        [sys.executable, "-m", "solsec", str(FIX / "vulnerable" / "Reentrancy.sol"),
         "--format", "json", "-o", str(out), "--fail-on", "high"],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert proc.returncode == 1, proc.stderr
    data = json.loads((out / "solsec-report.json").read_text())
    assert data["summary"]["findings"] >= 1


def test_cli_markdown_mode(tmp_path):
    out = tmp_path / "md"
    proc = subprocess.run(
        [sys.executable, "-m", "solsec", str(FIX / "safe" / "CleanToken.sol"),
         "--format", "md", "-o", str(out)],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    body = (out / "solsec-report.md").read_text()
    assert body.startswith("# ")
    assert "No findings" in body


def test_cli_missing_path_exits_2():
    proc = subprocess.run([sys.executable, "-m", "solsec", "does-not-exist.sol"],
                          cwd=ROOT, capture_output=True, text=True)
    assert proc.returncode == 2


def test_rule_crash_is_isolated(monkeypatch):
    import solsec.analyzer as analyzer_mod

    def boom(ctx):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(analyzer_mod, "RULES",
                        list(analyzer_mod.RULES) + [("SOL-999", boom)])
    findings = audit_source("pragma solidity ^0.8.20;\ncontract A {}\n")
    crashed = [f for f in findings if f.rule == "SOL-000"]
    assert crashed and "kaboom" in crashed[0].message
