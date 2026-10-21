# solsec-lint

A small, self-contained static security linter for Solidity. Pure Python 3.11+,
standard library only — no pip installs, no paid APIs, no network access, no
compiler. It reads `.sol` files, parses them with a hand-written lexer plus
targeted regex rules, and emits findings as JSON or Markdown.

```
$ solsec-lint tests/fixtures/vulnerable --format both -o examples/
solsec-lint: 11 file(s), 29 finding(s) [critical 7, high 15, medium 7]
```

## Why a lexer instead of plain regex

Comments and string literals are the main source of false positives in a regex
linter — a doc comment that says *"never use tx.origin"* must not be reported.
`solsec/lexer.py` masks comments and string bodies while preserving byte offsets
and newlines, so every reported line number still points at the real source
line, and then tokenizes what remains and locates function bodies by brace
matching. Rules therefore know which function they are inside, whether it has a
`nonReentrant` modifier, and in what order its statements appear.

## Rules

| ID | Severity | Detects |
|---|---|---|
| SOL-001 | critical | Reentrancy: external call (`call`/`send`/`transfer`) before a state write in the same function, with no `nonReentrant`-style guard |
| SOL-002 | high | Unchecked low-level call: `call`/`send`/`delegatecall`/`staticcall` return value discarded (no `require`, `if`, or bound-and-checked bool) |
| SOL-003 | high | `tx.origin` used for authorization |
| SOL-004 | high/medium | Integer and rounding issues: pre-0.8 `pragma` with unwrapped arithmetic and no `SafeMath`, arithmetic inside `unchecked {}`, and division-before-multiplication precision loss |
| SOL-005 | critical | Unprotected initializer: `public`/`external` `initialize()` without `initializer`/`reinitializer` or a one-shot guard |
| SOL-006 | critical/high/medium | Missing access control on privileged functions (`withdraw*`, `mint`, `pause`, `setFee`, `setOracle`, `upgradeTo`, `transferOwnership`, `selfdestruct`, …) with no owner/role modifier and no `msg.sender` check |
| SOL-007 | critical/high | Dangerous `delegatecall`: target is a function parameter, calldata-derived, or a mutable storage pointer that is neither `immutable`/`constant` nor whitelisted by a `require` |
| SOL-008 | high | Unprotected `selfdestruct` |

Every finding carries: `rule`, `title`, `severity`, `line` (plus `end_line`),
`function`, `contract`, `message`, `fix` (one line), `confidence`, and a source
`snippet`.

## Install and run

No installation needed:

```bash
python -m solsec tests/fixtures/vulnerable            # JSON to stdout
python -m solsec contracts/ --format md               # Markdown to stdout
python -m solsec contracts/ --format both -o reports/ # writes reports/
python -m solsec contracts/ --fail-on critical        # CI gate
```

Exit codes: `0` clean (below `--fail-on`), `1` finding at/above the threshold
(default `high`), `2` bad path. `--fail-on never` always exits 0.

As a library:

```python
from solsec import audit_file, audit_paths, to_json, to_markdown

findings = audit_file("contracts/Vault.sol")
for f in findings:
    print(f.severity, f.rule, f.line, f.title, "->", f.fix)

report = audit_paths(["contracts"])
print(to_markdown(report))
```

## JSON shape

```json
{
  "tool": "solsec-lint",
  "version": "1.0.0",
  "files": [
    {
      "file": "tests/fixtures/vulnerable/Reentrancy.sol",
      "findings": [
        {
          "rule": "SOL-001",
          "title": "Reentrancy: state written after external call",
          "severity": "critical",
          "line": 16,
          "end_line": 18,
          "function": "withdraw",
          "contract": "VulnerableBank",
          "message": "'withdraw' performs an external call to msg.sender ...",
          "fix": "Apply checks-effects-interactions: update state before the call, and add a nonReentrant guard.",
          "confidence": "high",
          "snippet": "(bool ok, ) = msg.sender.call{value: amount}(\"\");",
          "severity_rank": 4
        }
      ],
      "counts": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}
    }
  ],
  "summary": {"files_scanned": 1, "findings": 1,
              "by_severity": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
              "passed": false}
}
```

## Repository layout

```
clawork-audit/
├── solsec/
│   ├── __init__.py        # public API: audit_file / audit_paths / to_json / to_markdown
│   ├── __main__.py        # python -m solsec
│   ├── lexer.py           # comment/string masking, tokenizer, function+body scanner
│   ├── rules.py           # SOL-001..SOL-008 detectors, Finding/Context dataclasses
│   ├── analyzer.py        # rule orchestration, dedupe, severity sort, summary
│   ├── report.py          # JSON + Markdown renderers
│   └── cli.py             # argparse CLI, exit codes
├── tests/
│   ├── test_solsec.py     # 41 pytest tests (rule hits, false positives, CLI, schema)
│   └── fixtures/
│       ├── vulnerable/    # 11 intentionally buggy contracts, one family each
│       └── safe/          # 7 hardened counterparts that must report nothing
├── examples/report.md     # real output on tests/fixtures/vulnerable/KitchenSink.sol
├── pyproject.toml
└── README.md
```

## Fixtures

`tests/fixtures/vulnerable/` — `Reentrancy.sol`, `UncheckedCall.sol`,
`TxOriginAuth.sol`, `IntegerOverflow.sol`, `RoundingShare.sol`,
`UncheckedMath.sol`, `UnprotectedInit.sol`, `MissingAccessControl.sol`,
`DelegatecallProxy.sol`, `SelfDestruct.sol`, `KitchenSink.sol` (all rules).

`tests/fixtures/safe/` — `ReentrancySafe.sol`, `CheckedCall.sol`, `Owned.sol`,
`ProtectedInit.sol`, `AccessControlSafe.sol`, `DelegatecallProxy.sol`
(immutable target), `SafeShares.sol`, `CleanToken.sol` (also contains a comment
that mentions `tx.origin` and `delegatecall`, to prove masking works).

Each vulnerable fixture is asserted to trigger its specific rule **at the right
line**; each safe fixture is asserted to report **zero** findings.

## Testing

```bash
python -m pytest -q     # 41 passed
```

CI gate (works in any pipeline, no install beyond the package):

```bash
solsec-lint contracts/ --fail-on high -o reports/   # exits 1 on any high/critical
solsec-lint tests/fixtures/safe --fail-on low       # our clean baseline must exit 0
```

## Limits

This is pattern analysis, not formal verification: it does not compile the
code, resolve inheritance across files, build a call graph, reason about
storage layout, or model token semantics. It will miss logic bugs and can flag
unusual-but-safe patterns (for example a `delegatecall` to a mutable
implementation pointer that is only set behind `onlyOwner` — pin it `immutable`
or add an explicit `require(target == implementation)` to clear the finding).
Treat it as a fast first pass that also works in CI, not as a replacement for
tests, fuzzing, or a manual review.

## License

MIT
