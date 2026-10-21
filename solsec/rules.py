"""Detection rules for Solidity security smells.

Every rule is a function ``(ctx) -> list[Finding]`` registered in RULES.  Rules
work on the comment/string-masked source plus the lexed function list, so a
call written in a comment or inside a string never produces a finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict, field
from typing import Callable

from .lexer import Function, mask, find_functions, line_of

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Finding:
    rule: str
    title: str
    severity: str
    line: int
    message: str
    fix: str
    function: str = ""
    contract: str = ""
    snippet: str = ""
    confidence: str = "high"
    end_line: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        if not d["end_line"]:
            d["end_line"] = d["line"]
        d["severity_rank"] = SEVERITY_ORDER[self.severity]
        return d


@dataclass
class Context:
    path: str
    src: str
    clean: str
    funcs: list[Function]
    state_vars: list[str] = field(default_factory=list)

    @classmethod
    def build(cls, path: str, src: str) -> "Context":
        clean = mask(src)
        return cls(path, src, clean, find_functions(clean),
                   _collect_state_vars(clean, find_functions(clean)))


def _collect_state_vars(clean: str, funcs: list[Function]) -> list[str]:
    """Names declared at contract level (not inside a function body)."""
    body_spans = []
    for f in funcs:
        if f.body:
            body_spans.append((f.body_offset, f.body_offset + len(f.body)))
    names = []
    for m in re.finditer(
        r"\b(?:mapping\s*\([^)]*\)|uint\d*|int\d*|address|bool|bytes\d*|string|"
        r"[A-Z]\w*)\s+(?:public\s+|private\s+|internal\s+|immutable\s+|constant\s+)*"
        r"([A-Za-z_$][\w$]*)\s*[;=]",
        clean,
    ):
        pos = m.start()
        if any(a <= pos < b for a, b in body_spans):
            continue
        names.append(m.group(1))
    # dedupe, keep order
    return list(dict.fromkeys(names))


def _body_line(f: Function, body: str, offset: int) -> int:
    return f.body_start_line + body.count("\n", 0, offset)


def _stmt_start(body: str, pos: int) -> str:
    i = pos
    while i > 0 and body[i - 1] not in ";{}":
        i -= 1
    return body[i:pos]


def _snippet(src: str, line: int, span: int = 1) -> str:
    lines = src.splitlines()
    lo = max(0, line - 1)
    return "\n".join(lines[lo:lo + span]).strip()


# --------------------------------------------------------------------------
# SOL-001 reentrancy
# --------------------------------------------------------------------------

CALL_RE = re.compile(
    r"(?P<target>[A-Za-z_$][\w$]*(?:\s*\[[^\]]*\])?(?:\s*\.\s*[A-Za-z_$][\w$]*)*)"
    r"\s*\.\s*(?:call|send|transfer)\s*(?:\{[^}]*\})?\s*\("
)
REENTRANCY_GUARDS = {"nonreentrant", "nonreentrantview", "lock", "mutex", "onlyreentrant"}

WRITE_RE = re.compile(
    r"(?<![\w$.])([A-Za-z_$][\w$]*(?:\s*\[[^\]]*\])*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)"
    r"\s*(\+=|-=|\*=|/=|=(?!=|>))"
)
LOCAL_DECL_RE = re.compile(
    r"(?:uint\d*|int\d*|address|bool|bytes\d*|string|var)\s*(?:payable\s+)?"
    r"(?:memory\s+|storage\s+|calldata\s+)?[A-Za-z_$][\w$]*\s*$"
)


def _is_state_write(body: str, m: re.Match, locals_: set[str]) -> bool:
    target = m.group(1).strip()
    pre = _stmt_start(body, m.start(1))
    if LOCAL_DECL_RE.search(pre.strip()):
        return False
    if "return" in pre or "emit " in pre:
        return False
    root = re.split(r"[\[.]", target)[0].strip()
    if "[" in target or "." in target:
        return root not in locals_
    return root not in locals_


def rule_reentrancy(ctx: Context) -> list[Finding]:
    out: list[Finding] = []
    for f in ctx.funcs:
        body = f.body
        if not body or not f.is_mutating:
            continue
        if any(m.lower() in REENTRANCY_GUARDS for m in f.modifiers):
            continue
        locals_ = set(re.findall(
            r"(?:uint\d*|int\d*|address|bool|bytes\d*|string)\s+(?:memory\s+|storage\s+|calldata\s+)?([A-Za-z_$][\w$]*)",
            body))
        calls = list(CALL_RE.finditer(body))
        if not calls:
            continue
        for c in calls:
            target = re.sub(r"\s+", "", c.group("target"))
            # transfers to self / to a fixed trusted sink are not attacker code
            if target in ("address(this)", "this") or target.startswith("owner"):
                continue
            tail = body[c.end():]
            writes = [w for w in WRITE_RE.finditer(tail) if _is_state_write(tail, w, locals_)]
            if not writes:
                continue
            w = writes[0]
            line = _body_line(f, body, c.start())
            out.append(Finding(
                rule="SOL-001",
                title="Reentrancy: state written after external call",
                severity="critical",
                line=line,
                end_line=_body_line(f, body, c.end() + w.start()),
                function=f.name,
                contract=f.contract,
                message=(f"'{f.name}' performs an external call to {target} and only "
                         f"updates state afterwards; a malicious callee can re-enter "
                         f"before the balance/flag is updated."),
                fix="Apply checks-effects-interactions: update state before the call, and add a nonReentrant guard.",
                snippet=_snippet(ctx.src, line, 3),
            ))
            break  # one finding per function is enough signal
    return out


# --------------------------------------------------------------------------
# SOL-002 unchecked low-level call
# --------------------------------------------------------------------------

LOWLEVEL_RE = re.compile(
    r"\.\s*(call|send|delegatecall|staticcall)\s*(?:\{[^}]*\})?\s*\(")


def _call_end(body: str, open_paren: int) -> int:
    depth = 0
    for i in range(open_paren, len(body)):
        if body[i] == "(":
            depth += 1
        elif body[i] == ")":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(body)


def _return_checked(body: str, m: re.Match, call_end: int) -> bool:
    pre = _stmt_start(body, m.start()).strip()
    if re.search(r"\b(require|assert)\s*\(", pre):
        return True
    if re.match(r"(if|while|return|emit|revert)\b", pre):
        return True
    var = None
    bm = re.search(r"\(\s*bool\s+([A-Za-z_$][\w$]*)\s*,", pre) or \
        re.search(r"\bbool\s+([A-Za-z_$][\w$]*)\s*=", pre)
    if bm:
        var = bm.group(1)
    after = body[call_end:call_end + 400]
    if var:
        if re.search(r"(require|assert)\s*\(\s*" + re.escape(var) + r"\b", after):
            return True
        if re.search(r"if\s*\(\s*!?\s*" + re.escape(var) + r"\b", after):
            return True
    return False


def rule_unchecked_call(ctx: Context) -> list[Finding]:
    out = []
    for f in ctx.funcs:
        body = f.body
        if not body:
            continue
        for m in LOWLEVEL_RE.finditer(body):
            kind = m.group(1)
            if kind in ("call", "send") and re.search(r"\.\s*" + kind, body[max(0, m.start() - 40):m.start() + 1]):
                pass
            end = _call_end(body, m.end() - 1)
            if _return_checked(body, m, end):
                continue
            line = _body_line(f, body, m.start())
            out.append(Finding(
                rule="SOL-002",
                title=f"Unchecked low-level {kind} return value",
                severity="high",
                line=line,
                function=f.name,
                contract=f.contract,
                message=(f"Return value of {kind}() in '{f.name}' is ignored, so a "
                         f"failing transfer/execution continues silently."),
                fix=f"Capture the bool: (bool ok, ) = ...; require(ok, \"{kind} failed\");",
                snippet=_snippet(ctx.src, line, 2),
            ))
    return out


# --------------------------------------------------------------------------
# SOL-003 tx.origin
# --------------------------------------------------------------------------

def rule_tx_origin(ctx: Context) -> list[Finding]:
    out = []
    for m in re.finditer(r"\btx\s*\.\s*origin\b", ctx.clean):
        line = line_of(ctx.clean, m.start())
        fn = _enclosing(ctx.funcs, m.start())
        out.append(Finding(
            rule="SOL-003",
            title="Authorization via tx.origin",
            severity="high",
            line=line,
            function=fn.name if fn else "",
            contract=fn.contract if fn else "",
            message=("tx.origin authenticates the transaction's origin EOA, so a "
                     "phished user can be made to call an attacker contract that "
                     "passes the check on their behalf."),
            fix="Use msg.sender for authorization (or a signed permit / EIP-712 nonce).",
            snippet=_snippet(ctx.src, line, 2),
        ))
    return out


def _enclosing(funcs: list[Function], pos: int) -> Function | None:
    for f in funcs:
        if f.body and f.body_offset <= pos <= f.body_offset + len(f.body):
            return f
    return None


# --------------------------------------------------------------------------
# SOL-004 integer arithmetic and rounding
# --------------------------------------------------------------------------

DIV_THEN_MUL_RE = re.compile(
    r"([A-Za-z_$][\w$]*(?:\s*\[[^\]]*\])?(?:\s*\.\s*[A-Za-z_$][\w$]*)*)"
    r"\s*/\s*([A-Za-z_$][\w$.]*|\([^()]*\)|\d[\d_]*)\s*\*\s*"
)


def _pragma_minor(clean: str) -> int | None:
    m = re.search(r"pragma\s+solidity\s+[^;]*?0\s*\.\s*(\d+)", clean)
    return int(m.group(1)) if m else None


def rule_integer(ctx: Context) -> list[Finding]:
    out: list[Finding] = []
    minor = _pragma_minor(ctx.clean)
    has_safemath = bool(re.search(r"\bSafeMath\b|using\s+SafeMath", ctx.clean))
    has_arith = bool(re.search(
        r"(\+=|-=|\*=|/=|\+\+|--)|\b[A-Za-z0-9_\)\]]\s*(\+|\-|\*)\s*[A-Za-z0-9_(]", ctx.clean))

    if minor is not None and minor < 8 and has_arith and not has_safemath:
        out.append(Finding(
            rule="SOL-004",
            title="Unchecked integer overflow/underflow (pre-0.8 pragma)",
            severity="high",
            line=1,
            message=(f"pragma targets Solidity 0.8.{minor}x: arithmetic silently wraps "
                     f"and no SafeMath is used in this file."),
            fix="Bump to pragma solidity ^0.8.20 (checked arithmetic) or wrap all math in SafeMath.",
            snippet=_snippet(ctx.src, 1, 1),
        ))

    for f in ctx.funcs:
        body = f.body
        if not body:
            continue
        for m in re.finditer(r"\bunchecked\s*\{", body):
            end = _call_end(body.replace("{", "(").replace("}", ")"), m.end() - 1)
            block = body[m.end():m.start() + end]
            if re.search(r"[A-Za-z0-9_\)\]]\s*(\+|\-|\*)\s*[A-Za-z0-9_(]", block) or \
               re.search(r"(\+=|-=|\*=)", block):
                line = _body_line(f, body, m.start())
                out.append(Finding(
                    rule="SOL-004",
                    title="Arithmetic inside unchecked block",
                    severity="medium",
                    line=line,
                    function=f.name,
                    contract=f.contract,
                    message=(f"'{f.name}' does arithmetic inside unchecked {{ }}; "
                             f"overflow/underflow will wrap without revert."),
                    fix="Remove the unchecked block, or prove the bound with an explicit require before the math.",
                    snippet=_snippet(ctx.src, line, 3),
                ))
                break

        for m in DIV_THEN_MUL_RE.finditer(body):
            line = _body_line(f, body, m.start())
            if line == 1:
                continue
            out.append(Finding(
                rule="SOL-004",
                title="Precision loss: division before multiplication",
                severity="medium",
                line=line,
                function=f.name,
                contract=f.contract,
                message=(f"'{f.name}' divides before multiplying "
                         f"({m.group(1).strip()} / {m.group(2).strip()} * ...), truncating "
                         f"the intermediate result and losing value on small amounts."),
                fix="Multiply first, then divide: (a * b) / c, and round in the protocol's favour.",
                snippet=_snippet(ctx.src, line, 2),
                confidence="medium",
            ))
    return out


# --------------------------------------------------------------------------
# SOL-005 unprotected initializer
# --------------------------------------------------------------------------

INIT_NAMES = re.compile(r"^(__)?(init|initialize|initializeV\d+|initOwner|setup)$", re.I)
INIT_GUARD_MODS = re.compile(r"\b(initializer|reinitializer\s*\([^)]*\)|onlyInitializing)\b")
INIT_GUARD_BODY = re.compile(
    r"require\s*\(\s*(?:!\s*[A-Za-z_$][\w$]*initialized|"
    r"[A-Za-z_$][\w$]*initialized\s*==\s*false|"
    r"[A-Za-z_$][\w$]*\s*==\s*address\s*\(\s*0\s*\)|"
    r"!\s*_initialized)")


def rule_initializer(ctx: Context) -> list[Finding]:
    out = []
    for f in ctx.funcs:
        if f.kind not in ("function",) or not INIT_NAMES.match(f.name):
            continue
        if f.visibility not in ("public", "external"):
            continue
        if INIT_GUARD_MODS.search(f.header) or INIT_GUARD_BODY.search(f.body):
            continue
        line = f.start_line
        out.append(Finding(
            rule="SOL-005",
            title="Unprotected initializer",
            severity="critical",
            line=line,
            function=f.name,
            contract=f.contract,
            message=(f"'{f.name}' is {f.visibility} and has no initializer modifier or "
                     f"one-shot guard; anyone can call it again to reset owner/state "
                     f"(or front-run deployment in a proxy setup)."),
            fix="Add OpenZeppelin's `initializer` modifier (and `_disableInitializers()` in the constructor).",
            snippet=_snippet(ctx.src, line, 5),
        ))
    return out


# --------------------------------------------------------------------------
# SOL-006 missing access control on privileged functions
# --------------------------------------------------------------------------

ACL_MODS = re.compile(
    r"\b(?:onlyOwner|onlyAdmin|onlyRole\s*\([^)]*\)|onlyMinter|onlyGovernance|"
    r"onlyController|onlyOperator|onlyKeeper|onlyManager|onlyDAO|onlyTimelock|"
    r"onlyAuthorized|requiresAuth|auth|restricted|onlyProxyAdmin|onlyGuardian)"
    r"(?![\w$])",
    re.I)
ACL_BODY = re.compile(
    r"(require|if)\s*\(\s*(?:!\s*)?(?:msg\.sender\s*==|_msgSender\(\)\s*==)|"
    r"require\s*\(\s*hasRole\s*\(|_checkOwner\s*\(|_checkRole\s*\(|"
    r"if\s*\(\s*msg\.sender\s*!=")

PRIV_PATTERNS = [
    (re.compile(r"^(withdraw|withdrawAll|withdrawEth|withdrawToken|sweep|rescue|"
                r"emergencyWithdraw|drain)", re.I), "high"),
    (re.compile(r"^(mint|burn|setMinter|upgradeTo|upgradeToAndCall|setImplementation|"
                r"setAdmin|setOwner|transferOwnership|renounceOwnership)", re.I), "high"),
    (re.compile(r"^(selfdestruct|kill|destroy)$", re.I), "critical"),
    (re.compile(r"^(pause|unpause|setFee|setFees|setTax|setRate|setPrice|setOracle|"
                r"setRouter|setTreasury|setWallet|setWhitelist|setLimit|setConfig|"
                r"setBaseURI|setOperator|setGuardian|setController|setManager|"
                r"initializeV\d+)", re.I), "medium"),
]


def rule_access_control(ctx: Context) -> list[Finding]:
    out = []
    for f in ctx.funcs:
        if f.kind != "function" or f.visibility not in ("public", "external"):
            continue
        sev = None
        for rx, s in PRIV_PATTERNS:
            if rx.search(f.name):
                sev = s
                break
        if sev is None:
            continue
        if sev == "high" and f.name.lower().startswith(("withdraw", "claim", "burn")):
            # a per-user withdraw*/claim* is not privileged: only report it when
            # it moves protocol funds or pays an attacker-chosen sink
            moves_protocol_funds = re.search(
                r"address\s*\(\s*this\s*\)|selfbalance|\.\s*balance\b", f.body)
            has_sink_param = re.search(
                r"\b(to|recipient|beneficiary|sink|account|dst)\b", f.params)
            if not moves_protocol_funds and not has_sink_param:
                continue
        if ACL_MODS.search(f.header) or ACL_BODY.search(f.body):
            continue
        if not f.body.strip():
            continue
        line = f.start_line
        out.append(Finding(
            rule="SOL-006",
            title=f"Missing access control on '{f.name}'",
            severity=sev,
            line=line,
            function=f.name,
            contract=f.contract,
            message=(f"'{f.name}' is {f.visibility} and mutates privileged state but "
                     f"carries no owner/role modifier and no msg.sender check in its body."),
            fix=f"Restrict it: `{f.name}(...) external onlyOwner` (or an AccessControl role).",
            snippet=_snippet(ctx.src, line, 4),
        ))
    return out


# --------------------------------------------------------------------------
# SOL-007 dangerous delegatecall
# --------------------------------------------------------------------------

DELEGATE_RE = re.compile(r"([A-Za-z_$][\w$]*(?:\s*\[[^\]]*\])?|\w+\s*\.\s*\w+)"
                         r"\s*\.\s*delegatecall\s*(?:\{[^}]*\})?\s*\(")
ASM_DELEGATE_RE = re.compile(r"delegatecall\s*\(")
MUTABLE_TARGET_RE = re.compile(r"^(target|_target|implementation|_implementation|"
                              r"impl|_impl|logic|_logic|dest|destination|addr|to)$", re.I)
IMMUTABLE_RE = re.compile(
    r"\b(?:address|bytes32|uint\d*)\s+(?:public\s+|private\s+|internal\s+)*"
    r"(?:immutable|constant)\s+([A-Za-z_$][\w$]*)")


def rule_delegatecall(ctx: Context) -> list[Finding]:
    out = []
    pinned = set(IMMUTABLE_RE.findall(ctx.clean))
    for f in ctx.funcs:
        body = f.body
        if not body:
            continue
        params = set(re.findall(r"\b([A-Za-z_$][\w$]*)\s*(?:,|\))", f.params + ","))
        for m in DELEGATE_RE.finditer(body):
            target = re.sub(r"\s+", "", m.group(1))
            root = re.split(r"[\[.]", target)[0]
            line = _body_line(f, body, m.start())
            user_controlled = root in params or target in ("msg.data", "msg.sender")
            if not user_controlled:
                # storage-held implementation is only acceptable when pinned
                # (immutable/constant) or explicitly whitelisted in the body
                if root in pinned:
                    continue
                if re.search(r"require\s*\([^;]*\b" + re.escape(root) + r"\b\s*==", body):
                    continue
                if not MUTABLE_TARGET_RE.match(root):
                    continue
            out.append(Finding(
                rule="SOL-007",
                title="Dangerous delegatecall to a caller-controlled target",
                severity="critical" if user_controlled else "high",
                line=line,
                function=f.name,
                contract=f.contract,
                message=(f"'{f.name}' delegatecalls {target}, which the caller can "
                         f"choose; delegatecall runs the callee's code with this "
                         f"contract's storage and balance, allowing full takeover."),
                fix="Whitelist an immutable implementation: `require(target == implementation)` with `address public immutable implementation`.",
                snippet=_snippet(ctx.src, line, 3),
            ))
        for m in ASM_DELEGATE_RE.finditer(body):
            # assembly delegatecall(gas, addr, ...) - addr is the 3rd token
            seg = body[m.end():m.end() + 160]
            if not re.search(r"^\s*(?:gas\s*\(\s*\)|gas\s*\(\))", seg):
                continue
            parts = [p.strip() for p in seg.split(",")]
            if len(parts) < 2:
                continue
            addr_expr = parts[1].split(")")[0].strip()
            root = re.split(r"[\[.]", addr_expr)[0]
            if root in params or root in ("calldataload", "add", "mload", "sload"):
                line = _body_line(f, body, m.start())
                out.append(Finding(
                    rule="SOL-007",
                    title="delegatecall in inline assembly to a dynamic address",
                    severity="critical",
                    line=line,
                    function=f.name,
                    contract=f.contract,
                    message=(f"Inline assembly in '{f.name}' delegatecalls a target "
                             f"derived from calldata/params ({addr_expr})."),
                    fix="Load the implementation from an immutable whitelist and require it before the assembly delegatecall.",
                    snippet=_snippet(ctx.src, line, 3),
                ))
    return out


# --------------------------------------------------------------------------
# SOL-008 unprotected selfdestruct
# --------------------------------------------------------------------------

def rule_selfdestruct(ctx: Context) -> list[Finding]:
    out = []
    for f in ctx.funcs:
        if not f.body:
            continue
        m = re.search(r"\b(selfdestruct|suicide)\s*\(", f.body)
        if not m:
            continue
        if ACL_MODS.search(f.header) or ACL_BODY.search(f.body):
            continue
        line = _body_line(f, f.body, m.start())
        out.append(Finding(
            rule="SOL-008",
            title="Unprotected selfdestruct",
            severity="high",
            line=line,
            function=f.name,
            contract=f.contract,
            message=(f"'{f.name}' can destroy the contract and forward its balance "
                     f"without any owner/role check."),
            fix="Gate destruction behind onlyOwner + a timelock, or remove selfdestruct entirely.",
            snippet=_snippet(ctx.src, line, 2),
        ))
    return out


RULES: list[tuple[str, Callable[[Context], list[Finding]]]] = [
    ("SOL-001", rule_reentrancy),
    ("SOL-002", rule_unchecked_call),
    ("SOL-003", rule_tx_origin),
    ("SOL-004", rule_integer),
    ("SOL-005", rule_initializer),
    ("SOL-006", rule_access_control),
    ("SOL-007", rule_delegatecall),
    ("SOL-008", rule_selfdestruct),
]
