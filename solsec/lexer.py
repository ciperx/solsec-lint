"""Small Solidity lexer.

Deliberately dependency-free: it strips comments and string literals while
preserving byte offsets and newlines (so line numbers stay exact), tokenizes
what remains, and locates function bodies with brace matching.  Regex alone
cannot tell a call inside a comment from a real call; the lexer is what makes
the rules trustworthy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

KEYWORDS = {
    "pragma", "solidity", "import", "contract", "interface", "library",
    "abstract", "function", "modifier", "constructor", "fallback", "receive",
    "returns", "return", "if", "else", "for", "while", "do", "break",
    "continue", "throw", "emit", "try", "catch", "new", "delete", "assembly",
    "unchecked", "using", "is", "public", "private", "internal", "external",
    "pure", "view", "payable", "virtual", "override", "immutable", "constant",
    "memory", "storage", "calldata", "indexed", "event", "error", "struct",
    "enum", "mapping", "true", "false", "this", "super", "let",
}

_IDENT_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_NUM_RE = re.compile(r"(?:0[xX][0-9a-fA-F_]+|\d[\d_]*(?:\.\d+)?(?:[eE][+-]?\d+)?)")
_MULTI_OPS = (
    ">>>=", "<<=", ">>=", "**", "==", "!=", "<=", ">=", "&&", "||", "++", "--",
    "+=", "-=", "*=", "/=", "%=", "|=", "&=", "^=", "=>", "->", "<<", ">>",
)


@dataclass
class Token:
    kind: str          # ident | keyword | number | string | op | punct
    value: str
    line: int          # 1-based
    col: int           # 1-based
    pos: int           # offset in the cleaned source


@dataclass
class Function:
    name: str
    kind: str                      # function | constructor | fallback | receive | modifier
    header: str                    # text between name and opening brace
    params: str
    modifiers: list[str] = field(default_factory=list)
    visibility: str = ""
    start_line: int = 0            # line of the `function` keyword
    body_start_line: int = 0
    end_line: int = 0
    body: str = ""                 # body text (cleaned), without outer braces
    body_offset: int = 0           # offset of body in cleaned source
    contract: str = ""

    @property
    def is_mutating(self) -> bool:
        return "view" not in self.header and "pure" not in self.header


def mask(src: str) -> str:
    """Return src with comments/strings blanked out, same length, newlines kept."""
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out[i] = " "
                i += 1
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            out[i] = out[i + 1] = " "
            i += 2
            while i < n and not (src[i] == "*" and i + 1 < n and src[i + 1] == "/"):
                if src[i] != "\n":
                    out[i] = " "
                i += 1
            if i < n:
                out[i] = " "
                if i + 1 < n:
                    out[i + 1] = " "
                i += 2
        elif c in ('"', "'"):
            q = c
            out[i] = " "
            i += 1
            while i < n:
                if src[i] == "\\":
                    out[i] = " "
                    if i + 1 < n and src[i + 1] != "\n":
                        out[i + 1] = " "
                    i += 2
                    continue
                if src[i] == q:
                    out[i] = " "
                    i += 1
                    break
                if src[i] != "\n":
                    out[i] = " "
                i += 1
        else:
            i += 1
    return "".join(out)


def tokenize(clean: str) -> list[Token]:
    tokens: list[Token] = []
    i, n = 0, len(clean)
    line, col = 1, 1
    while i < n:
        c = clean[i]
        if c == "\n":
            line += 1
            col = 1
            i += 1
            continue
        if c.isspace():
            i += 1
            col += 1
            continue
        m = _IDENT_RE.match(clean, i)
        if m:
            v = m.group(0)
            tokens.append(Token("keyword" if v in KEYWORDS else "ident", v, line, col, i))
            col += len(v)
            i = m.end()
            continue
        m = _NUM_RE.match(clean, i)
        if m:
            v = m.group(0)
            tokens.append(Token("number", v, line, col, i))
            col += len(v)
            i = m.end()
            continue
        for op in _MULTI_OPS:
            if clean.startswith(op, i):
                tokens.append(Token("op", op, line, col, i))
                i += len(op)
                col += len(op)
                break
        else:
            kind = "punct" if c in "(){}[];,." else "op"
            tokens.append(Token(kind, c, line, col, i))
            i += 1
            col += 1
    return tokens


_FN_RE = re.compile(
    r"\b(function|constructor|fallback|receive|modifier)\b"
    r"\s*([A-Za-z_$][A-Za-z0-9_$]*)?\s*"
)


def _match_brace(clean: str, open_pos: int) -> int:
    depth = 0
    for i in range(open_pos, len(clean)):
        if clean[i] == "{":
            depth += 1
        elif clean[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(clean) - 1


def find_functions(clean: str) -> list[Function]:
    funcs: list[Function] = []
    contract = ""
    # track contract names by simple scan of `contract X` occurrences
    contract_marks = [(m.start(), m.group(1)) for m in re.finditer(r"\b(?:contract|library|interface)\s+([A-Za-z_$][\w$]*)", clean)]

    for m in _FN_RE.finditer(clean):
        kw = m.group(1)
        name = m.group(2) or ("constructor" if kw == "constructor" else kw)
        # skip `function` keyword inside comments already masked; skip if part of
        # a variable type e.g. "function(uint) external" (no body/header bar)
        j = m.end()
        # find the parameter list
        while j < len(clean) and clean[j].isspace():
            j += 1
        if j >= len(clean) or clean[j] != "(":
            continue
        depth = 0
        k = j
        while k < len(clean):
            if clean[k] == "(":
                depth += 1
            elif clean[k] == ")":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        params = clean[j + 1:k]
        # header runs to the first '{' or ';'
        h = k + 1
        while h < len(clean) and clean[h] not in "{;":
            h += 1
        header = clean[k + 1:h].strip()
        if h >= len(clean) or clean[h] != "{":
            # interface/abstract declaration - no body, still useful for ACL?
            funcs.append(Function(name, kw, header, params,
                                  start_line=clean.count("\n", 0, m.start()) + 1,
                                  contract=_contract_at(contract_marks, m.start())))
            continue
        end = _match_brace(clean, h)
        start_line = clean.count("\n", 0, m.start()) + 1
        body_start_line = clean.count("\n", 0, h) + 1
        end_line = clean.count("\n", 0, end) + 1
        mods = _parse_modifiers(header)
        vis = _parse_visibility(header)
        funcs.append(Function(
            name, kw, header, params, mods, vis, start_line,
            body_start_line, end_line, clean[h + 1:end], h + 1,
            _contract_at(contract_marks, m.start()),
        ))
    return funcs


def _contract_at(marks: list[tuple[int, str]], pos: int) -> str:
    name = ""
    for p, n in marks:
        if p < pos:
            name = n
        else:
            break
    return name


def _parse_modifiers(header: str) -> list[str]:
    mods = []
    for m in re.finditer(r"\b([A-Za-z_$][\w$]*)\s*(?:\([^)]*\))?", header):
        w = m.group(1)
        if w in ("public", "private", "internal", "external", "pure", "view",
                 "payable", "virtual", "override", "returns", "memory",
                 "calldata", "storage"):
            continue
        mods.append(w)
    return mods


def _parse_visibility(header: str) -> str:
    for v in ("external", "public", "internal", "private"):
        if re.search(r"\b" + v + r"\b", header):
            return v
    return "public"  # solidity default for functions


def line_of(clean: str, offset: int) -> int:
    return clean.count("\n", 0, offset) + 1


def iter_lines(src: str) -> Iterable[tuple[int, str]]:
    for i, line in enumerate(src.splitlines(), 1):
        yield i, line
