"""solsec-lint — a small, dependency-free static security linter for Solidity."""

from .analyzer import audit_file, audit_paths, audit_source, TOOL_NAME, TOOL_VERSION
from .rules import Finding, Context, RULES, SEVERITY_ORDER
from .report import to_json, to_markdown

__all__ = [
    "audit_file", "audit_paths", "audit_source", "Finding", "Context", "RULES",
    "SEVERITY_ORDER", "to_json", "to_markdown", "TOOL_NAME", "TOOL_VERSION",
]
__version__ = TOOL_VERSION
