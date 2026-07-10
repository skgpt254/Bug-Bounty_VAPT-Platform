"""
Scope enforcement. Every active-scanning phase (nuclei, ffuf, CORS probing,
cloud bucket checks) must filter its target list through `in_scope()` before
sending a single packet. This is the same gate the original bash script
implemented with SCOPE_REGEX / OUT_OF_SCOPE_REGEX — kept as a hard rule here
because it's the difference between authorized testing and a ToS violation.
"""

from __future__ import annotations

import re

from app.config import settings
from app.models import Program

# Matches on hostnames/URLs, which are bounded (DNS labels max 253 chars
# total). This caps runaway backtracking cost even for a badly-written
# pattern: worst case is bounded by input length, not unbounded.
MAX_MATCH_INPUT_LEN = 2048
MAX_PATTERN_LEN = 500

# Heuristic catastrophic-backtracking shapes: a quantified group containing
# another quantified sub-expression, e.g. (a+)+, (.*)+, (\w+)*. Not
# exhaustive — this is a tripwire for the obvious cases, not a full ReDoS
# analyzer — but it catches the patterns people actually paste by accident.
_REDOS_SHAPE = re.compile(r"\([^)]*[+*][^)]*\)[+*]")


class UnsafeScopeRegexError(ValueError):
    pass


def validate_scope_regex(pattern: str) -> None:
    """Raises UnsafeScopeRegexError on patterns that are too long or match a
    known catastrophic-backtracking shape. Call this at program-creation
    time (API layer), not just at match time — by match time it's too late.
    """
    if len(pattern) > MAX_PATTERN_LEN:
        raise UnsafeScopeRegexError(f"scope regex too long (max {MAX_PATTERN_LEN} chars)")
    if _REDOS_SHAPE.search(pattern):
        raise UnsafeScopeRegexError(
            "scope regex contains a nested-quantifier shape (e.g. (a+)+) that risks "
            "catastrophic backtracking — simplify it, e.g. use a single quantified group"
        )
    re.compile(pattern)  # raises re.error on plain syntax errors


class ScopeFilter:
    def __init__(self, program: Program):
        self.scope_re = re.compile(program.scope_regex) if program.scope_regex else None
        self.out_re = re.compile(program.out_of_scope_regex) if program.out_of_scope_regex else None

    def in_scope(self, host_or_url: str) -> bool:
        if not settings.enforce_scope:
            return True
        # Bound the input length matched against — the regex only ever needs
        # to see a hostname or URL, never an attacker-lengthenable blob.
        target = host_or_url[:MAX_MATCH_INPUT_LEN]
        if self.out_re and self.out_re.search(target):
            return False
        if self.scope_re and not self.scope_re.search(target):
            return False
        return True

    def filter(self, items: list[str]) -> list[str]:
        return [i for i in items if self.in_scope(i)]
