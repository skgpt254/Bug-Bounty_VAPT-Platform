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


class ScopeFilter:
    def __init__(self, program: Program):
        self.scope_re = re.compile(program.scope_regex) if program.scope_regex else None
        self.out_re = re.compile(program.out_of_scope_regex) if program.out_of_scope_regex else None

    def in_scope(self, host_or_url: str) -> bool:
        if not settings.enforce_scope:
            return True
        if self.out_re and self.out_re.search(host_or_url):
            return False
        if self.scope_re and not self.scope_re.search(host_or_url):
            return False
        return True

    def filter(self, items: list[str]) -> list[str]:
        return [i for i in items if self.in_scope(i)]
