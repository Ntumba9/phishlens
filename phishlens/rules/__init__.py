"""The detection rule registry.

Every signal PhishLens can raise lives here as a named, documented rule.
"""

from __future__ import annotations

from . import attachments, authentication, headers, language, links, lookalike, route
from .base import AnalysisContext, Rule

RULES: list[Rule] = [
    *headers.RULES,
    *authentication.RULES,
    *route.RULES,
    *links.RULES,
    *lookalike.RULES,
    *language.RULES,
    *attachments.RULES,
]

RULES_BY_ID: dict[str, Rule] = {rule.id: rule for rule in RULES}

if len(RULES_BY_ID) != len(RULES):  # pragma: no cover - import-time guard
    raise RuntimeError("Duplicate rule IDs in the registry")

__all__ = ["AnalysisContext", "Rule", "RULES", "RULES_BY_ID"]
