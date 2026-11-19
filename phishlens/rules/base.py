"""The rule registry: every detection is a named, documented, testable rule.

A rule owns one signal. It carries a stable ID, the category the finding
belongs to in the report, a plain-language rationale the analyst can read
next to the evidence, and an external reference only where the mapping is
direct. Rules never fetch, resolve or open anything: they reason over the
parsed message and the parsed relay route only.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ..models import Finding, Hop, ParsedEmail


@dataclass
class AnalysisContext:
    """Everything a rule is allowed to see."""

    parsed: ParsedEmail
    hops: list[Hop] = field(default_factory=list)


RuleRun = Callable[[AnalysisContext], list[Finding]]


@dataclass(frozen=True)
class Rule:
    """One detection with its analyst-facing documentation."""

    id: str
    name: str
    category: str  # headers, authentication, links, lookalike, language, attachments, route
    rationale: str
    run: RuleRun
    reference: str = ""
