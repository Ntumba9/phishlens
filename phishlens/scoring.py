"""Turn findings into a score and a verdict for a human reviewer.

The model is deliberately simple and documented: each finding contributes
its severity weight, capped at 100. Weights are a heuristic, tuned against
the synthetic fixture corpus in tests/fixtures (see scripts/evaluate.py);
they are not measured real-world accuracy, and the README says so.

The verdict is triage, not truth: "no_strong_signals" means exactly that,
never "safe". The reasons always ship with the verdict so an analyst can
overrule it - and the case store records that override.
"""

from __future__ import annotations

from .models import Finding

_WEIGHTS = {"high": 30, "medium": 12, "low": 4, "info": 0}

LIKELY_PHISH_AT = 50
SUSPICIOUS_AT = 20

VERDICTS = ("likely_phish", "suspicious", "no_strong_signals")


def score_findings(findings: list[Finding]) -> int:
    return min(100, sum(_WEIGHTS.get(f.severity, 0) for f in findings))


def verdict_for(score: int) -> str:
    if score >= LIKELY_PHISH_AT:
        return "likely_phish"
    if score >= SUSPICIOUS_AT:
        return "suspicious"
    return "no_strong_signals"
