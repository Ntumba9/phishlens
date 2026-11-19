"""Language rules: pressure and credential-bait phrases in subject/body."""

from __future__ import annotations

import re

from ..models import Finding
from .base import AnalysisContext, Rule

_PRESSURE = [
    r"\burgent\b",
    r"\bimmediately\b",
    r"\bwithin\s+\d+\s+hours?\b",
    r"\baccount\s+(has\s+been|will\s+be)\s+(suspended|closed|locked|limited)\b",
    r"\bunusual\s+(activity|sign[- ]in|login)\b",
    r"\bverify\s+your\s+(account|identity|email)\b",
    r"\bconfirm\s+your\s+(identity|account|details)\b",
    r"\bfinal\s+(notice|warning|reminder)\b",
    r"\blast\s+chance\b",
    r"\bfailed\s+payment\b",
    r"\bpayment\s+(was\s+)?declined\b",
    r"\bsuspend\w*\s+your\s+account\b",
    r"\bunauthorized\s+(access|transaction|login)\b",
]

_CREDENTIAL_BAIT = [
    r"\benter\s+your\s+password\b",
    r"\bupdate\s+your\s+(password|payment|billing)\b",
    r"\blog\s*in\s+to\s+(verify|confirm|secure)\b",
    r"\bsign\s*in\s+to\s+(verify|confirm|secure)\b",
    r"\bconfirm\s+your\s+(password|card|banking)\b",
    r"\bone[- ]time\s+(code|pin|password)\b",
    r"\botp\b",
]


def _matches(patterns: list[str], haystack: str) -> list[str]:
    hits = []
    for pattern in patterns:
        m = re.search(pattern, haystack, re.IGNORECASE)
        if m:
            hits.append(m.group(0))
    return hits


def _pressure(ctx: AnalysisContext) -> list[Finding]:
    haystack = f"{ctx.parsed.subject}\n{ctx.parsed.text_body}"
    hits = _matches(_PRESSURE, haystack)
    if len(hits) >= 2:
        return [
            Finding(
                code="pressure_language",
                severity="medium",
                title="Message pressures the reader to act fast",
                detail="Phrases found: " + ", ".join(f'"{p}"' for p in hits[:5]),
            )
        ]
    if hits:
        return [
            Finding(
                code="pressure_language",
                severity="low",
                title="Some urgency language present",
                detail=f'Phrase found: "{hits[0]}"',
            )
        ]
    return []


def _credential_bait(ctx: AnalysisContext) -> list[Finding]:
    haystack = f"{ctx.parsed.subject}\n{ctx.parsed.text_body}"
    hits = _matches(_CREDENTIAL_BAIT, haystack)
    if hits:
        return [
            Finding(
                code="credential_bait",
                severity="medium",
                title="Message asks for credentials or sensitive details",
                detail="Phrases found: " + ", ".join(f'"{b}"' for b in hits[:4]),
            )
        ]
    return []


RULES = [
    Rule(
        id="pressure_language",
        name="Pressure language",
        category="language",
        rationale=(
            "Deadlines and threats ('within 24 hours', 'account "
            "suspended') push the reader to act before checking. "
            "Legitimate services rarely demand instant action over email."
        ),
        run=_pressure,
    ),
    Rule(
        id="credential_bait",
        name="Credential bait",
        category="language",
        rationale=(
            "Asking for a password, card or one-time code by email is what "
            "a credential-phishing lure is ultimately for, especially "
            "combined with a mismatched link."
        ),
        run=_credential_bait,
    ),
]
