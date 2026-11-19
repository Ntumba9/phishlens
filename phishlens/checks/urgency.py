"""Language evidence: pressure and credential-bait phrases in subject/body."""

from __future__ import annotations

import re

from ..models import Finding, ParsedEmail

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


def _count_matches(patterns: list[str], haystack: str) -> list[str]:
    hits = []
    for pattern in patterns:
        m = re.search(pattern, haystack, re.IGNORECASE)
        if m:
            hits.append(m.group(0))
    return hits


def check(msg: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    haystack = f"{msg.subject}\n{msg.text_body}"

    pressure = _count_matches(_PRESSURE, haystack)
    if len(pressure) >= 2:
        findings.append(
            Finding(
                code="pressure_language",
                severity="medium",
                title="Message pressures the reader to act fast",
                detail="Phrases found: " + ", ".join(f'"{p}"' for p in pressure[:5]),
            )
        )
    elif pressure:
        findings.append(
            Finding(
                code="pressure_language",
                severity="low",
                title="Some urgency language present",
                detail=f'Phrase found: "{pressure[0]}"',
            )
        )

    bait = _count_matches(_CREDENTIAL_BAIT, haystack)
    if bait:
        findings.append(
            Finding(
                code="credential_bait",
                severity="medium",
                title="Message asks for credentials or sensitive details",
                detail="Phrases found: " + ", ".join(f'"{b}"' for b in bait[:4]),
            )
        )
    return findings
