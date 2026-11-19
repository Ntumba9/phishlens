"""Authentication rules: SPF, DKIM and DMARC as recorded by the receiver.

These results are claims written down by the receiving mail server in the
Authentication-Results header. PhishLens reports what that server recorded;
it does not re-verify authentication itself. When no such header exists
(a hand-pasted message, a stripped export), authentication is unknown, not
passed and not failed.
"""

from __future__ import annotations

import re

from ..models import Finding
from .base import AnalysisContext, Rule

_OUTCOMES = {"fail": "high", "softfail": "medium", "permerror": "medium", "temperror": "medium"}


def _mechanism_failure(mechanism: str):
    def run(ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        pattern = re.compile(rf"\b{mechanism}\s*=\s*(\w+)", re.IGNORECASE)
        for header in ctx.parsed.authentication_results:
            for outcome in pattern.findall(header):
                outcome = outcome.lower()
                severity = _OUTCOMES.get(outcome)
                if severity:
                    findings.append(
                        Finding(
                            code=f"{mechanism}_fail",
                            severity=severity,
                            title=f"{mechanism.upper()} {outcome}",
                            detail=(
                                f"The receiving server recorded "
                                f"{mechanism}={outcome} in Authentication-Results."
                            ),
                        )
                    )
        return findings

    return run


def _no_authentication_results(ctx: AnalysisContext) -> list[Finding]:
    if ctx.parsed.authentication_results:
        return []
    return [
        Finding(
            code="no_authentication_results",
            severity="info",
            title="No authentication results recorded",
            detail=(
                "No Authentication-Results header is present, so SPF, DKIM "
                "and DMARC were not recorded by a receiving server and "
                "cannot be assessed from this message."
            ),
        )
    ]


RULES = [
    Rule(
        id="spf_fail",
        name="SPF failure",
        category="authentication",
        rationale=(
            "SPF checks whether the sending server is authorized to send "
            "for the envelope (MAIL FROM) domain, which is not necessarily "
            "the visible From domain. A recorded fail removes one "
            "legitimacy signal; by itself it does not prove the visible "
            "From address is forged."
        ),
        run=_mechanism_failure("spf"),
    ),
    Rule(
        id="dkim_fail",
        name="DKIM failure",
        category="authentication",
        rationale=(
            "DKIM is a cryptographic signature over parts of the message. "
            "A recorded fail means a signature was present but did not "
            "verify - the content changed after signing or the key did not "
            "match. That is not the same as an unsigned message, and much "
            "legitimate mail is unsigned."
        ),
        run=_mechanism_failure("dkim"),
    ),
    Rule(
        id="dmarc_fail",
        name="DMARC failure",
        category="authentication",
        rationale=(
            "DMARC ties SPF and DKIM results to the visible From domain. "
            "A recorded fail means the receiver's alignment check did not "
            "pass - as claimed in this header. Headers inside an uploaded "
            "message can be forged, so treat this as the receiver's "
            "recorded claim, not independently verified fact."
        ),
        run=_mechanism_failure("dmarc"),
    ),
    Rule(
        id="no_authentication_results",
        name="Authentication not recorded",
        category="authentication",
        rationale=(
            "Without a recorded Authentication-Results header, there is no "
            "receiver-side evidence about the sender at all. The other "
            "signals in the report carry the full weight."
        ),
        run=_no_authentication_results,
    ),
]
