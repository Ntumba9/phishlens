"""Header evidence: sender alignment and authentication results."""

from __future__ import annotations

import re

from ..domains import domain_of_address, registered_domain
from ..models import Finding, ParsedEmail

_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*(\w+)", re.IGNORECASE)


def check(msg: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []

    from_domain = domain_of_address(msg.from_header)
    reply_domain = domain_of_address(msg.reply_to)
    if (
        from_domain
        and reply_domain
        and registered_domain(from_domain) != registered_domain(reply_domain)
    ):
        findings.append(
            Finding(
                code="reply_to_mismatch",
                severity="high",
                title="Replies go to a different domain than the sender",
                detail=f"From domain is {from_domain} but Reply-To is {reply_domain}.",
            )
        )

    return_path_domain = domain_of_address(msg.return_path)
    if (
        from_domain
        and return_path_domain
        and registered_domain(from_domain) != registered_domain(return_path_domain)
    ):
        findings.append(
            Finding(
                code="return_path_mismatch",
                severity="medium",
                title="Bounce address (Return-Path) is a different domain",
                detail=(
                    f"From domain is {from_domain} but Return-Path is "
                    f"{return_path_domain}."
                ),
            )
        )

    results = " ".join(msg.authentication_results)
    if results:
        for mech, outcome in _AUTH_RE.findall(results):
            outcome = outcome.lower()
            if outcome in {"fail", "softfail", "permerror", "temperror"}:
                findings.append(
                    Finding(
                        code=f"{mech.lower()}_fail",
                        severity="high" if outcome == "fail" else "medium",
                        title=f"{mech.upper()} {outcome}",
                        detail=(
                            f"Authentication-Results reports "
                            f"{mech.lower()}={outcome}."
                        ),
                    )
                )
    else:
        findings.append(
            Finding(
                code="no_authentication_results",
                severity="info",
                title="No Authentication-Results header present",
                detail=(
                    "The receiving server did not record SPF/DKIM/DMARC "
                    "results, so authentication cannot be assessed here."
                ),
            )
        )

    if not msg.received_chain:
        findings.append(
            Finding(
                code="no_received_headers",
                severity="low",
                title="No Received headers",
                detail=(
                    "The message carries no Received chain, which is unusual "
                    "for mail that crossed real servers."
                ),
            )
        )
    return findings
