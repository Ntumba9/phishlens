"""Header alignment rules: who the mail claims to be from vs where it goes."""

from __future__ import annotations

from ..domains import domain_of_address, registered_domain
from ..models import Finding
from .base import AnalysisContext, Rule


def _reply_to_mismatch(ctx: AnalysisContext) -> list[Finding]:
    from_domain = domain_of_address(ctx.parsed.from_header)
    reply_domain = domain_of_address(ctx.parsed.reply_to)
    if (
        from_domain
        and reply_domain
        and registered_domain(from_domain) != registered_domain(reply_domain)
    ):
        return [
            Finding(
                code="reply_to_mismatch",
                severity="high",
                title="Replies go to a different domain than the sender",
                detail=f"From domain is {from_domain} but Reply-To is {reply_domain}.",
            )
        ]
    return []


def _return_path_mismatch(ctx: AnalysisContext) -> list[Finding]:
    from_domain = domain_of_address(ctx.parsed.from_header)
    return_path_domain = domain_of_address(ctx.parsed.return_path)
    if (
        from_domain
        and return_path_domain
        and registered_domain(from_domain) != registered_domain(return_path_domain)
    ):
        return [
            Finding(
                code="return_path_mismatch",
                severity="medium",
                title="Bounce address (Return-Path) is a different domain",
                detail=(
                    f"From domain is {from_domain} but Return-Path is "
                    f"{return_path_domain}."
                ),
            )
        ]
    return []


RULES = [
    Rule(
        id="reply_to_mismatch",
        name="Reply-To domain mismatch",
        category="headers",
        rationale=(
            "A sender whose replies land on a different domain fits the "
            "business-email-compromise pattern: the displayed name looks "
            "right, but the answer goes to someone else's mailbox."
        ),
        run=_reply_to_mismatch,
    ),
    Rule(
        id="return_path_mismatch",
        name="Return-Path domain mismatch",
        category="headers",
        rationale=(
            "The bounce address is set by the sending system. When it does "
            "not match the From domain, the mail may have been sent through "
            "an unrelated service, or the From header may be forged."
        ),
        run=_return_path_mismatch,
    ),
]
