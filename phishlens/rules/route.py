"""Route rules: the relay path recorded in the Received chain."""

from __future__ import annotations

from ..models import Finding
from ..received import hop_delays
from .base import AnalysisContext, Rule

_SLOW_RELAY_SECONDS = 3600  # a hop taking over an hour is worth a look


def _no_received(ctx: AnalysisContext) -> list[Finding]:
    if ctx.parsed.received_chain:
        return []
    return [
        Finding(
            code="no_received_headers",
            severity="low",
            title="No Received headers",
            detail=(
                "The message carries no Received chain, which is unusual "
                "for mail that crossed real servers."
            ),
        )
    ]


def _relay_delay(ctx: AnalysisContext) -> list[Finding]:
    findings: list[Finding] = []
    delays = hop_delays(ctx.hops)
    for hop, delay in zip(ctx.hops, delays, strict=False):
        if delay is not None and delay > _SLOW_RELAY_SECONDS:
            findings.append(
                Finding(
                    code="relay_delay",
                    severity="low",
                    title="Unusually slow relay hop",
                    detail=(
                        f"Hop {hop.index} sat for {int(delay // 60)} minutes "
                        f"between {hop.from_host or 'unknown'} and "
                        f"{hop.by_host or 'unknown'}. Direct delivery is "
                        "usually seconds."
                    ),
                )
            )
    return findings


def _clock_skew(ctx: AnalysisContext) -> list[Finding]:
    findings: list[Finding] = []
    delays = hop_delays(ctx.hops)
    for hop, delay in zip(ctx.hops, delays, strict=False):
        if delay is not None and delay < 0:
            findings.append(
                Finding(
                    code="relay_clock_skew",
                    severity="medium",
                    title="Received timestamps are out of order",
                    detail=(
                        f"Hop {hop.index} is stamped earlier than the hop "
                        "before it. Relay clocks can drift, but forged "
                        "chains often get the order wrong."
                    ),
                )
            )
    return findings


RULES = [
    Rule(
        id="no_received_headers",
        name="Missing Received chain",
        category="route",
        rationale=(
            "Every real relay prepends a Received header. A message with "
            "none was hand-assembled or stripped, so nothing about its "
            "origin can be checked."
        ),
        run=_no_received,
    ),
    Rule(
        id="relay_delay",
        name="Slow relay hop",
        category="route",
        rationale=(
            "Long holds between relays can fit mail queued on an "
            "intermediate host rather than delivered directly. Neither "
            "proof nor innocence on its own."
        ),
        run=_relay_delay,
    ),
    Rule(
        id="relay_clock_skew",
        name="Out-of-order relay timestamps",
        category="route",
        rationale=(
            "A chain whose timestamps run backwards means a misconfigured "
            "clock or a forged chain; either way the route as written "
            "cannot be relied on."
        ),
        run=_clock_skew,
    ),
]
