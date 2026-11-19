"""Individual evidence checks. Each returns zero or more Findings."""

from . import headers, links, lookalike, urgency

ALL_CHECKS = [
    headers.check,
    links.check,
    lookalike.check,
    urgency.check,
]
