"""Parse the Received header chain into relay hops.

Received headers are prepended by each relay, so the raw list is
newest-first; hops are returned origin-first. Timestamps come from the
header text itself and are parsed with the stdlib; a hop with an
unparseable timestamp simply carries ``None`` and the route rules note
what that means.
"""

from __future__ import annotations

import re
from datetime import datetime
from email.utils import parsedate_to_datetime

from .models import Hop

_FROM_RE = re.compile(r"\bfrom\s+([^\s;]+)", re.IGNORECASE)
_BY_RE = re.compile(r"\bby\s+([^\s;]+)", re.IGNORECASE)


def _parse_timestamp(header: str) -> datetime | None:
    """The timestamp sits after the final semicolon in a Received header."""
    if ";" not in header:
        return None
    candidate = header.rsplit(";", 1)[1].strip()
    try:
        stamp = parsedate_to_datetime(candidate)
    except (TypeError, ValueError):
        return None
    if stamp is not None and stamp.tzinfo is None:
        # RFC 5322 requires a zone; treat a missing one as unparseable rather
        # than guessing, so delay math never mixes aware and naive values.
        return None
    return stamp


def parse_hops(received_chain: list[str]) -> list[Hop]:
    """Turn raw Received headers (newest-first) into origin-first hops."""
    hops: list[Hop] = []
    ordered = list(reversed(received_chain))
    for index, raw in enumerate(ordered):
        from_match = _FROM_RE.search(raw)
        by_match = _BY_RE.search(raw)
        hops.append(
            Hop(
                index=index,
                raw=raw,
                from_host=from_match.group(1).lower() if from_match else "",
                by_host=by_match.group(1).lower() if by_match else "",
                timestamp=_parse_timestamp(raw),
            )
        )
    return hops


def hop_delays(hops: list[Hop]) -> list[float | None]:
    """Seconds each hop took from the previous one; None when unknown."""
    delays: list[float | None] = [None]
    for previous, current in zip(hops, hops[1:], strict=False):
        if previous.timestamp is None or current.timestamp is None:
            delays.append(None)
        else:
            delays.append((current.timestamp - previous.timestamp).total_seconds())
    return delays
