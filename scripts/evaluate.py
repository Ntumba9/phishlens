#!/usr/bin/env python3
"""Evaluate the rule engine against the fixture corpus.

IMPORTANT - read this before quoting the numbers:
The corpus is six hand-written synthetic messages in tests/fixtures,
labelled by filename prefix (phish_ / legit_). It exists to stop
regressions in development. Precision and recall over six synthetic
messages are NOT measured real-world accuracy; a real evaluation needs a
large, labelled, current corpus of actual mail.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from phishlens.engine import analyze  # noqa: E402

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def main() -> int:
    rows = []
    for path in sorted(FIXTURES.glob("*.eml")):
        expected = "phish" if path.name.startswith("phish_") else "legit"
        report = analyze(path.read_bytes())
        flagged = report.verdict in {"likely_phish", "suspicious"}
        rows.append((path.name, expected, report.verdict, report.score, flagged))

    print(f"{'fixture':<26}{'expected':<10}{'verdict':<20}{'score':<7}flagged")
    for name, expected, verdict, score, flagged in rows:
        print(f"{name:<26}{expected:<10}{verdict:<20}{score:<7}{flagged}")

    tp = sum(1 for _, e, _, _, f in rows if e == "phish" and f)
    fn = sum(1 for _, e, _, _, f in rows if e == "phish" and not f)
    fp = sum(1 for _, e, _, _, f in rows if e == "legit" and f)
    tn = sum(1 for _, e, _, _, f in rows if e == "legit" and not f)
    total = len(rows)
    print()
    print(f"corpus: {total} synthetic fixtures "
          f"({tp + fn} phishing, {fp + tn} legitimate), labelled by filename")
    print(f"flagged phishing: {tp}/{tp + fn}   false flags: {fp}/{fp + tn}")
    print()
    print("NOTE: synthetic regression corpus only. These numbers say nothing")
    print("about accuracy on real mail.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
