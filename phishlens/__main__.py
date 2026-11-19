"""CLI: python -m phishlens <message.eml> prints the report as JSON."""

from __future__ import annotations

import json
import sys

from .analyzer import analyze, report_to_dict


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] in {"-h", "--help"}:
        print("usage: python -m phishlens <message.eml>", file=sys.stderr)
        return 2
    with open(argv[1], "rb") as handle:
        data = handle.read()
    print(json.dumps(report_to_dict(analyze(data)), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
