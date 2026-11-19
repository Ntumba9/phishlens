"""CLI: python -m phishlens <message.eml> prints the report as JSON.

--report writes a self-contained inert HTML report next to the terminal
output; --iocs prints defanged indicators only.
"""

from __future__ import annotations

import argparse
import json

from .engine import analyze, report_to_dict
from .export import render_html_report
from .ioc import iocs_as_text


def main() -> int:
    parser = argparse.ArgumentParser(prog="phishlens")
    parser.add_argument("message", help="path to a .eml file")
    parser.add_argument("--report", metavar="OUT.html", help="write an HTML report")
    parser.add_argument("--iocs", action="store_true", help="print defanged IOCs only")
    args = parser.parse_args()

    with open(args.message, "rb") as handle:
        data = handle.read()

    report = analyze(data)
    report_dict = report_to_dict(report)

    if args.iocs:
        print(iocs_as_text(report.iocs, defanged=True))
        return 0
    if args.report:
        case = {"report": report_dict, "analyst_verdict": None, "analyst_reason": ""}
        with open(args.report, "w", encoding="utf-8") as handle:
            handle.write(render_html_report(case))
    print(json.dumps(report_dict, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
