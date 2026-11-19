"""Orchestration: raw email in, analyst report out."""

from __future__ import annotations

from .checks import ALL_CHECKS
from .checks import attachments as attachments_check
from .models import Report
from .parser import parse_email
from .scoring import score_findings, verdict_for

SAFETY_NOTE = (
    "PhishLens never opens, resolves or fetches the links in an email. "
    "Every finding comes from the message itself."
)

HUMAN_REVIEW_NOTE = (
    "This report is triage for a human analyst. 'No strong signals' does "
    "not mean safe; treat unexpected mail with care either way."
)


def analyze(raw: bytes) -> Report:
    parsed = parse_email(raw)

    findings = []
    for check in ALL_CHECKS:
        findings.extend(check(parsed))
    findings.extend(attachments_check.check(parsed))

    # High severity first, then medium, low, info.
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: order.get(f.severity, 4))

    score = score_findings(findings)
    return Report(
        subject=parsed.subject,
        from_header=parsed.from_header,
        verdict=verdict_for(score),
        score=score,
        findings=findings,
        links=parsed.links,
        attachment_names=parsed.attachment_names,
        notes=[SAFETY_NOTE, HUMAN_REVIEW_NOTE],
    )


def report_to_dict(report: Report) -> dict:
    return {
        "subject": report.subject,
        "from": report.from_header,
        "verdict": report.verdict,
        "score": report.score,
        "findings": [
            {
                "code": f.code,
                "severity": f.severity,
                "title": f.title,
                "detail": f.detail,
            }
            for f in report.findings
        ],
        "links": [
            {"url": l.url, "anchor_text": l.anchor_text, "source": l.source}
            for l in report.links
        ],
        "attachments": report.attachment_names,
        "notes": report.notes,
    }
