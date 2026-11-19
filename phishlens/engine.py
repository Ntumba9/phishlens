"""Orchestration: raw email in, analyst report out."""

from __future__ import annotations

from datetime import datetime, timezone

from .ioc import extract_iocs
from .models import Report
from .parser import parse_email
from .received import parse_hops
from .rules import RULES, AnalysisContext
from .scoring import score_findings, verdict_for

SAFETY_NOTE = (
    "PhishLens never opens, resolves or fetches the links in an email. "
    "Every finding comes from the message itself."
)

HUMAN_REVIEW_NOTE = (
    "This report is triage for a human analyst. 'No strong signals' does "
    "not mean safe; treat unexpected mail with care either way."
)

AUTH_NOTE = (
    "Authentication findings report what the receiving server recorded in "
    "Authentication-Results. PhishLens does not re-verify SPF, DKIM or "
    "DMARC itself."
)


def analyze(raw: bytes) -> Report:
    """Analyze one raw message and return the full analyst report."""
    parsed = parse_email(raw)
    hops = parse_hops(parsed.received_chain)
    context = AnalysisContext(parsed=parsed, hops=hops)

    findings = []
    for rule in RULES:
        for finding in rule.run(context):
            finding.category = rule.category
            finding.why = rule.rationale
            finding.reference = rule.reference
            findings.append(finding)

    # The same signal can fire on several copies of one link (HTML part,
    # text part); show each distinct piece of evidence once.
    seen: set[tuple[str, str]] = set()
    unique = []
    for finding in findings:
        key = (finding.code, finding.detail)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    findings = unique

    # High severity first, then medium, low, info.
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: order.get(f.severity, 4))

    score = score_findings(findings)
    return Report(
        subject=parsed.subject,
        from_header=parsed.from_header,
        verdict=verdict_for(score),
        score=score,
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        findings=findings,
        links=parsed.links,
        attachments=parsed.attachments,
        hops=hops,
        iocs=extract_iocs(parsed, parsed.attachments),
        notes=[SAFETY_NOTE, HUMAN_REVIEW_NOTE, AUTH_NOTE],
    )


def report_to_dict(report: Report) -> dict:
    """The report as a JSON-ready dict; also the shape cases are stored as."""
    return {
        "case_id": report.case_id,
        "created_at": report.created_at,
        "subject": report.subject,
        "from": report.from_header,
        "verdict": report.verdict,
        "score": report.score,
        "findings": [
            {
                "code": f.code,
                "severity": f.severity,
                "category": f.category,
                "title": f.title,
                "detail": f.detail,
                "why": f.why,
                "reference": f.reference,
            }
            for f in report.findings
        ],
        "links": [
            {"url": link.url, "anchor_text": link.anchor_text, "source": link.source}
            for link in report.links
        ],
        "attachments": [
            {
                "filename": a.filename,
                "content_type": a.content_type,
                "size": a.size,
                "md5": a.md5,
                "sha256": a.sha256,
                "detected_type": a.detected_type,
                "truncated": a.truncated,
            }
            for a in report.attachments
        ],
        "route": [
            {
                "index": h.index,
                "from_host": h.from_host,
                "by_host": h.by_host,
                "timestamp": h.timestamp.isoformat() if h.timestamp else None,
                "raw": h.raw,
            }
            for h in report.hops
        ],
        "iocs": {
            "domains": report.iocs.domains,
            "urls": report.iocs.urls,
            "ips": report.iocs.ips,
            "addresses": report.iocs.addresses,
            "file_hashes": report.iocs.file_hashes,
        },
        "notes": report.notes,
    }
