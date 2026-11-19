"""Export a case as a self-contained, inert HTML analyst report.

Every value from the email is HTML-escaped. The output carries no
JavaScript, no external resources and no live links: it is safe to open,
archive and attach to a ticket.
"""

from __future__ import annotations

import html
import re

from .ioc import defang

_URL_IN_TEXT_RE = re.compile(r"https?://[^\s\"'<>]+")

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

_STYLE = """
body { font-family: Georgia, 'Times New Roman', serif; color: #1a1a1a;
       max-width: 800px; margin: 2rem auto; padding: 0 1rem; }
h1 { font-size: 1.4rem; border-bottom: 2px solid #1a1a1a; padding-bottom: .4rem; }
h2 { font-size: 1rem; margin-top: 1.8rem; text-transform: uppercase;
     letter-spacing: .06em; color: #444; }
table { width: 100%; border-collapse: collapse; font-size: .85rem; }
th, td { text-align: left; padding: .4rem .5rem; border-bottom: 1px solid #ddd;
         vertical-align: top; }
th { color: #666; font-size: .75rem; text-transform: uppercase; }
.verdict { display: inline-block; padding: .3rem .9rem; border-radius: 4px;
           font-weight: bold; text-transform: uppercase; font-size: .85rem; }
.likely_phish { background: #c0392b; color: #fff; }
.suspicious { background: #b7770d; color: #fff; }
.no_strong_signals { background: #2471a3; color: #fff; }
.sev { font-weight: bold; text-transform: uppercase; font-size: .72rem; }
.sev.high { color: #c0392b; } .sev.medium { color: #b7770d; }
.sev.low { color: #2471a3; } .sev.info { color: #666; }
.meta, .notes { color: #555; font-size: .85rem; }
code { font-family: 'Courier New', monospace; font-size: .82rem;
       word-break: break-all; }
.why { color: #555; font-size: .8rem; font-style: italic; }
@media print { body { margin: 0; } }
"""


def _esc(value) -> str:
    return html.escape("" if value is None else str(value))


def _esc_inert(value) -> str:
    """Escape, and defang any URLs embedded in message-derived free text.

    Finding details and subjects can quote URLs from the email; some viewers
    auto-link bare URLs, so they are defanged as well as escaped.
    """
    text = "" if value is None else str(value)
    return html.escape(_URL_IN_TEXT_RE.sub(lambda m: defang(m.group(0)), text))


def _finding_rows(findings: list[dict]) -> str:
    if not findings:
        return "<tr><td colspan='4'>No findings.</td></tr>"
    rows = []
    for f in findings:
        reference = f" ({_esc(f['reference'])})" if f.get("reference") else ""
        rows.append(
            "<tr>"
            f"<td class='sev {_esc(f['severity'])}'>{_esc(f['severity'])}</td>"
            f"<td>{_esc(f['title'])}</td>"
            f"<td>{_esc_inert(f['detail'])}</td>"
            f"<td class='why'>{_esc(f.get('why', ''))}{reference}</td>"
            "</tr>"
        )
    return "".join(rows)


def render_html_report(case: dict) -> str:
    """Render a stored case (store.get_case shape) as a full HTML document."""
    report = case["report"]
    verdict = report.get("verdict", "")
    analyst = case.get("analyst_verdict")
    analyst_line = ""
    if analyst:
        analyst_line = (
            f"<p><strong>Analyst verdict:</strong> {_esc(analyst)}"
            + (
                f" &mdash; {_esc(case.get('analyst_reason', ''))}"
                if case.get("analyst_reason")
                else ""
            )
            + "</p>"
        )

    findings = sorted(
        report.get("findings", []),
        key=lambda f: _SEVERITY_ORDER.get(f.get("severity", ""), 4),
    )

    links = report.get("links", [])
    link_rows = "".join(
        f"<tr><td><code>{_esc(defang(link['url']))}</code></td>"
        f"<td>{_esc(defang(link.get('anchor_text') or ''))}</td></tr>"
        for link in links
    ) or "<tr><td colspan='2'>No links found.</td></tr>"

    attachments = report.get("attachments", [])
    attachment_rows = "".join(
        f"<tr><td>{_esc(a['filename'])}</td><td>{_esc(a['detected_type'])}</td>"
        f"<td>{a['size']}</td><td><code>{_esc(a['sha256'])}</code></td></tr>"
        for a in attachments
    ) or "<tr><td colspan='4'>No attachments.</td></tr>"

    route = report.get("route", [])
    route_rows = "".join(
        f"<tr><td>{h['index']}</td><td><code>{_esc(h.get('from_host') or 'unknown')}</code></td>"
        f"<td><code>{_esc(h.get('by_host') or 'unknown')}</code></td>"
        f"<td>{_esc(h.get('timestamp') or 'unknown')}</td></tr>"
        for h in route
    ) or "<tr><td colspan='4'>No Received chain in this message.</td></tr>"

    iocs = report.get("iocs", {})
    ioc_items = "".join(
        f"<tr><td>{label}</td><td><code>{_esc(defang(value))}</code></td></tr>"
        for label, key in (
            ("Domain", "domains"), ("URL", "urls"),
            ("IP", "ips"), ("Address", "addresses"),
        )
        for value in iocs.get(key, [])
    )
    for entry in iocs.get("file_hashes", []):
        ioc_items += (
            f"<tr><td>SHA-256</td><td><code>{_esc(entry['sha256'])}"
            f"</code> ({_esc(entry['filename'])})</td></tr>"
        )
    if not ioc_items:
        ioc_items = "<tr><td colspan='2'>No indicators extracted.</td></tr>"

    notes = "<br>".join(_esc(n) for n in report.get("notes", []))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>PhishLens report - {_esc(report.get('subject', ''))}</title>
<style>{_STYLE}</style>
</head>
<body>
<h1>PhishLens triage report</h1>
<p class="meta">
Case {_esc(report.get('case_id', ''))} &middot; analyzed {_esc(report.get('created_at', ''))}<br>
Subject: {_esc_inert(report.get('subject', ''))}<br>
From: {_esc(report.get('from', ''))}
</p>
<p><span class="verdict {_esc(verdict)}">{_esc(verdict.replace('_', ' '))}</span>
&nbsp; Score {report.get('score', 0)}/100 (heuristic, not a calibrated probability)</p>
<p class="meta">Authentication findings repeat what the receiving server recorded in this
message's own headers. Those headers can be forged by a sender; they are
claims, not independently verified facts.</p>
{analyst_line}

<h2>Findings</h2>
<table>
<thead><tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>Why it matters</th></tr></thead>
<tbody>{_finding_rows(findings)}</tbody>
</table>

<h2>Links (defanged, never opened)</h2>
<table>
<thead><tr><th>URL</th><th>Shown text</th></tr></thead>
<tbody>{link_rows}</tbody>
</table>

<h2>Attachments (metadata and hashes only)</h2>
<table>
<thead><tr><th>Name</th><th>Detected type</th><th>Bytes</th><th>SHA-256</th></tr></thead>
<tbody>{attachment_rows}</tbody>
</table>

<h2>Relay route</h2>
<table>
<thead><tr><th>Hop</th><th>From</th><th>By</th><th>Timestamp</th></tr></thead>
<tbody>{route_rows}</tbody>
</table>

<h2>Indicators of compromise (defanged)</h2>
<table>
<thead><tr><th>Type</th><th>Indicator</th></tr></thead>
<tbody>{ioc_items}</tbody>
</table>

<h2>Notes</h2>
<p class="notes">{notes}</p>
</body>
</html>
"""


_SEVERITY_ORDER_TEXT = {"high": 0, "medium": 1, "low": 2, "info": 3}


def render_handoff(case: dict) -> str:
    """Plain-text incident handoff for an analyst to copy into a ticket.

    Copy-only by design: nothing here sends anything. Every indicator is
    defanged, and URLs quoted inside finding details are defanged too, so
    the pasted text carries no live links.
    """
    report = case["report"]
    lines = [
        "PhishLens incident handoff",
        f"Case: {report.get('case_id', '')} (analyzed {report.get('created_at', '')})",
        f"Subject: {report.get('subject', '')}",
        f"From: {report.get('from', '')}",
        "",
        f"Verdict: {report.get('verdict', '').replace('_', ' ')} "
        f"(heuristic score {report.get('score', 0)}/100, not a calibrated probability)",
    ]
    if case.get("analyst_verdict"):
        line = f"Analyst verdict: {case['analyst_verdict'].replace('_', ' ')}"
        if case.get("analyst_reason"):
            line += f" - {case['analyst_reason']}"
        lines.append(line)
    lines.append("")

    findings = sorted(
        report.get("findings", []),
        key=lambda f: _SEVERITY_ORDER_TEXT.get(f.get("severity", ""), 4),
    )
    lines.append("Findings:")
    if findings:
        for f in findings:
            detail = _URL_IN_TEXT_RE.sub(lambda m: defang(m.group(0)), f["detail"])
            lines.append(f"- [{f['severity'].upper()}] {f['title']}: {detail}")
    else:
        lines.append("- None. That describes this message only; it is not proof of safety.")
    lines.append("")

    iocs = report.get("iocs", {})
    lines.append("Indicators (defanged):")
    any_ioc = False
    for label, key in (
        ("Domain", "domains"), ("URL", "urls"),
        ("IP", "ips"), ("Address", "addresses"),
    ):
        for value in iocs.get(key, []):
            any_ioc = True
            lines.append(f"- {label}: {defang(value)}")
    for entry in iocs.get("file_hashes", []):
        any_ioc = True
        lines.append(f"- SHA-256: {entry['sha256']} ({entry['filename']})")
    if not any_ioc:
        lines.append("- None extracted.")
    lines.append("")
    lines.append(
        "Note: recorded authentication results repeat what the receiving server "
        "wrote in this message's own headers and can be forged by the sender."
    )
    return "\n".join(lines) + "\n"
