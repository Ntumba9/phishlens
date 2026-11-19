from phishlens.engine import analyze, report_to_dict
from phishlens.export import render_html_report


def make_case(raw: bytes, **overrides) -> dict:
    report = report_to_dict(analyze(raw))
    report["case_id"] = "testcase1234"
    return {
        "report": report,
        "analyst_verdict": overrides.get("analyst_verdict"),
        "analyst_reason": overrides.get("analyst_reason", ""),
    }


def test_report_contains_core_sections(phish_raw):
    html = render_html_report(make_case(phish_raw))
    for section in ("Findings", "Links", "Attachments", "Relay route",
                    "Indicators of compromise", "Notes"):
        assert section in html
    assert "likely phish" in html.lower()


def test_message_content_is_escaped():
    raw = (
        b"From: a@b.co.za\r\n"
        b"Subject: <script>alert('xss')</script>\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"<img src=x onerror=alert(1)> body text\r\n"
    )
    html = render_html_report(make_case(raw))
    assert "<script>alert('xss')</script>" not in html
    assert "&lt;script&gt;" in html
    assert "<img src=x onerror=alert(1)>" not in html


def test_links_are_defanged_and_not_clickable(phish_raw):
    html = render_html_report(make_case(phish_raw))
    assert "hxxps://" in html
    # No live hyperlinks into the suspicious infrastructure - not in the URL
    # column and not in the shown-anchor-text column (viewers may auto-link).
    assert 'href="https://paypal.com.account-verify.top' not in html
    assert "https://www.paypal.com/security" not in html
    assert "hxxps://www[.]paypal[.]com/security" in html


def test_score_is_labelled_as_heuristic(phish_raw):
    html = render_html_report(make_case(phish_raw))
    assert "(heuristic" in html


def test_trust_boundary_stated_next_to_findings(phish_raw):
    html = render_html_report(make_case(phish_raw))
    assert "can be forged by a sender" in html


def test_analyst_verdict_rendered_when_set(phish_raw):
    html = render_html_report(
        make_case(phish_raw, analyst_verdict="likely_phish",
                  analyst_reason="Client confirmed they never sent it")
    )
    assert "Analyst verdict" in html
    assert "Client confirmed they never sent it" in html
