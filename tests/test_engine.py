"""End-to-end engine behavior over the full fixture corpus."""

import pytest
from conftest import FIXTURES

from phishlens.engine import analyze, report_to_dict

EXPECTED = {
    "phish_paypa1.eml": "likely_phish",
    "phish_sars.eml": "likely_phish",
    "phish_macro.eml": "likely_phish",
    "phish_bec.eml": "suspicious",
    "legit_newsletter.eml": "no_strong_signals",
    "legit_invoice.eml": "no_strong_signals",
}


@pytest.mark.parametrize("fixture,verdict", sorted(EXPECTED.items()))
def test_fixture_verdicts(fixture, verdict):
    report = analyze((FIXTURES / fixture).read_bytes())
    assert report.verdict == verdict, fixture


def test_phish_fixture_scores_high(phish_raw):
    report = analyze(phish_raw)
    assert report.score >= 50
    severities = [f.severity for f in report.findings]
    assert severities == sorted(severities, key={"high": 0, "medium": 1, "low": 2, "info": 3}.get)


def test_findings_carry_rule_metadata(phish_raw):
    report = analyze(phish_raw)
    for finding in report.findings:
        assert finding.category
        assert finding.why


def test_report_has_iocs_and_route(phish_raw):
    report = analyze(phish_raw)
    assert "secure-paypa1.top" in report.iocs.domains
    assert any("account-verify.top" in url for url in report.iocs.urls)
    assert "verifications@account-review.click" in report.iocs.addresses
    assert len(report.hops) == 1
    assert report.hops[0].from_host == "mail.secure-paypa1.top"


def test_report_serialises_for_the_api(phish_raw):
    data = report_to_dict(analyze(phish_raw))
    assert set(data) >= {
        "verdict", "score", "findings", "links", "attachments", "route", "iocs", "notes",
    }
    assert all(
        {"code", "severity", "category", "title", "detail", "why"} <= set(f)
        for f in data["findings"]
    )
