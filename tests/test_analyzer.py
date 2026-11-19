from phishlens.analyzer import analyze, report_to_dict


def test_phish_fixture_scores_likely_phish(phish_raw):
    report = analyze(phish_raw)
    assert report.verdict == "likely_phish"
    assert report.score >= 50
    severities = [f.severity for f in report.findings]
    assert severities == sorted(severities, key={"high": 0, "medium": 1, "low": 2, "info": 3}.get)


def test_legit_fixture_has_no_strong_signals(legit_raw):
    report = analyze(legit_raw)
    assert report.verdict == "no_strong_signals"
    assert report.score < 20


def test_report_serialises_for_the_api(phish_raw):
    data = report_to_dict(analyze(phish_raw))
    assert set(data) >= {"verdict", "score", "findings", "links", "notes"}
    assert all({"code", "severity", "title", "detail"} <= set(f) for f in data["findings"])
