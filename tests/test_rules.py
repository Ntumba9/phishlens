"""Registry integrity and per-rule behavior against the fixtures."""


from phishlens.parser import parse_email
from phishlens.received import parse_hops
from phishlens.rules import RULES, RULES_BY_ID, AnalysisContext


def run_rules(raw: bytes):
    parsed = parse_email(raw)
    ctx = AnalysisContext(parsed=parsed, hops=parse_hops(parsed.received_chain))
    return {rule.id: rule.run(ctx) for rule in RULES}


def codes(results):
    return {f.code for findings in results.values() for f in findings}


def test_registry_ids_are_unique_and_complete():
    assert len(RULES) == len(RULES_BY_ID)
    for rule in RULES:
        assert rule.id and rule.name and rule.category and rule.rationale


def test_every_finding_carries_its_rule_id(phish_raw):
    for rule_id, findings in run_rules(phish_raw).items():
        for finding in findings:
            assert finding.code == rule_id


def test_headers_catch_reply_to_mismatch(phish_raw):
    found = codes(run_rules(phish_raw))
    assert "reply_to_mismatch" in found


def test_authentication_failures_recorded(phish_raw):
    found = codes(run_rules(phish_raw))
    assert {"spf_fail", "dkim_fail", "dmarc_fail"} <= found


def test_authentication_absent_is_reported_as_unverified(legit_raw):
    raw = legit_raw.replace(b"Authentication-Results:", b"X-Stripped-Auth:", 1)
    found = codes(run_rules(raw))
    assert "no_authentication_results" in found
    assert not any(c.endswith("_fail") for c in found)


def test_links_catch_anchor_mismatch_and_risky_tld(phish_raw):
    found = codes(run_rules(phish_raw))
    assert "anchor_href_mismatch" in found
    assert "risky_tld" in found


def test_lookalike_catches_brand_and_leetspeak(phish_raw):
    found = codes(run_rules(phish_raw))
    assert "brand_in_foreign_domain" in found
    assert "leetspeak_lookalike" in found


def test_lookalike_quiet_on_real_brand(legit_raw):
    results = run_rules(legit_raw)
    for rule_id in ("brand_in_foreign_domain", "leetspeak_lookalike", "typo_lookalike"):
        assert results[rule_id] == []


def test_language_catches_pressure_and_credential_bait(phish_raw):
    found = codes(run_rules(phish_raw))
    assert "pressure_language" in found
    assert "credential_bait" in found


def test_bec_fixture_caught_by_reply_to_and_language():
    from conftest import FIXTURES

    found = codes(run_rules((FIXTURES / "phish_bec.eml").read_bytes()))
    assert "reply_to_mismatch" in found
    assert "pressure_language" in found


def test_magic_bytes_catch_renamed_executable():
    from conftest import FIXTURES

    found = codes(run_rules((FIXTURES / "phish_macro.eml").read_bytes()))
    assert "executable_content" in found
    assert "attachment_type_mismatch" in found
    # The .pdf filename alone is innocent: the name rule must stay quiet.
    assert "executable_attachment" not in found


def test_out_of_order_received_chain_flagged():
    from conftest import FIXTURES

    found = codes(run_rules((FIXTURES / "phish_macro.eml").read_bytes()))
    assert "relay_clock_skew" in found


def test_legit_invoice_is_clean():
    from conftest import FIXTURES

    found = codes(run_rules((FIXTURES / "legit_invoice.eml").read_bytes()))
    assert not found - {"no_authentication_results"}
