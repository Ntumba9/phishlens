from phishlens.checks import attachments, headers, links, lookalike, urgency
from phishlens.parser import parse_email


def codes(findings):
    return {f.code for f in findings}


def test_headers_catch_reply_to_and_auth_failures(phish_raw):
    found = codes(headers.check(parse_email(phish_raw)))
    assert "reply_to_mismatch" in found
    assert "spf_fail" in found
    assert "dkim_fail" in found
    assert "dmarc_fail" in found


def test_headers_quiet_on_aligned_legit_mail(legit_raw):
    found = codes(headers.check(parse_email(legit_raw)))
    assert "reply_to_mismatch" not in found
    assert not any(c.endswith("_fail") for c in found)


def test_links_catch_anchor_mismatch(phish_raw):
    found = codes(links.check(parse_email(phish_raw)))
    assert "anchor_href_mismatch" in found
    assert "risky_tld" in found  # the .top link


def test_lookalike_catches_brand_in_foreign_domain(phish_raw):
    found = codes(lookalike.check(parse_email(phish_raw)))
    assert "brand_in_foreign_domain" in found  # paypal.com.account-verify.top
    assert "leetspeak_lookalike" in found  # secure-paypa1.top reads as paypal


def test_lookalike_quiet_on_real_brand(legit_raw):
    assert lookalike.check(parse_email(legit_raw)) == []


def test_urgency_catches_pressure_and_credential_bait(phish_raw):
    found = codes(urgency.check(parse_email(phish_raw)))
    assert "pressure_language" in found
    assert "credential_bait" in found


def test_attachments_flag_risky_names():
    raw = (
        b"From: a@b.co.za\r\nSubject: invoice\r\n"
        b"Content-Type: multipart/mixed; boundary=X\r\n\r\n"
        b"--X\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n"
        b"--X\r\nContent-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="statement.pdf.exe"\r\n\r\n'
        b"MZ\r\n--X--\r\n"
    )
    found = codes(attachments.check(parse_email(raw)))
    assert "executable_attachment" in found
