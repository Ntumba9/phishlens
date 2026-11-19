from phishlens.ioc import defang, extract_iocs, iocs_as_text, refang
from phishlens.parser import parse_email


def test_extracts_and_dedupes(phish_raw):
    iocs = extract_iocs(parse_email(phish_raw), parse_email(phish_raw).attachments)
    assert "secure-paypa1.top" in iocs.domains
    assert "account-verify.top" in iocs.domains
    assert len(iocs.domains) == len(set(iocs.domains))
    assert "verifications@account-review.click" in iocs.addresses
    assert any(url.startswith("https://paypal.com.account-verify.top") for url in iocs.urls)


def test_ip_literals_land_in_ips_not_domains():
    raw = (
        b"From: a@b.co.za\r\nSubject: x\r\nContent-Type: text/plain\r\n\r\n"
        b"see http://192.0.2.44/login now\r\n"
    )
    iocs = extract_iocs(parse_email(raw), [])
    assert "192.0.2.44" in iocs.ips
    assert "192.0.2.44" not in iocs.domains


def test_attachment_hashes_are_iocs():
    from conftest import FIXTURES

    parsed = parse_email((FIXTURES / "legit_invoice.eml").read_bytes())
    iocs = extract_iocs(parsed, parsed.attachments)
    assert iocs.file_hashes[0]["filename"] == "invoice-1042.pdf"
    assert len(iocs.file_hashes[0]["sha256"]) == 64


def test_defang_roundtrip():
    url = "https://paypal.com.account-verify.top/login"
    assert defang(url) == "hxxps://paypal[.]com[.]account-verify[.]top/login"
    assert refang(defang(url)) == url
    assert defang("user@example.com") == "user[at]example[.]com"


def test_iocs_as_text_is_defanged_by_default(phish_raw):
    parsed = parse_email(phish_raw)
    text = iocs_as_text(extract_iocs(parsed, parsed.attachments))
    assert "hxxps://" in text
    assert "https://" not in text
    assert "[Domains]" in text
