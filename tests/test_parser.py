from phishlens.parser import parse_email


def test_parses_headers_and_bodies(phish_raw):
    msg = parse_email(phish_raw)
    assert msg.subject == "Urgent: your account has been suspended"
    assert msg.from_header == "no-reply@secure-paypa1.top"
    assert msg.reply_to == "verifications@account-review.click"
    assert msg.return_path == "bounce@secure-paypa1.top"
    assert msg.authentication_results
    assert "unusual activity" in msg.text_body.lower()
    assert "<html>" in msg.html_body.lower()


def test_extracts_links_from_text_and_html(phish_raw):
    msg = parse_email(phish_raw)
    urls = {link.url for link in msg.links}
    assert "https://paypal.com.account-verify.top/login" in urls
    # The HTML copy carries the misleading anchor text.
    html_link = next(link for link in msg.links if link.source == "html")
    assert html_link.anchor_text == "https://www.paypal.com/security"


def test_legit_message_parses_cleanly(legit_raw):
    msg = parse_email(legit_raw)
    assert msg.from_header == "noreply@github.com"
    assert not msg.reply_to
    assert len(msg.links) == 2


def test_attachment_metadata_and_hashes():
    from conftest import FIXTURES

    msg = parse_email((FIXTURES / "legit_invoice.eml").read_bytes())
    assert len(msg.attachments) == 1
    attachment = msg.attachments[0]
    assert attachment.filename == "invoice-1042.pdf"
    assert attachment.detected_type == "PDF document"
    assert len(attachment.sha256) == 64
    assert not attachment.truncated


def test_garbage_input_does_not_raise():
    msg = parse_email(b"\xff\xfe not an email \x00 at all")
    assert msg.subject == ""
    assert isinstance(msg.links, list)
    assert isinstance(msg.attachments, list)
