"""Parse raw email source (.eml or pasted headers+body) with the stdlib.

Only the standard library `email` package is used: it is battle-tested on
hostile input and keeps the attack surface small.
"""

from __future__ import annotations

from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr

from .extract import extract_links
from .models import ParsedEmail


def _walk_bodies(msg) -> tuple[str, str, list[str]]:
    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        filename = part.get_filename()
        if filename:
            attachments.append(filename)
            continue
        if ctype == "text/plain":
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            text_parts.append(payload.decode(charset, errors="replace"))
        elif ctype == "text/html":
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            html_parts.append(payload.decode(charset, errors="replace"))
    return "\n".join(text_parts), "\n".join(html_parts), attachments


def parse_email(raw: bytes) -> ParsedEmail:
    """Parse raw message bytes into a ParsedEmail. Never raises on bad input."""
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    parsed = ParsedEmail()

    headers: dict[str, list[str]] = {}
    for name, value in msg.items():
        headers.setdefault(name.lower(), []).append(str(value))
    parsed.raw_headers = headers

    parsed.subject = str(msg.get("Subject", ""))
    # getaddresses handles "Name <addr>" and multiple values.
    parsed.from_header = ", ".join(
        addr for _, addr in getaddresses(headers.get("from", [])) if addr
    )
    parsed.reply_to = ", ".join(
        addr for _, addr in getaddresses(headers.get("reply-to", [])) if addr
    )
    # Return-Path is a single address, often in angle brackets.
    parsed.return_path = parseaddr(headers.get("return-path", [""])[0])[1]
    parsed.date = headers.get("date", [""])[0]
    parsed.message_id = headers.get("message-id", [""])[0]
    parsed.authentication_results = headers.get("authentication-results", [])
    parsed.received_chain = headers.get("received", [])

    text_body, html_body, attachments = _walk_bodies(msg)
    parsed.text_body = text_body
    parsed.html_body = html_body
    parsed.attachment_names = attachments
    parsed.links = extract_links(text_body, html_body)
    return parsed


def parse_email_text(raw: str) -> ParsedEmail:
    """Parse a pasted raw message string."""
    return parse_email(raw.encode("utf-8", errors="replace"))
