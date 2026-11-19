"""Link evidence: what the URLs themselves show, without ever visiting them."""

from __future__ import annotations

from ..domains import (
    domain_of_address,
    host_of,
    is_ip_literal,
    registered_domain,
    subdomain_depth,
)
from ..models import Finding, ParsedEmail

_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc",
}

_RISKY_TLDS = {
    "zip", "mov", "top", "xyz", "click", "country", "kim", "science",
    "work", "support", "live", "buzz", "rest", "quest", "monster", "cfd",
}


def _looks_like_domain(text: str) -> str | None:
    """If anchor text looks like a domain/URL, return its registered domain."""
    text = (text or "").strip().lower()
    if not text:
        return None
    if " " in text:
        return None
    candidate = text if text.startswith(("http://", "https://")) else f"https://{text}"
    host = host_of(candidate)
    if not host or "." not in host:
        return None
    # For bare text (no scheme), a slash means it was prose, not a domain.
    if not text.startswith(("http://", "https://")) and "/" in text:
        return None
    return registered_domain(host)


def check(msg: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    from_domain = registered_domain(domain_of_address(msg.from_header))

    for link in msg.links:
        host = host_of(link.url)
        if not host:
            findings.append(
                Finding(
                    code="unparseable_url",
                    severity="medium",
                    title="A link could not be parsed",
                    detail=f"URL: {link.url}",
                )
            )
            continue

        reg = registered_domain(host)

        if is_ip_literal(host):
            findings.append(
                Finding(
                    code="ip_literal_link",
                    severity="high",
                    title="Link points at a raw IP address",
                    detail=f"{link.url} — real services use domain names.",
                )
            )

        if "@" in link.url.split("/", 3)[2]:
            findings.append(
                Finding(
                    code="userinfo_in_url",
                    severity="high",
                    title="URL hides its real host behind an @ sign",
                    detail=(
                        f"{link.url} — everything before the @ is ignored "
                        "by the browser."
                    ),
                )
            )

        if host.startswith("xn--") or ".xn--" in host:
            findings.append(
                Finding(
                    code="punycode_link",
                    severity="high",
                    title="Link uses punycode (possible lookalike characters)",
                    detail=f"{link.url} — punycode can render as lookalike letters.",
                )
            )

        if reg in _SHORTENERS:
            findings.append(
                Finding(
                    code="shortened_link",
                    severity="medium",
                    title="Link hides behind a URL shortener",
                    detail=f"{link.url} — the destination cannot be inspected.",
                )
            )

        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in _RISKY_TLDS:
            findings.append(
                Finding(
                    code="risky_tld",
                    severity="low",
                    title=f"Link uses a .{tld} domain",
                    detail=(
                        f"{link.url} — .{tld} domains are cheap and common "
                        "in phishing."
                    ),
                )
            )

        if subdomain_depth(host) >= 3:
            findings.append(
                Finding(
                    code="deep_subdomains",
                    severity="low",
                    title="Link has unusually deep subdomains",
                    detail=f"{link.url} — padding subdomains is a common disguise.",
                )
            )

        if link.anchor_text:
            anchor_domain = _looks_like_domain(link.anchor_text)
            if anchor_domain and anchor_domain != reg:
                findings.append(
                    Finding(
                        code="anchor_href_mismatch",
                        severity="high",
                        title="Link text shows one domain but goes to another",
                        detail=(
                            f'Text says "{link.anchor_text}" but the link '
                            f"points to {host}."
                        ),
                    )
                )

        if (
            from_domain
            and reg
            and reg == from_domain
            and link.url.startswith("http://")
        ):
            findings.append(
                Finding(
                    code="sender_domain_insecure_link",
                    severity="low",
                    title="Link to the sender's own domain is not HTTPS",
                    detail=f"{link.url}",
                )
            )
    return findings
