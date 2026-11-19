"""Link rules: what the URLs themselves show, without ever visiting them."""

from __future__ import annotations

from ..domains import (
    domain_of_address,
    host_of,
    is_ip_literal,
    registered_domain,
    subdomain_depth,
)
from ..models import Finding, Link
from .base import AnalysisContext, Rule

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
    if not text or " " in text:
        return None
    candidate = text if text.startswith(("http://", "https://")) else f"https://{text}"
    host = host_of(candidate)
    if not host or "." not in host:
        return None
    # For bare text (no scheme), a slash means it was prose, not a domain.
    if not text.startswith(("http://", "https://")) and "/" in text:
        return None
    return registered_domain(host)


def _each_link(ctx: AnalysisContext, check) -> list[Finding]:
    """Run a per-link predicate over every link, collecting findings."""
    parsed = ctx.parsed
    findings: list[Finding] = []
    from_domain = registered_domain(domain_of_address(parsed.from_header))
    for link in parsed.links:
        host = host_of(link.url)
        if not host:
            if check is _unparseable:
                findings.extend(check(link, host, from_domain))
            continue
        findings.extend(check(link, host, from_domain))
    return findings


def _unparseable(link: Link, host: str, from_domain: str) -> list[Finding]:
    if host:
        return []
    return [
        Finding(
            code="unparseable_url",
            severity="medium",
            title="A link could not be parsed",
            detail=f"URL: {link.url}",
        )
    ]


def _ip_literal(link: Link, host: str, from_domain: str) -> list[Finding]:
    if host and is_ip_literal(host):
        return [
            Finding(
                code="ip_literal_link",
                severity="high",
                title="Link points at a raw IP address",
                detail=f"{link.url} — real services use domain names.",
            )
        ]
    return []


def _userinfo(link: Link, host: str, from_domain: str) -> list[Finding]:
    parts = link.url.split("/", 3)
    if len(parts) >= 3 and "@" in parts[2]:
        return [
            Finding(
                code="userinfo_in_url",
                severity="high",
                title="URL hides its real host behind an @ sign",
                detail=(
                    f"{link.url} — everything before the @ is ignored "
                    "by the browser."
                ),
            )
        ]
    return []


def _punycode(link: Link, host: str, from_domain: str) -> list[Finding]:
    if host and (host.startswith("xn--") or ".xn--" in host):
        return [
            Finding(
                code="punycode_link",
                severity="high",
                title="Link uses punycode (possible lookalike characters)",
                detail=f"{link.url} — punycode can render as lookalike letters.",
            )
        ]
    return []


def _shortener(link: Link, host: str, from_domain: str) -> list[Finding]:
    if host and registered_domain(host) in _SHORTENERS:
        return [
            Finding(
                code="shortened_link",
                severity="medium",
                title="Link hides behind a URL shortener",
                detail=f"{link.url} — the destination cannot be inspected.",
            )
        ]
    return []


def _risky_tld(link: Link, host: str, from_domain: str) -> list[Finding]:
    if not host:
        return []
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in _RISKY_TLDS:
        return [
            Finding(
                code="risky_tld",
                severity="low",
                title=f"Link uses a .{tld} domain",
                detail=(
                    f"{link.url} — .{tld} is a low-cost TLD often seen "
                    "in abuse reports."
                ),
            )
        ]
    return []


def _deep_subdomain(link: Link, host: str, from_domain: str) -> list[Finding]:
    if host and subdomain_depth(host) >= 3:
        return [
            Finding(
                code="deep_subdomains",
                severity="low",
                title="Link has unusually deep subdomains",
                detail=f"{link.url} — padding subdomains is a common disguise.",
            )
        ]
    return []


def _anchor_mismatch(link: Link, host: str, from_domain: str) -> list[Finding]:
    if not host or not link.anchor_text:
        return []
    anchor_domain = _looks_like_domain(link.anchor_text)
    if anchor_domain and anchor_domain != registered_domain(host):
        return [
            Finding(
                code="anchor_href_mismatch",
                severity="high",
                title="Link text shows one domain but goes to another",
                detail=(
                    f'Text says "{link.anchor_text}" but the link '
                    f"points to {host}."
                ),
            )
        ]
    return []


def _insecure_own_domain(link: Link, host: str, from_domain: str) -> list[Finding]:
    if (
        host
        and from_domain
        and registered_domain(host) == from_domain
        and link.url.startswith("http://")
    ):
        return [
            Finding(
                code="sender_domain_insecure_link",
                severity="low",
                title="Link to the sender's own domain is not HTTPS",
                detail=f"{link.url}",
            )
        ]
    return []


def _per_link(check):
    def run(ctx: AnalysisContext) -> list[Finding]:
        return _each_link(ctx, check)

    return run


RULES = [
    Rule(
        id="unparseable_url",
        name="Unparseable link",
        category="links",
        rationale=(
            "A URL the parser cannot read is often deliberately malformed "
            "to slip past link scanners while still resolving in a browser."
        ),
        run=_per_link(_unparseable),
    ),
    Rule(
        id="ip_literal_link",
        name="Raw IP link",
        category="links",
        rationale=(
            "Legitimate services link to domain names. A bare IP means no "
            "registrar, no reputation history and no takedown path."
        ),
        reference="MITRE ATT&CK T1566.002 (Spearphishing Link)",
        run=_per_link(_ip_literal),
    ),
    Rule(
        id="userinfo_in_url",
        name="Host hidden behind userinfo",
        category="links",
        rationale=(
            "In a URL of the form http://trusted.com@evil.com, the browser "
            "ignores everything before the @. Attackers put a trusted name "
            "in front so the link looks safe at a glance."
        ),
        reference="MITRE ATT&CK T1566.002 (Spearphishing Link)",
        run=_per_link(_userinfo),
    ),
    Rule(
        id="punycode_link",
        name="Punycode link",
        category="links",
        rationale=(
            "Punycode (xn--) lets non-ASCII lookalike characters render as "
            "a trusted brand while the real domain is something else."
        ),
        reference="MITRE ATT&CK T1566.002 (Spearphishing Link)",
        run=_per_link(_punycode),
    ),
    Rule(
        id="shortened_link",
        name="URL shortener",
        category="links",
        rationale=(
            "A shortener hides the destination from both the reader and "
            "mail filters. Real transactional mail links directly."
        ),
        run=_per_link(_shortener),
    ),
    Rule(
        id="risky_tld",
        name="High-risk TLD",
        category="links",
        rationale=(
            "Some TLDs are priced low enough to show up often in abuse "
            "reports. A weak signal on its own; it adds weight next to "
            "other signals."
        ),
        run=_per_link(_risky_tld),
    ),
    Rule(
        id="deep_subdomains",
        name="Padded subdomains",
        category="links",
        rationale=(
            "Long chains of subdomains push the real registered domain out "
            "of view - especially on a narrow screen - and pad the link "
            "with trusted-looking words."
        ),
        run=_per_link(_deep_subdomain),
    ),
    Rule(
        id="anchor_href_mismatch",
        name="Anchor text / destination mismatch",
        category="links",
        rationale=(
            "The reader sees one domain, the browser goes to another - a "
            "standard visual trick in phishing mail."
        ),
        reference="MITRE ATT&CK T1566.002 (Spearphishing Link)",
        run=_per_link(_anchor_mismatch),
    ),
    Rule(
        id="sender_domain_insecure_link",
        name="Own-domain link not HTTPS",
        category="links",
        rationale=(
            "A sender linking to their own domain over plain HTTP is "
            "unusual for a real service and exposes the reader to "
            "tampering in transit."
        ),
        run=_per_link(_insecure_own_domain),
    ),
]
