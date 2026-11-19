"""Lookalike-domain evidence: brands imitated in sender domains and links.

Three shapes are caught:
1. The brand appears in a subdomain or path of someone else's domain
   (paypal.com.secure-login.top).
2. Leetspeak substitutions that normalize back to the brand (paypa1.com).
3. One-edit typos of the brand (paypol.com, micosoft.com).
"""

from __future__ import annotations

from ..domains import domain_of_address, host_of, registered_domain
from ..models import Finding, ParsedEmail

# Brands a South African target actually sees in phishing mail.
_BRANDS = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "gmail": "gmail.com",
    "apple": "apple.com",
    "icloud": "icloud.com",
    "netflix": "netflix.com",
    "amazon": "amazon.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "linkedin": "linkedin.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "ebay": "ebay.com",
    "coinbase": "coinbase.com",
    "binance": "binance.com",
    "capitec": "capitecbank.co.za",
    "fnb": "fnb.co.za",
    "absa": "absa.co.za",
    "standardbank": "standardbank.co.za",
    "nedbank": "nedbank.co.za",
    "sars": "sars.gov.za",
    "takealot": "takealot.com",
}

_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})


def _edit_distance_one(a: str, b: str) -> bool:
    """True when a and b differ by exactly one insert, delete or substitute."""
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        return sum(x != y for x, y in zip(a, b)) == 1
    if la > lb:
        a, b = b, a
        la, lb = lb, la
    i = j = 0
    skipped = False
    while i < la and j < lb:
        if a[i] == b[j]:
            i += 1
            j += 1
        elif skipped:
            return False
        else:
            skipped = True
            j += 1
    return True


def _first_label(host: str) -> str:
    reg = registered_domain(host)
    return reg.split(".", 1)[0] if reg else ""


def _inspect_host(host: str, where: str) -> list[Finding]:
    findings: list[Finding] = []
    if not host:
        return findings
    reg = registered_domain(host)
    label = _first_label(host)
    normalized = label.replace("-", "").translate(_LEET)

    for brand, official in _BRANDS.items():
        official_reg = registered_domain(official)
        if reg == official_reg or reg == f"{brand}.com":
            continue  # genuinely the brand's domain
        brand_in_host = brand in host and reg != official_reg
        if brand_in_host and label != brand:
            findings.append(
                Finding(
                    code="brand_in_foreign_domain",
                    severity="high",
                    title=f'"{brand}" appears inside an unrelated domain',
                    detail=(
                        f"{host} ({where}) uses the {brand} name but the "
                        f"registered domain is {reg}."
                    ),
                )
            )
            continue
        elif brand in normalized and brand not in label:
            findings.append(
                Finding(
                    code="leetspeak_lookalike",
                    severity="high",
                    title=f"Domain imitates {brand} with look-alike characters",
                    detail=(
                        f"{host} ({where}) reads as {brand} once digits and "
                        "symbols are read as letters."
                    ),
                )
            )
        elif _edit_distance_one(label, brand):
            findings.append(
                Finding(
                    code="typo_lookalike",
                    severity="high",
                    title=f"Domain is one character off from {brand}",
                    detail=f"{host} ({where}) vs the real {official}.",
                )
            )
    return findings


def check(msg: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    seen_hosts: set[str] = set()

    for address, where in (
        (msg.from_header, "From address"),
        (msg.reply_to, "Reply-To address"),
    ):
        host = domain_of_address(address)
        if host and host not in seen_hosts:
            seen_hosts.add(host)
            findings.extend(_inspect_host(host, where))

    for link in msg.links:
        host = host_of(link.url)
        if host and host not in seen_hosts:
            seen_hosts.add(host)
            findings.extend(_inspect_host(host, "link"))

    return findings
