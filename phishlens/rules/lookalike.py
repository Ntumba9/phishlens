"""Lookalike-domain rules: brands imitated in sender domains and links.

Three shapes are caught:
1. The brand appears inside someone else's domain
   (paypal.com.secure-login.top).
2. Leetspeak substitutions that normalize back to the brand (paypa1.com).
3. One-edit typos of the brand (paypol.com, micosoft.com).
"""

from __future__ import annotations

from collections.abc import Callable

from ..domains import domain_of_address, host_of, registered_domain
from ..models import Finding
from .base import AnalysisContext, Rule

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

_LEET = str.maketrans(
    {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"}
)


def _edit_distance_one(a: str, b: str) -> bool:
    """True when a and b differ by exactly one insert, delete or substitute."""
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        return sum(x != y for x, y in zip(a, b, strict=True)) == 1
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


def _candidate_hosts(parsed) -> list[tuple[str, str]]:
    """(host, where-seen) pairs, deduplicated, from sender fields and links."""
    seen: set[str] = set()
    candidates: list[tuple[str, str]] = []
    for address, where in (
        (parsed.from_header, "From address"),
        (parsed.reply_to, "Reply-To address"),
    ):
        host = domain_of_address(address)
        if host and host not in seen:
            seen.add(host)
            candidates.append((host, where))
    for link in parsed.links:
        host = host_of(link.url)
        if host and host not in seen:
            seen.add(host)
            candidates.append((host, "link"))
    return candidates


def _scan_hosts(
    ctx: AnalysisContext, detector: Callable[[str, str], Finding | None]
) -> list[Finding]:
    findings: list[Finding] = []
    for host, where in _candidate_hosts(ctx.parsed):
        finding = detector(host, where)
        if finding:
            findings.append(finding)
    return findings


def _brand_in_foreign(host: str, where: str) -> Finding | None:
    reg = registered_domain(host)
    label = _first_label(host)
    for brand, official in _BRANDS.items():
        official_reg = registered_domain(official)
        if reg == official_reg or reg == f"{brand}.com":
            continue  # genuinely the brand's domain
        if brand in host and label != brand:
            return Finding(
                code="brand_in_foreign_domain",
                severity="high",
                title=f'"{brand}" appears inside an unrelated domain',
                detail=(
                    f"{host} ({where}) uses the {brand} name but the "
                    f"registered domain is {reg}."
                ),
            )
    return None


def _leetspeak(host: str, where: str) -> Finding | None:
    reg = registered_domain(host)
    label = _first_label(host)
    normalized = label.replace("-", "").translate(_LEET)
    for brand, official in _BRANDS.items():
        official_reg = registered_domain(official)
        if reg == official_reg or reg == f"{brand}.com":
            continue
        if brand in host and label != brand:
            continue  # handled by the foreign-domain rule
        if brand in normalized and brand not in label:
            return Finding(
                code="leetspeak_lookalike",
                severity="high",
                title=f"Domain imitates {brand} with look-alike characters",
                detail=(
                    f"{host} ({where}) reads as {brand} once digits and "
                    "symbols are read as letters."
                ),
            )
    return None


def _typo(host: str, where: str) -> Finding | None:
    reg = registered_domain(host)
    label = _first_label(host)
    normalized = label.replace("-", "").translate(_LEET)
    for brand, official in _BRANDS.items():
        official_reg = registered_domain(official)
        if reg == official_reg or reg == f"{brand}.com":
            continue
        if brand in host or brand in normalized:
            continue  # louder rules already cover these
        if _edit_distance_one(label, brand):
            return Finding(
                code="typo_lookalike",
                severity="high",
                title=f"Domain is one character off from {brand}",
                detail=f"{host} ({where}) vs the real {official}.",
            )
    return None


RULES = [
    Rule(
        id="brand_in_foreign_domain",
        name="Brand name in foreign domain",
        category="lookalike",
        rationale=(
            "paypal.com.account-verify.top is not PayPal: the registered "
            "domain is everything after the brand name. Reading a host "
            "right-to-left defuses this disguise."
        ),
        run=lambda ctx: _scan_hosts(ctx, _brand_in_foreign),
    ),
    Rule(
        id="leetspeak_lookalike",
        name="Leetspeak lookalike",
        category="lookalike",
        rationale=(
            "Digits and symbols that read as letters (paypa1, micr0soft) "
            "survive a quick glance and slip past brand-name string "
            "matching."
        ),
        run=lambda ctx: _scan_hosts(ctx, _leetspeak),
    ),
    Rule(
        id="typo_lookalike",
        name="One-character typo of a brand",
        category="lookalike",
        rationale=(
            "A typosquat sits one edit away from the real brand and is "
            "easy to misread as the real thing."
        ),
        run=lambda ctx: _scan_hosts(ctx, _typo),
    ),
]
