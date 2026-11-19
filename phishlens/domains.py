"""Small domain helpers.

No tldextract dependency: a short list of common two-level public suffixes
covers the cases this tool actually sees (including South African .co.za),
and everything else falls back to the last two labels.
"""

from __future__ import annotations

from urllib.parse import urlsplit

_TWO_LEVEL_SUFFIXES = {
    "co.za", "org.za", "net.za", "ac.za", "gov.za", "web.za",
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au",
    "co.nz", "com.br", "com.ng", "co.ke", "co.in",
}


def host_of(url: str) -> str:
    """Hostname of a URL, lowercased, without port. Empty on parse failure."""
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def domain_of_address(address: str) -> str:
    """Domain part of an email address, lowercased."""
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip().lower()


def registered_domain(host: str) -> str:
    """Registrable domain for a host (example.co.uk for a.b.example.co.uk)."""
    host = host.strip(".").lower()
    if not host:
        return ""
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    suffix2 = ".".join(labels[-2:])
    if suffix2 in _TWO_LEVEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return suffix2


def is_ip_literal(host: str) -> bool:
    """True when the host is a dotted IPv4 literal."""
    parts = host.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def subdomain_depth(host: str) -> int:
    """How many labels sit in front of the registered domain."""
    reg = registered_domain(host)
    if not reg or not host.endswith(reg):
        return 0
    prefix = host[: -len(reg)].strip(".")
    return len(prefix.split(".")) if prefix else 0
