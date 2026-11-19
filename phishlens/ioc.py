"""IOC extraction and defanging.

Indicators of compromise are observables an analyst can block on or pivot
from: domains, URLs, IP literals, sender addresses and attachment hashes.
Extraction only - nothing here resolves, fetches or submits anything.
"""

from __future__ import annotations

import re

from .domains import domain_of_address, host_of, is_ip_literal, registered_domain
from .models import Attachment, IocSet, ParsedEmail

_ADDRESS_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def defang(value: str) -> str:
    """Render an IOC inert for safe sharing: hxxp, [.], [at]."""
    out = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
    out = out.replace(".", "[.]").replace("@", "[at]")
    return out


def refang(value: str) -> str:
    """Reverse defang for analysts pasting indicators back in."""
    out = value.replace("hxxps://", "https://").replace("hxxp://", "http://")
    out = out.replace("[.]", ".").replace("[at]", "@")
    return out


def extract_iocs(parsed: ParsedEmail, attachments: list[Attachment]) -> IocSet:
    """Collect deduped observables from one parsed message."""
    iocs = IocSet()
    domains: set[str] = set()
    urls: set[str] = set()
    ips: set[str] = set()
    addresses: set[str] = set()

    for link in parsed.links:
        urls.add(link.url)
        host = host_of(link.url)
        if not host:
            continue
        if is_ip_literal(host):
            ips.add(host)
        else:
            domains.add(registered_domain(host))

    for address, in (
        (parsed.from_header,),
        (parsed.reply_to,),
        (parsed.return_path,),
    ):
        if address:
            addresses.add(address.lower())
            domain = domain_of_address(address)
            if domain and not is_ip_literal(domain):
                domains.add(registered_domain(domain))

    for match in _ADDRESS_RE.finditer(f"{parsed.subject}\n{parsed.text_body}"):
        addresses.add(match.group(0).lower())

    for attachment in attachments:
        if attachment.sha256:
            iocs.file_hashes.append(
                {
                    "filename": attachment.filename,
                    "md5": attachment.md5,
                    "sha256": attachment.sha256,
                }
            )

    iocs.domains = sorted(domains)
    iocs.urls = sorted(urls)
    iocs.ips = sorted(ips)
    iocs.addresses = sorted(addresses)
    return iocs


def iocs_as_text(iocs: IocSet, *, defanged: bool = True) -> str:
    """Render an IOC set as a plain-text block for ticketing systems."""
    render = defang if defanged else (lambda value: value)
    lines: list[str] = []
    sections = (
        ("Domains", iocs.domains),
        ("URLs", iocs.urls),
        ("IP addresses", iocs.ips),
        ("Email addresses", iocs.addresses),
    )
    for title, values in sections:
        if values:
            lines.append(f"[{title}]")
            lines.extend(render(value) for value in values)
            lines.append("")
    if iocs.file_hashes:
        lines.append("[File hashes]")
        for entry in iocs.file_hashes:
            lines.append(f"{entry['sha256']}  {entry['filename']}")
        lines.append("")
    return "\n".join(lines).strip()
