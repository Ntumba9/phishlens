"""Extract URLs from plain-text and HTML bodies.

Extraction only. Nothing here dereferences, resolves or fetches a URL.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

from .models import Link

# Deliberately conservative: http/https only, stops at whitespace and quotes.
_URL_RE = re.compile(r"https?://[^\s\"'<>\)]+", re.IGNORECASE)


class _AnchorCollector(HTMLParser):
    """Collect <a href> targets with their visible text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self._current_href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        attrs_dict = dict(attrs)
        href = attrs_dict.get("href")
        if href and href.lower().startswith(("http://", "https://")):
            self._current_href = href
            self._text = []

    def handle_data(self, data):
        if self._current_href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._current_href is not None:
            anchor = " ".join("".join(self._text).split()) or None
            self.links.append(
                Link(url=self._current_href, anchor_text=anchor, source="html")
            )
            self._current_href = None
            self._text = []


def extract_links(text_body: str, html_body: str) -> list[Link]:
    """Pull every http(s) link from both bodies, deduplicated by URL+anchor."""
    links: list[Link] = []
    seen: set[tuple[str, str | None]] = set()

    if html_body:
        collector = _AnchorCollector()
        try:
            collector.feed(html_body)
        except Exception:
            pass  # malformed HTML: fall back to what was collected so far
        for link in collector.links:
            key = (link.url, link.anchor_text)
            if key not in seen:
                seen.add(key)
                links.append(link)

    for match in _URL_RE.finditer(text_body or ""):
        url = match.group(0).rstrip(".,;!")
        key = (url, None)
        if key not in seen:
            seen.add(key)
            links.append(Link(url=url, anchor_text=None, source="text"))
    return links
