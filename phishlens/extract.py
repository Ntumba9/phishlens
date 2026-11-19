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
    """Pull every http(s) link from both bodies, one row per URL.

    When the same URL appears in the HTML part with anchor text and again
    in the plain-text part, keep the HTML copy: the anchor text is evidence.
    """
    by_url: dict[str, Link] = {}

    if html_body:
        collector = _AnchorCollector()
        try:
            collector.feed(html_body)
        except Exception:
            pass  # malformed HTML: fall back to what was collected so far
        for link in collector.links:
            existing = by_url.get(link.url)
            if existing is None or (link.anchor_text and not existing.anchor_text):
                by_url[link.url] = link

    for match in _URL_RE.finditer(text_body or ""):
        url = match.group(0).rstrip(".,;!")
        if url not in by_url:
            by_url[url] = Link(url=url, anchor_text=None, source="text")
    return list(by_url.values())
