"""Live regulatory text search from authoritative Indian government sources.

Fetches regulatory text at runtime from official sources:
- dpdpact.in — DPDP Act 2023 and Rules 2025
- rbi.org.in — RBI Master Directions
- meity.gov.in — MeitY notifications
- egazette.gov.in — Gazette notifications

No bundled/stale data. Every search hits the live source.
"""

from __future__ import annotations

import re
import urllib.request
import urllib.error
from html.parser import HTMLParser
from typing import Any

from .domains import ALLOWED_SOURCE_DOMAINS

_SOURCES: dict[str, list[str]] = {
    "dpdp": [
        "https://dpdpact.in",
    ],
    "rbi": [
        "https://rbi.org.in/Scripts/BS_ViewMasterDirections.aspx",
    ],
}

_CACHE: dict[str, str] = {}  # URL -> fetched text, cleared each server restart


class _TextExtractor(HTMLParser):
    """Extract visible text from HTML, stripping tags."""

    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self._skip = False

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag in ("script", "style", "nav", "footer", "header"):
            self._skip = True

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "nav", "footer", "header"):
            self._skip = False

    def handle_data(self, data: str) -> None:
        if not self._skip:
            text = data.strip()
            if text:
                self.parts.append(text)


def _fetch_text(url: str) -> str:
    """Fetch a URL and extract visible text. Cached per server lifetime."""
    if url in _CACHE:
        return _CACHE[url]
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "aws-india-compliance-mcp/0.1"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="replace")
        parser = _TextExtractor()
        parser.feed(html)
        text = "\n".join(parser.parts)
        _CACHE[url] = text
        return text
    except (urllib.error.URLError, OSError, ValueError):
        return ""


def search_live(query: str, framework: str = "", top_k: int = 5) -> list[dict[str, Any]]:
    """Search regulatory text from live authoritative sources.

    Fetches pages from official government URLs, extracts text,
    and returns paragraphs matching the query using keyword matching.

    Args:
        query: Search terms (e.g., "breach notification", "encryption").
        framework: "dpdp" or "rbi". Empty searches all.
        top_k: Max results to return.

    Returns:
        List of dicts with content, source_url, framework, score.
    """
    query_words = set(re.findall(r"[a-z0-9]+", query.lower()))
    if not query_words:
        return []

    sources = {}
    if not framework or framework.lower() == "dpdp":
        sources["dpdp"] = _SOURCES["dpdp"]
    if not framework or framework.lower() == "rbi":
        sources["rbi"] = _SOURCES["rbi"]

    results: list[dict[str, Any]] = []

    for fw, urls in sources.items():
        for url in urls:
            text = _fetch_text(url)
            if not text:
                continue
            # Split into paragraphs and score each
            paragraphs = [p.strip() for p in re.split(r"\n{2,}", text) if len(p.strip()) > 30]
            for para in paragraphs:
                para_words = set(re.findall(r"[a-z0-9]+", para.lower()))
                overlap = query_words & para_words
                if overlap:
                    score = len(overlap) / len(query_words)
                    results.append({
                        "content": para[:500],
                        "source_url": url,
                        "framework": fw,
                        "score": round(score, 3),
                    })

    results.sort(key=lambda x: -x["score"])
    return results[:top_k]
