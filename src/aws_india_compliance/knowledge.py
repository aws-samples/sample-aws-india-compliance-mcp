"""Live regulatory text search from authoritative Indian government sources.

Fetches regulatory text at runtime from official sources:
- dpdpact.in — DPDP Act 2023 and Rules 2025
- rbi.org.in — RBI Master Directions

Security:
- HTTPS only (TLS 1.2+). Plain HTTP never used.
- Response size capped at 5 MB. Content-type validated.
- Rate limited to 10 requests/minute per domain.
- Configurable cache TTL via REGULATORY_CACHE_TTL env var.
- 30-second request timeout.
"""

from __future__ import annotations

import os
import re
import time
import urllib.request
import urllib.error
from html.parser import HTMLParser
from typing import Any

from .domains import ALLOWED_SOURCE_DOMAINS

MAX_RESPONSE_SIZE = 5 * 1024 * 1024  # 5 MB
REQUEST_TIMEOUT = 30  # seconds
ALLOWED_CONTENT_TYPES = {"text/html", "application/json", "text/plain", "application/xhtml+xml"}

_SOURCES: dict[str, list[str]] = {
    "dpdp": ["https://dpdpact.in"],
    "rbi": ["https://rbi.org.in/Scripts/BS_ViewMasterDirections.aspx"],
}

# Cache: URL -> (text, timestamp)
_CACHE: dict[str, tuple[str, float]] = {}
_CACHE_TTL: int = int(os.environ.get("REGULATORY_CACHE_TTL", "0"))

# Rate limiter: domain -> list of request timestamps
_RATE_LIMIT: dict[str, list[float]] = {}
_RATE_LIMIT_MAX = 10  # requests per minute


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


def _check_rate_limit(domain: str) -> bool:
    """Return True if request is allowed, False if rate-limited."""
    now = time.monotonic()
    timestamps = _RATE_LIMIT.get(domain, [])
    # Remove timestamps older than 60 seconds
    timestamps = [t for t in timestamps if now - t < 60]
    _RATE_LIMIT[domain] = timestamps
    if len(timestamps) >= _RATE_LIMIT_MAX:
        return False
    timestamps.append(now)
    return True


def _extract_domain(url: str) -> str:
    """Extract domain from URL for rate limiting."""
    from urllib.parse import urlparse
    return urlparse(url).netloc


def _fetch_text(url: str) -> str:
    """Fetch a URL and extract visible text.

    Security: HTTPS only, response size capped, content-type validated,
    rate-limited, with configurable caching.
    """
    # Enforce HTTPS
    if not url.startswith("https://"):
        return ""

    # Check cache
    if _CACHE_TTL > 0 and url in _CACHE:
        text, ts = _CACHE[url]
        if time.monotonic() - ts < _CACHE_TTL:
            return text

    # Rate limit
    domain = _extract_domain(url)
    if not _check_rate_limit(domain):
        return ""

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "aws-india-compliance-mcp/0.1"})
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            # Validate content-type
            content_type = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
            if content_type not in ALLOWED_CONTENT_TYPES:
                return ""

            # Read with size limit
            data = resp.read(MAX_RESPONSE_SIZE + 1)
            if len(data) > MAX_RESPONSE_SIZE:
                return ""

            html = data.decode("utf-8", errors="replace")

        parser = _TextExtractor()
        parser.feed(html)
        text = "\n".join(parser.parts)

        # Cache if TTL configured
        if _CACHE_TTL > 0:
            _CACHE[url] = (text, time.monotonic())

        return text
    except (urllib.error.URLError, OSError, ValueError):
        return ""


def search_live(query: str, framework: str = "", top_k: int = 5) -> list[dict[str, Any]]:
    """Search regulatory text from live authoritative sources.

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

    sources: dict[str, list[str]] = {}
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
