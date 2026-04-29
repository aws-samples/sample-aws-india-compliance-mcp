"""Live regulatory text search from authoritative Indian government sources.

Fetches regulatory text at runtime from official sources:
- dpdpact.in — DPDP Act 2023 and Rules 2025
- rbi.org.in — RBI Master Directions
- sebi.gov.in — SEBI CSCRF circulars

When live fetch fails or returns no results (e.g., JS-rendered pages,
site downtime, rate limiting), falls back to the bundled
control_mappings.json manifest which contains domain names, section
references, AWS control mappings, Config rules, and guardrails.

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

from .domains import ALLOWED_SOURCE_DOMAINS, load_manifest

MAX_RESPONSE_SIZE = 5 * 1024 * 1024  # 5 MB
REQUEST_TIMEOUT = 30  # seconds
ALLOWED_CONTENT_TYPES = {"text/html", "application/json", "text/plain", "application/xhtml+xml"}

_SOURCES: dict[str, list[str]] = {
    "dpdp": [
        "https://dpdpact.in",
    ],
    "rbi": [
        "https://rbi.org.in/Scripts/BS_ViewMasterDirections.aspx",
    ],
    "sebi": [
        "https://www.sebi.gov.in",
        "https://www.sebi.gov.in/sebiweb/home/HomeAction.do?doListing=yes&sid=3&ssid=27&smid=0",
    ],
}

# Cache: URL -> (text, timestamp)
_CACHE: dict[str, tuple[str, float]] = {}
_CACHE_TTL: int = int(os.environ.get("REGULATORY_CACHE_TTL", "0"))

# Rate limiter: domain -> list of request timestamps
_RATE_LIMIT: dict[str, list[float]] = {}
_RATE_LIMIT_MAX = 10  # requests per minute


class _TextExtractor(HTMLParser):
    """Extract visible text from HTML, stripping tags.

    Inserts paragraph breaks on block-level elements so downstream
    splitting can segment the text into meaningful chunks.
    """

    _BLOCK_TAGS = frozenset({
        "p", "div", "section", "article", "main", "aside",
        "h1", "h2", "h3", "h4", "h5", "h6",
        "li", "tr", "td", "th", "dt", "dd",
        "blockquote", "pre", "figcaption",
    })
    _SKIP_TAGS = frozenset({"script", "style", "nav", "footer", "header"})

    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self._skip = False

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag in self._SKIP_TAGS:
            self._skip = True
        elif tag in self._BLOCK_TAGS and not self._skip:
            self.parts.append("\n\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP_TAGS:
            self._skip = False
        elif tag in self._BLOCK_TAGS and not self._skip:
            self.parts.append("\n\n")

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

    Security: HTTPS only (scheme validated before open), response size
    capped, content-type validated, rate-limited, with configurable caching.
    """
    # Enforce HTTPS — reject file:/, ftp://, data:, and plain http://
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return ""

    # Enforce domain allowlist
    if parsed.netloc and not any(parsed.netloc.endswith(d) for d in ALLOWED_SOURCE_DOMAINS):
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
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:  # noqa: S310 — scheme validated above
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


def _search_manifest_fallback(query_words: set[str], framework: str, top_k: int) -> list[dict[str, Any]]:
    """Search the bundled control_mappings.json as a fallback.

    Builds searchable text from each domain's name, section, AWS controls,
    Config rules, and guardrails, then scores against query words.

    Args:
        query_words: Lowercased query terms.
        framework: "dpdp", "rbi", "sebi", or "" for all.
        top_k: Max results to return.

    Returns:
        List of result dicts with content, source_url, framework, score, source.
    """
    try:
        manifest = load_manifest()
    except (OSError, ValueError):
        return []

    frameworks_data = manifest.get("frameworks", {})
    targets = [framework.lower()] if framework else list(frameworks_data.keys())
    results: list[dict[str, Any]] = []

    for fw_key in targets:
        fw_data = frameworks_data.get(fw_key)
        if not fw_data:
            continue
        source_url = fw_data.get("source_url", "")
        fw_name = fw_data.get("name", fw_key)
        domains = fw_data.get("domains", {})

        for dom_num, dom in domains.items():
            # Build searchable text from all domain fields
            parts = [
                dom.get("name", ""),
                dom.get("section", ""),
                dom.get("type", ""),
                " ".join(dom.get("aws_controls", [])),
                " ".join(dom.get("config_rules", [])),
                " ".join(dom.get("guardrails", [])),
            ]
            text = " ".join(parts)
            text_words = set(re.findall(r"[a-z0-9]+", text.lower()))
            overlap = query_words & text_words
            if overlap:
                score = len(overlap) / len(query_words)
                # Build a readable summary
                content = f"[{fw_name}] Domain {dom_num}: {dom.get('name', '')} ({dom.get('section', '')})"
                aws_ctrls = dom.get("aws_controls", [])
                if aws_ctrls:
                    content += f". AWS controls: {', '.join(aws_ctrls[:5])}"
                config_rules = dom.get("config_rules", [])
                if config_rules:
                    content += f". Config rules: {', '.join(config_rules[:5])}"
                guardrails = dom.get("guardrails", [])
                if guardrails:
                    content += f". Guardrails: {', '.join(guardrails[:5])}"

                results.append({
                    "content": content[:500],
                    "source_url": source_url,
                    "framework": fw_key,
                    "score": round(score, 3),
                    "source": "control_mappings_fallback",
                })

    results.sort(key=lambda x: -x["score"])
    return results[:top_k]


def search_live(query: str, framework: str = "", top_k: int = 5) -> list[dict[str, Any]]:
    """Search regulatory text from live authoritative sources.

    Attempts live HTTPS fetch first. If no results are found for any
    requested framework, falls back to the bundled control_mappings.json
    manifest which contains domain definitions, AWS control mappings,
    Config rules, and guardrails.

    Args:
        query: Search terms (e.g., "breach notification", "encryption").
        framework: "dpdp", "rbi", or "sebi". Empty searches all.
        top_k: Max results to return.

    Returns:
        List of dicts with content, source_url, framework, score.
        Fallback results include source="control_mappings_fallback".
    """
    query_words = set(re.findall(r"[a-z0-9]+", query.lower()))
    if not query_words:
        return []

    sources: dict[str, list[str]] = {}
    if not framework or framework.lower() == "dpdp":
        sources["dpdp"] = _SOURCES["dpdp"]
    if not framework or framework.lower() == "rbi":
        sources["rbi"] = _SOURCES["rbi"]
    if not framework or framework.lower() == "sebi":
        sources["sebi"] = _SOURCES["sebi"]

    results: list[dict[str, Any]] = []
    frameworks_with_results: set[str] = set()

    for fw, urls in sources.items():
        for url in urls:
            text = _fetch_text(url)
            if not text:
                continue
            # Split on double newlines (block-level boundaries from _TextExtractor),
            # then fall back to single newlines if that yields too few chunks.
            paragraphs = [p.strip() for p in re.split(r"\n{2,}", text) if len(p.strip()) > 20]
            if len(paragraphs) < 3:
                paragraphs = [p.strip() for p in text.split("\n") if len(p.strip()) > 20]
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
                    frameworks_with_results.add(fw)

    # Fallback: for any framework that returned no live results,
    # search the bundled control_mappings.json
    frameworks_without_results = set(sources.keys()) - frameworks_with_results
    if frameworks_without_results:
        for fw in frameworks_without_results:
            fallback = _search_manifest_fallback(query_words, fw, top_k)
            results.extend(fallback)

    results.sort(key=lambda x: -x["score"])
    return results[:top_k]
