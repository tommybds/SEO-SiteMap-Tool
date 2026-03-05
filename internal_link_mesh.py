#!/usr/bin/env python3
"""Minimal internal linking mesh audit for a single host.

Outputs JSON only.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import sys
import time
from collections import defaultdict, deque
from html.parser import HTMLParser
from typing import Callable, DefaultDict, Dict, List, Optional, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urldefrag, urljoin, urlparse, urlunparse
from urllib.request import Request, build_opener
import xml.etree.ElementTree as ET

BLOCKED_HOSTS = {"localhost", "127.0.0.1", "::1"}
BLOCKED_HOST_SUFFIXES = (".local", ".localhost", ".internal", ".test", ".home.arpa")
MAX_BODY_BYTES = 2 * 1024 * 1024
USER_AGENT = "InternalMeshBot/1.0 (+https://tools.tommy-bordas.fr/)"
MAX_SITEMAPS_TO_FETCH = 80
MAX_DISCOVERED_SITEMAPS = 8
LOCALE_SEGMENTS = {"en", "fr", "de", "es", "it", "pt", "nl"}
HREFLANG_RE = re.compile(r"^(x-default|[a-z]{2,3}(?:-[a-z0-9]{2,8})*)$")
PAGE_FILE_EXTENSIONS = {".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".cfm"}
NON_PAGE_FILE_EXTENSIONS = {
    ".xml", ".xsl", ".txt", ".json", ".csv", ".rss", ".atom",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".svg", ".ico", ".bmp", ".tif", ".tiff",
    ".mp4", ".webm", ".mov", ".avi", ".mp3", ".wav", ".ogg", ".m4a",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".rar", ".7z", ".tar", ".gz",
    ".css", ".js", ".map", ".woff", ".woff2", ".ttf", ".otf", ".eot",
}
EXCLUDED_PATH_PREFIXES = (
    "/wp-content/uploads/",
    "/wp-content/cache/",
    "/wp-includes/",
    "/wp-json/",
    "/cdn-cgi/",
)
LINK_CONTEXT_WEIGHTS = {
    "menu": 0.45,
    "footer": 0.25,
    "breadcrumb": 0.6,
    "content": 1.0,
}
TEMPLATE_CONTEXTS = {"menu", "footer", "breadcrumb"}


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: List[Dict[str, str]] = []
        self.hreflang_links: List[Tuple[str, str, str]] = []
        self._stack: List[Tuple[str, Dict[str, str]]] = []
        self._open_anchors: List[Dict[str, object]] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attrs_dict = {str(k).lower(): (v or "") for k, v in attrs}
        tag_name = tag.lower()
        self._stack.append((tag_name, attrs_dict))

        href = attrs_dict.get("href", "").strip()
        if tag_name == "a" and href:
            self._open_anchors.append(
                {
                    "href": href,
                    "context": self._detect_link_context(),
                    "anchor_parts": [],
                }
            )

        hreflang = attrs_dict.get("hreflang", "").strip().lower()
        rel_tokens = [part for part in attrs_dict.get("rel", "").lower().split() if part]
        if href and hreflang and ("alternate" in rel_tokens or tag_name in {"link", "a"}):
            self.hreflang_links.append((hreflang, href, tag_name))

    def handle_startendtag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_data(self, data: str) -> None:
        if self._open_anchors:
            self._open_anchors[-1]["anchor_parts"].append(data)

    def handle_endtag(self, tag: str) -> None:
        tag_name = tag.lower()
        if tag_name == "a" and self._open_anchors:
            link = self._open_anchors.pop()
            anchor_text = _normalize_space(" ".join(str(x) for x in link.get("anchor_parts", [])))
            self.links.append(
                {
                    "href": str(link.get("href", "")),
                    "context": str(link.get("context", "content")),
                    "anchor_text": anchor_text,
                }
            )

        for index in range(len(self._stack) - 1, -1, -1):
            if self._stack[index][0] == tag_name:
                del self._stack[index:]
                break

    def _detect_link_context(self) -> str:
        def _has_marker(markers: Tuple[str, ...]) -> bool:
            for tag_name, attrs in self._stack:
                blob = " ".join(
                    [
                        tag_name,
                        attrs.get("id", ""),
                        attrs.get("class", ""),
                        attrs.get("role", ""),
                        attrs.get("aria-label", ""),
                        attrs.get("data-testid", ""),
                        attrs.get("data-component", ""),
                    ]
                ).lower()
                if any(marker in blob for marker in markers):
                    return True
            return False

        if _has_marker(("breadcrumb", "breadcrumbs", "fil-ariane", "fil_ariane")):
            return "breadcrumb"

        if _has_marker((" footer", "footer ", "site-footer", "copyright")) or any(
            tag_name == "footer" for tag_name, _attrs in self._stack
        ):
            return "footer"

        if _has_marker((" menu", "menu ", "navigation", "navbar", "main-nav", "header-nav")) or any(
            tag_name == "nav" for tag_name, _attrs in self._stack
        ):
            return "menu"

        if _has_marker(("main-content", "entry-content", "article-body", "post-body", "rich-text")) or any(
            tag_name in {"main", "article"} for tag_name, _attrs in self._stack
        ):
            return "content"

        return "content"


def _json_out(payload: Dict[str, object]) -> int:
    print(json.dumps(payload, ensure_ascii=False))
    return 0


def _write_json_file(path: str, payload: Dict[str, object]) -> None:
    target = str(path or "").strip()
    if not target:
        return
    parent = os.path.dirname(target)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(target, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False)


def _normalize_space(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _is_public_ip(ip_text: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    return ip_obj.is_global


def _host_is_allowed(host: str) -> Tuple[bool, str]:
    host = host.strip().lower()
    if not host:
        return False, "Host is missing"

    if host in BLOCKED_HOSTS:
        return False, "Host is local"

    for suffix in BLOCKED_HOST_SUFFIXES:
        if host.endswith(suffix):
            return False, "Host suffix is private/internal"

    try:
        ip_obj = ipaddress.ip_address(host)
        if not ip_obj.is_global:
            return False, "IP is private or reserved"
        return True, ""
    except ValueError:
        pass

    ips: Set[str] = set()
    try:
        records = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False, "Cannot resolve host"

    for item in records:
        if len(item) < 5:
            continue
        sockaddr = item[4]
        if not sockaddr:
            continue
        ip_text = str(sockaddr[0])
        ips.add(ip_text)

    if not ips:
        return False, "Cannot resolve host"

    for ip_text in ips:
        if not _is_public_ip(ip_text):
            return False, "Host resolves to private/reserved IP"

    return True, ""


def _normalize_url(url: str) -> Optional[str]:
    try:
        parsed = urlparse(url)
    except Exception:
        return None

    scheme = parsed.scheme.lower().strip()
    if scheme not in {"http", "https"}:
        return None

    host = (parsed.hostname or "").lower().strip()
    if not host:
        return None

    if parsed.username or parsed.password:
        return None

    port = parsed.port
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None

    netloc = host if port is None else f"{host}:{port}"
    path = parsed.path or "/"

    normalized = urlunparse((scheme, netloc, path, "", "", ""))
    return normalized


def _host_variants(host: str) -> Set[str]:
    host = host.strip().lower()
    variants: Set[str] = set()
    if not host:
        return variants
    variants.add(host)
    if host.startswith("www."):
        variants.add(host[4:])
    else:
        variants.add(f"www.{host}")
    return variants


def _same_host(url: str, expected_hosts: Set[str]) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    return host in expected_hosts


def _safe_internal_url(base_url: str, href: str, expected_hosts: Set[str]) -> Optional[str]:
    if not href:
        return None

    href = href.strip()
    if href.startswith(("mailto:", "tel:", "javascript:")):
        return None

    absolute = urljoin(base_url, href)
    absolute, _frag = urldefrag(absolute)
    normalized = _normalize_url(absolute)
    if not normalized:
        return None

    if not _same_host(normalized, expected_hosts):
        return None

    return normalized


def _is_mesh_page_candidate(url: str) -> bool:
    try:
        path = (urlparse(url).path or "/").lower()
    except Exception:
        return False

    if not path:
        path = "/"

    for prefix in EXCLUDED_PATH_PREFIXES:
        if path.startswith(prefix):
            return False

    if path.endswith("/"):
        return True

    slug = path.rsplit("/", 1)[-1]
    if "." not in slug:
        return True

    dot = slug.rfind(".")
    ext = slug[dot:] if dot >= 0 else ""
    if ext in PAGE_FILE_EXTENSIONS:
        return True
    if ext in NON_PAGE_FILE_EXTENSIONS:
        return False
    return True


def _root_url(url: str) -> Optional[str]:
    normalized = _normalize_url(url)
    if not normalized:
        return None
    parsed = urlparse(normalized)
    return urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))


def _decode_html(body: bytes, content_type: str) -> str:
    charset_match = re.search(r"charset=([a-zA-Z0-9_-]+)", content_type or "")
    enc = charset_match.group(1) if charset_match else "utf-8"
    try:
        return body.decode(enc, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def _fetch_page(url: str, timeout: int) -> Dict[str, object]:
    request = Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml,text/xml;q=0.9,*/*;q=0.8",
        },
    )
    opener = build_opener()

    try:
        with opener.open(request, timeout=timeout) as response:
            final_url = str(response.geturl())
            status = int(response.getcode() or 0)
            content_type = str(response.headers.get("Content-Type", "")).lower()
            body = response.read(MAX_BODY_BYTES + 1)
            if len(body) > MAX_BODY_BYTES:
                body = body[:MAX_BODY_BYTES]

            return {
                "ok": True,
                "url": url,
                "final_url": final_url,
                "status": status,
                "content_type": content_type,
                "body": body,
            }
    except HTTPError as exc:
        return {
            "ok": False,
            "url": url,
            "final_url": url,
            "status": int(exc.code or 0),
            "content_type": "",
            "body": b"",
            "error": f"HTTP {exc.code}",
        }
    except URLError as exc:
        return {
            "ok": False,
            "url": url,
            "final_url": url,
            "status": 0,
            "content_type": "",
            "body": b"",
            "error": f"URL error: {exc.reason}",
        }
    except Exception as exc:
        return {
            "ok": False,
            "url": url,
            "final_url": url,
            "status": 0,
            "content_type": "",
            "body": b"",
            "error": f"Fetch error: {exc}",
        }


def _normalize_hreflang(value: str) -> str:
    return value.strip().lower()


def _is_valid_hreflang(value: str) -> bool:
    return bool(HREFLANG_RE.match(value))


def _normalize_link_context(value: str) -> str:
    raw = value.strip().lower()
    if raw in LINK_CONTEXT_WEIGHTS:
        return raw
    return "content"


def _link_context_weight(value: str) -> float:
    return float(LINK_CONTEXT_WEIGHTS.get(_normalize_link_context(value), 1.0))


def _parse_internal_links_and_hreflang(
    html_text: str,
    base_url: str,
    expected_hosts: Set[str],
) -> Tuple[List[Dict[str, object]], List[Dict[str, object]]]:
    parser = LinkParser()
    try:
        parser.feed(html_text)
    except Exception:
        return [], []

    found: Dict[str, Dict[str, object]] = {}
    for link in parser.links:
        href = str(link.get("href", "")).strip()
        safe = _safe_internal_url(base_url, href, expected_hosts)
        if not safe:
            continue
        if not _is_mesh_page_candidate(safe):
            continue
        context = _normalize_link_context(str(link.get("context", "content")))
        weight = _link_context_weight(context)
        anchor_text = _normalize_space(str(link.get("anchor_text", "")))
        if len(anchor_text) > 120:
            anchor_text = anchor_text[:117].rstrip() + "..."

        existing = found.get(safe)
        if existing is None:
            found[safe] = {
                "target_url": safe,
                "context": context,
                "weight": round(weight, 2),
                "anchor_text": anchor_text,
            }
            continue

        existing_weight = float(existing.get("weight", 0.0))
        existing_anchor = str(existing.get("anchor_text", ""))
        if weight > existing_weight or (anchor_text and not existing_anchor):
            found[safe] = {
                "target_url": safe,
                "context": context,
                "weight": round(weight, 2),
                "anchor_text": anchor_text,
            }

    hreflang_links: List[Dict[str, object]] = []
    for hreflang_raw, href, tag_name in parser.hreflang_links:
        hreflang = _normalize_hreflang(hreflang_raw)
        if not hreflang:
            continue

        absolute = urljoin(base_url, href)
        absolute, _frag = urldefrag(absolute)
        normalized_target = _normalize_url(absolute)
        if not normalized_target:
            continue

        is_internal = _same_host(normalized_target, expected_hosts)
        hreflang_links.append(
            {
                "hreflang": hreflang,
                "href": normalized_target,
                "is_valid": _is_valid_hreflang(hreflang),
                "is_internal": is_internal,
                "tag": tag_name,
            }
        )

    links_sorted = sorted(found.values(), key=lambda item: str(item.get("target_url", "")))
    return links_sorted, hreflang_links


def _looks_like_js_app_shell(html_text: str) -> bool:
    lower = html_text.lower()
    markers = (
        'id="root"',
        "id='root'",
        'id="__next"',
        "id='__next'",
        "data-reactroot",
        "__next_data__",
        "window.__nuxt__",
        "data-v-app",
        'id="app"',
        "id='app'",
    )
    if any(marker in lower for marker in markers):
        return True

    script_tags = lower.count("<script")
    anchor_tags = lower.count("<a ")
    if script_tags >= 8 and anchor_tags <= 2:
        return True
    return False


def _segment_key(path: str) -> str:
    parts = [part for part in path.split("/") if part]
    if not parts:
        return "home"
    if parts[0] in LOCALE_SEGMENTS and len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0]


def _section_key(path: str) -> str:
    parts = [part for part in path.split("/") if part]
    if not parts:
        return "home"
    if parts[0] in LOCALE_SEGMENTS:
        parts = parts[1:]
    if not parts:
        return "home"
    if len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0]


def _locale_key(path: str) -> str:
    parts = [part for part in path.split("/") if part]
    if parts and parts[0] in LOCALE_SEGMENTS:
        return parts[0]
    return ""


def _xml_local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1].lower()
    return tag.lower()


def _parse_sitemap_document(xml_text: str) -> Tuple[List[str], List[str]]:
    child_sitemaps: List[str] = []
    page_urls: List[str] = []

    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return child_sitemaps, page_urls

    root_name = _xml_local_name(root.tag)

    if root_name == "sitemapindex":
        for sitemap_node in root.iter():
            if _xml_local_name(sitemap_node.tag) != "sitemap":
                continue
            loc = ""
            for child in sitemap_node:
                if _xml_local_name(child.tag) == "loc":
                    loc = (child.text or "").strip()
                    break
            if loc:
                child_sitemaps.append(loc)
    elif root_name == "urlset":
        for url_node in root.iter():
            if _xml_local_name(url_node.tag) != "url":
                continue
            loc = ""
            for child in url_node:
                if _xml_local_name(child.tag) == "loc":
                    loc = (child.text or "").strip()
                    break
            if loc:
                page_urls.append(loc)

    return child_sitemaps, page_urls


def _looks_like_sitemap(url: str, content_type: str, body: bytes) -> bool:
    path = (urlparse(url).path or "").lower()
    ct = (content_type or "").lower()
    sample = bytes(body[:600]).lstrip().lower()

    if "xml" in ct:
        return True
    if path.endswith(".xml") and "sitemap" in path:
        return True
    if sample.startswith(b"<?xml") or sample.startswith(b"<urlset") or sample.startswith(b"<sitemapindex"):
        return True
    return False


def _collect_urls_from_sitemap(
    sitemap_url: str,
    timeout: int,
    allowed_hosts: Set[str],
    max_urls: int,
) -> List[str]:
    sitemap_queue: deque[str] = deque([sitemap_url])
    seen_sitemaps: Set[str] = set()
    seen_pages: Set[str] = set()
    pages: List[str] = []

    while sitemap_queue and len(pages) < max_urls and len(seen_sitemaps) < MAX_SITEMAPS_TO_FETCH:
        current = sitemap_queue.popleft()
        if current in seen_sitemaps:
            continue
        seen_sitemaps.add(current)

        fetched = _fetch_page(current, timeout)
        if not bool(fetched.get("ok", False)):
            continue

        final_url = _normalize_url(str(fetched.get("final_url", current))) or current
        if not _same_host(final_url, allowed_hosts):
            continue

        body = fetched.get("body", b"")
        if not isinstance(body, (bytes, bytearray)):
            continue
        xml_text = bytes(body).decode("utf-8", errors="replace")

        child_sitemaps, page_urls = _parse_sitemap_document(xml_text)

        for child in child_sitemaps:
            safe = _safe_internal_url(final_url, child, allowed_hosts)
            if not safe:
                continue
            if safe not in seen_sitemaps:
                sitemap_queue.append(safe)

        for page in page_urls:
            safe = _safe_internal_url(final_url, page, allowed_hosts)
            if not safe:
                continue
            if not _is_mesh_page_candidate(safe):
                continue
            if safe in seen_pages:
                continue
            seen_pages.add(safe)
            pages.append(safe)
            if len(pages) >= max_urls:
                break

    return pages


def _extract_sitemaps_from_robots(
    robots_text: str,
    robots_url: str,
    allowed_hosts: Set[str],
) -> List[str]:
    found: List[str] = []
    seen: Set[str] = set()

    for raw_line in robots_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.lower().startswith("sitemap:"):
            continue

        candidate = line.split(":", 1)[1].strip()
        safe = _safe_internal_url(robots_url, candidate, allowed_hosts)
        if not safe or safe in seen:
            continue
        seen.add(safe)
        found.append(safe)

    return found


def _discover_sitemap_candidates(
    start_url: str,
    timeout: int,
    allowed_hosts: Set[str],
) -> List[str]:
    root = _root_url(start_url)
    if not root:
        return []

    discovered: List[str] = []
    seen: Set[str] = set()

    def _add_candidate(url: str) -> None:
        normalized = _normalize_url(url)
        if not normalized:
            return
        if not _same_host(normalized, allowed_hosts):
            return
        if normalized in seen:
            return
        seen.add(normalized)
        discovered.append(normalized)

    for path in ("/sitemap.xml", "/sitemap_index.xml", "/wp-sitemap.xml"):
        _add_candidate(urljoin(root, path))

    robots_url = urljoin(root, "/robots.txt")
    robots_fetch = _fetch_page(robots_url, timeout)
    if bool(robots_fetch.get("ok", False)):
        body = robots_fetch.get("body", b"")
        if isinstance(body, (bytes, bytearray)):
            robots_text = _decode_html(bytes(body), str(robots_fetch.get("content_type", "")))
            for sitemap_url in _extract_sitemaps_from_robots(robots_text, robots_url, allowed_hosts):
                _add_candidate(sitemap_url)

    return discovered[:MAX_DISCOVERED_SITEMAPS]


def run_mesh(
    start_url: str,
    max_pages: int,
    timeout: int,
    max_edges: int,
    max_runtime_ms: int,
    progress_callback: Optional[Callable[[Dict[str, object]], None]] = None,
) -> Dict[str, object]:
    normalized_start = _normalize_url(start_url)
    if not normalized_start:
        return {"ok": False, "error": "Invalid start_url"}

    start_host = (urlparse(normalized_start).hostname or "").lower()
    allowed, reason = _host_is_allowed(start_host)
    if not allowed:
        return {"ok": False, "error": f"Unsafe host: {reason}"}

    allowed_hosts = _host_variants(start_host)
    crawl_start = normalized_start

    queue: deque[str] = deque([normalized_start])
    queued: Set[str] = {normalized_start}
    visited_order: List[str] = []
    visited_set: Set[str] = set()
    reportable_order: List[str] = []
    reportable_set: Set[str] = set()

    inbound_count: DefaultDict[str, int] = defaultdict(int)
    outbound_count: DefaultDict[str, int] = defaultdict(int)
    weighted_inbound_count: DefaultDict[str, float] = defaultdict(float)
    weighted_outbound_count: DefaultDict[str, float] = defaultdict(float)
    source_context_counts: DefaultDict[str, DefaultDict[str, int]] = defaultdict(lambda: defaultdict(int))
    edges_set: Set[Tuple[str, str]] = set()
    edge_meta: Dict[Tuple[str, str], Dict[str, object]] = {}
    fetch_errors: List[Dict[str, str]] = []
    prefetched: Dict[str, Dict[str, object]] = {}
    seed_mode = "crawl_only"
    seed_sitemaps: List[str] = []
    html_pages_scanned = 0
    js_like_pages: List[str] = []
    hreflang_entries_by_source: DefaultDict[str, List[Dict[str, object]]] = defaultdict(list)
    hreflang_source_count: DefaultDict[str, int] = defaultdict(int)
    hreflang_invalid_count = 0
    hreflang_external_count = 0

    started_at_total = time.time()
    runtime_limited = False
    last_progress_emit_at = 0.0

    def _build_progress(stage: str, *, force_complete: bool = False) -> Dict[str, object]:
        elapsed_ms = int((time.time() - started_at_total) * 1000)
        scanned_pages = len(reportable_order)
        page_ratio = scanned_pages / max(1, max_pages)
        runtime_ratio = (
            elapsed_ms / max(1, max_runtime_ms)
            if int(max_runtime_ms) > 0
            else 0.0
        )
        ratio = max(page_ratio, min(0.95, runtime_ratio * 0.85))
        progress_pct = int(round(min(1.0, ratio) * 100))
        if force_complete:
            progress_pct = 100
        elif progress_pct < 1:
            progress_pct = 1
        elif progress_pct > 99:
            progress_pct = 99

        return {
            "stage": stage,
            "progress_pct": progress_pct,
            "pages_scanned": scanned_pages,
            "pages_target": int(max_pages),
            "queue_size": len(queue),
            "edges_found": len(edges_set),
            "elapsed_ms": elapsed_ms,
            "runtime_budget_ms": int(max_runtime_ms),
            "runtime_limited": bool(runtime_limited),
            "seed_mode": seed_mode,
        }

    def _emit_progress(stage: str, *, force: bool = False, force_complete: bool = False) -> None:
        nonlocal last_progress_emit_at
        if progress_callback is None:
            return
        now = time.time()
        if not force and (now - last_progress_emit_at) < 0.8:
            return
        progress_callback(_build_progress(stage, force_complete=force_complete))
        last_progress_emit_at = now

    _emit_progress("preparing", force=True)

    # Pre-fetch first URL once to detect host canonicalization and sitemap URLs.
    first_fetch = _fetch_page(normalized_start, timeout)
    first_final = _normalize_url(str(first_fetch.get("final_url", normalized_start))) or normalized_start
    first_final_host = (urlparse(first_final).hostname or "").lower()
    if first_final_host:
        if first_final_host not in _host_variants(start_host):
            return {"ok": False, "error": "Start URL redirects outside allowed host scope"}
        allowed_hosts = _host_variants(first_final_host)
        start_host = first_final_host
        crawl_start = first_final
    queue = deque([crawl_start])
    queued = {crawl_start}

    if bool(first_fetch.get("ok", False)):
        content_type = str(first_fetch.get("content_type", "")).lower()
        body = first_fetch.get("body", b"")
        body_bytes = bytes(body) if isinstance(body, (bytes, bytearray)) else b""
        if _looks_like_sitemap(crawl_start, content_type, body_bytes):
            sitemap_pages = _collect_urls_from_sitemap(crawl_start, timeout, allowed_hosts, max_pages * 3)
            if sitemap_pages:
                unique_pages = []
                seen_local: Set[str] = set()
                for page in sitemap_pages:
                    if page in seen_local:
                        continue
                    seen_local.add(page)
                    unique_pages.append(page)
                    if len(unique_pages) >= max_pages:
                        break
                if unique_pages:
                    queue = deque(unique_pages)
                    queued = set(unique_pages)
                    crawl_start = unique_pages[0]
                    seed_mode = "sitemap_start"
                    seed_sitemaps = [crawl_start]
        else:
            prefetched[crawl_start] = first_fetch
    else:
        prefetched[crawl_start] = first_fetch

    if seed_mode == "crawl_only":
        _emit_progress("discovering_sitemaps", force=True)
        discovered_sitemaps = _discover_sitemap_candidates(crawl_start, timeout, allowed_hosts)
        discovered_pages: List[str] = []
        seen_pages: Set[str] = set()
        for sitemap_url in discovered_sitemaps:
            pages = _collect_urls_from_sitemap(sitemap_url, timeout, allowed_hosts, max_pages * 3)
            for page in pages:
                if page in seen_pages:
                    continue
                seen_pages.add(page)
                discovered_pages.append(page)
                if len(discovered_pages) >= max_pages:
                    break
            if len(discovered_pages) >= max_pages:
                break

        appended = 0
        for page in discovered_pages:
            if page in visited_set or page in queued:
                continue
            if len(queue) >= max_pages:
                break
            queue.append(page)
            queued.add(page)
            appended += 1

        if appended > 0:
            seed_mode = "crawl_plus_sitemap_discovery"
            seed_sitemaps = discovered_sitemaps

    crawl_started_at = time.time()
    _emit_progress("scanning", force=True)

    while queue and len(reportable_order) < max_pages:
        if max_runtime_ms > 0:
            elapsed_loop_ms = int((time.time() - crawl_started_at) * 1000)
            if elapsed_loop_ms >= max_runtime_ms:
                runtime_limited = True
                break

        current = queue.popleft()
        queued.discard(current)

        if current in visited_set:
            continue
        if not _is_mesh_page_candidate(current):
            continue

        current_host = (urlparse(current).hostname or "").lower()
        allowed, reason = _host_is_allowed(current_host)
        if not allowed:
            fetch_errors.append({"url": current, "error": f"Blocked URL: {reason}"})
            continue

        fetched = prefetched.pop(current, None) or _fetch_page(current, timeout)
        final_url = _normalize_url(str(fetched.get("final_url", current))) or current

        if not _same_host(final_url, allowed_hosts):
            fetch_errors.append({"url": current, "error": "Redirected outside start host"})
            _emit_progress("scanning")
            continue

        visited_set.add(final_url)
        visited_order.append(final_url)

        if not bool(fetched.get("ok", False)):
            fetch_errors.append({"url": final_url, "error": str(fetched.get("error", "Fetch failed"))})
            outbound_count[final_url] = outbound_count.get(final_url, 0)
            _emit_progress("scanning")
            continue

        content_type = str(fetched.get("content_type", "")).lower()
        is_html = "text/html" in content_type or "application/xhtml+xml" in content_type
        if not is_html:
            outbound_count[final_url] = outbound_count.get(final_url, 0)
            _emit_progress("scanning")
            continue

        body = fetched.get("body", b"")
        if not isinstance(body, (bytes, bytearray)):
            outbound_count[final_url] = outbound_count.get(final_url, 0)
            _emit_progress("scanning")
            continue

        html_text = _decode_html(bytes(body), content_type)
        if final_url not in reportable_set:
            reportable_set.add(final_url)
            reportable_order.append(final_url)
        html_pages_scanned += 1
        if _looks_like_js_app_shell(html_text):
            js_like_pages.append(final_url)
        internal_links, hreflang_links = _parse_internal_links_and_hreflang(html_text, final_url, allowed_hosts)

        unique_hreflang: Set[Tuple[str, str]] = set()
        for entry in hreflang_links:
            hreflang = str(entry.get("hreflang", "")).strip().lower()
            target_url = str(entry.get("href", "")).strip()
            if not hreflang or not target_url:
                continue
            key = (hreflang, target_url)
            if key in unique_hreflang:
                continue
            unique_hreflang.add(key)

            is_valid = bool(entry.get("is_valid", False))
            is_internal = bool(entry.get("is_internal", False))
            if not is_valid:
                hreflang_invalid_count += 1
            if not is_internal:
                hreflang_external_count += 1

            hreflang_entries_by_source[final_url].append(
                {
                    "hreflang": hreflang,
                    "href": target_url,
                    "is_valid": is_valid,
                    "is_internal": is_internal,
                    "tag": str(entry.get("tag", "")),
                }
            )

        hreflang_source_count[final_url] = len(unique_hreflang)

        unique_targets: Dict[str, Dict[str, object]] = {}
        for link in internal_links:
            target = str(link.get("target_url", "")).strip()
            if not target or target == final_url:
                continue

            context = _normalize_link_context(str(link.get("context", "content")))
            weight = float(link.get("weight", _link_context_weight(context)))
            anchor_text = _normalize_space(str(link.get("anchor_text", "")))

            existing = unique_targets.get(target)
            if existing is None:
                unique_targets[target] = {
                    "context": context,
                    "weight": weight,
                    "anchor_text": anchor_text,
                }
            else:
                prev_weight = float(existing.get("weight", 0.0))
                prev_anchor = str(existing.get("anchor_text", ""))
                if weight > prev_weight or (anchor_text and not prev_anchor):
                    unique_targets[target] = {
                        "context": context,
                        "weight": weight,
                        "anchor_text": anchor_text,
                    }

        outbound_weight_sum = 0.0
        for target, meta in unique_targets.items():
            inbound_count[target] += 1
            weight = float(meta.get("weight", 1.0))
            context = _normalize_link_context(str(meta.get("context", "content")))
            anchor_text = _normalize_space(str(meta.get("anchor_text", "")))
            weighted_inbound_count[target] += weight
            outbound_weight_sum += weight
            source_context_counts[final_url][context] += 1

            if len(edges_set) < max_edges:
                edges_set.add((final_url, target))
                edge_key = (final_url, target)
                previous = edge_meta.get(edge_key)
                if previous is None or weight > float(previous.get("weight", 0.0)) or (
                    anchor_text and not str(previous.get("anchor_text", ""))
                ):
                    edge_meta[edge_key] = {
                        "context": context,
                        "weight": round(weight, 2),
                        "anchor_text": anchor_text,
                    }

        outbound_count[final_url] = len(unique_targets)
        weighted_outbound_count[final_url] = round(outbound_weight_sum, 3)

        for target in unique_targets.keys():
            if target in visited_set or target in queued:
                continue
            if len(reportable_order) + len(queue) >= max_pages:
                break
            queue.append(target)
            queued.add(target)

        _emit_progress("scanning")

    _emit_progress("finalizing", force=True)

    edges_filtered: List[Dict[str, object]] = []
    for source, target in sorted(edges_set):
        if source not in reportable_set or target not in reportable_set:
            continue
        meta = edge_meta.get((source, target), {})
        edges_filtered.append(
            {
                "source": source,
                "target": target,
                "context": _normalize_link_context(str(meta.get("context", "content"))),
                "weight": round(float(meta.get("weight", 1.0)), 2),
                "anchor_text": _normalize_space(str(meta.get("anchor_text", ""))),
            }
        )

    outgoing_map: DefaultDict[str, Set[str]] = defaultdict(set)
    edge_lookup: Set[Tuple[str, str]] = set()
    for edge in edges_filtered:
        source = str(edge.get("source", ""))
        target = str(edge.get("target", ""))
        if not source or not target:
            continue
        outgoing_map[source].add(target)
        edge_lookup.add((source, target))

    edge_context_counts: DefaultDict[str, int] = defaultdict(int)
    target_context_inbound_counts: DefaultDict[str, DefaultDict[str, int]] = defaultdict(lambda: defaultdict(int))
    target_template_source_clusters: DefaultDict[str, DefaultDict[str, int]] = defaultdict(lambda: defaultdict(int))
    for edge in edges_filtered:
        source = str(edge.get("source", ""))
        target = str(edge.get("target", ""))
        context = _normalize_link_context(str(edge.get("context", "content")))
        edge_context_counts[context] += 1
        if target:
            target_context_inbound_counts[target][context] += 1
            if context in TEMPLATE_CONTEXTS and source:
                source_path = urlparse(source).path or "/"
                cluster_key = f"{context}:{_section_key(source_path)}"
                target_template_source_clusters[target][cluster_key] += 1

    template_inbound_share_by_url: Dict[str, float] = {}
    template_dominant_targets: List[str] = []
    content_inbound_by_url: DefaultDict[str, int] = defaultdict(int)
    template_inbound_by_url: DefaultDict[str, int] = defaultdict(int)
    for target_url, counts in target_context_inbound_counts.items():
        total = sum(int(v) for v in counts.values())
        if total <= 0:
            continue
        template_hits = sum(int(counts.get(ctx, 0)) for ctx in TEMPLATE_CONTEXTS)
        content_hits = int(counts.get("content", 0))
        content_inbound_by_url[target_url] = content_hits
        template_inbound_by_url[target_url] = template_hits
        share = template_hits / total
        template_inbound_share_by_url[target_url] = round(share, 3)
        if total >= 5 and share >= 0.7:
            template_dominant_targets.append(target_url)

    hreflang_edges_internal: Set[Tuple[str, str, str]] = set()
    hreflang_inbound_count: DefaultDict[str, int] = defaultdict(int)
    hreflang_outbound_count: DefaultDict[str, int] = defaultdict(int)
    hreflang_reverse_lookup: DefaultDict[str, Set[str]] = defaultdict(set)
    hreflang_duplicate_by_page: List[Dict[str, object]] = []
    hreflang_missing_x_default_pages: List[Dict[str, object]] = []
    pages_with_hreflang = 0

    for source_url in reportable_order:
        entries = hreflang_entries_by_source.get(source_url, [])
        if entries:
            pages_with_hreflang += 1

        by_lang_targets: DefaultDict[str, Set[str]] = defaultdict(set)
        has_x_default = False
        for entry in entries:
            lang = str(entry.get("hreflang", "")).strip().lower()
            target_url = str(entry.get("href", "")).strip()
            if not lang or not target_url:
                continue
            by_lang_targets[lang].add(target_url)
            if lang == "x-default":
                has_x_default = True

            if not bool(entry.get("is_internal", False)):
                continue
            if source_url not in reportable_set or target_url not in reportable_set:
                continue
            if source_url == target_url:
                continue

            hreflang_edges_internal.add((source_url, target_url, lang))
            hreflang_reverse_lookup[target_url].add(source_url)

        non_x_langs = [lang for lang in by_lang_targets.keys() if lang != "x-default"]
        duplicate_langs = sorted([lang for lang, targets in by_lang_targets.items() if len(targets) > 1])
        if duplicate_langs:
            hreflang_duplicate_by_page.append(
                {
                    "url": source_url,
                    "path": urlparse(source_url).path or "/",
                    "duplicate_langs": duplicate_langs,
                }
            )

        if len(non_x_langs) >= 2 and not has_x_default:
            hreflang_missing_x_default_pages.append(
                {
                    "url": source_url,
                    "path": urlparse(source_url).path or "/",
                }
            )

    for source_url, target_url, _lang in hreflang_edges_internal:
        hreflang_outbound_count[source_url] += 1
        hreflang_inbound_count[target_url] += 1

    hreflang_non_reciprocal: List[Dict[str, object]] = []
    for source_url, target_url, lang in sorted(hreflang_edges_internal):
        reverse_sources = hreflang_reverse_lookup.get(source_url, set())
        if target_url in reverse_sources:
            continue
        hreflang_non_reciprocal.append(
            {
                "from_url": source_url,
                "to_url": target_url,
                "hreflang": lang,
                "to_path": urlparse(target_url).path or "/",
            }
        )

    depth_by_url: Dict[str, int] = {}
    if crawl_start in reportable_set:
        depth_queue: deque[Tuple[str, int]] = deque([(crawl_start, 0)])
        depth_by_url[crawl_start] = 0
        while depth_queue:
            current_url, depth = depth_queue.popleft()
            for target in sorted(outgoing_map.get(current_url, set())):
                if target in depth_by_url:
                    continue
                depth_by_url[target] = depth + 1
                depth_queue.append((target, depth + 1))

    context_profile_by_url: Dict[str, Dict[str, object]] = {}
    for url in reportable_order:
        counts = source_context_counts.get(url, {})
        total = sum(int(v) for v in counts.values())
        dominant_context = "content"
        if total > 0:
            dominant_context = max(counts.items(), key=lambda item: int(item[1]))[0]
        template_ratio = (
            sum(int(counts.get(ctx, 0)) for ctx in TEMPLATE_CONTEXTS) / total if total > 0 else 0.0
        )
        content_ratio = int(counts.get("content", 0)) / total if total > 0 else 0.0
        context_profile_by_url[url] = {
            "dominant_context": _normalize_link_context(dominant_context),
            "template_ratio": round(template_ratio, 3),
            "content_ratio": round(content_ratio, 3),
            "context_links_total": total,
        }

    nodes: List[Dict[str, object]] = []
    for url in reportable_order:
        parsed = urlparse(url)
        profile = context_profile_by_url.get(url, {})
        nodes.append(
            {
                "url": url,
                "path": parsed.path or "/",
                "inbound": int(inbound_count.get(url, 0)),
                "outbound": int(outbound_count.get(url, 0)),
                "weighted_inbound": round(float(weighted_inbound_count.get(url, 0.0)), 2),
                "weighted_outbound": round(float(weighted_outbound_count.get(url, 0.0)), 2),
                "dominant_link_context": str(profile.get("dominant_context", "content")),
                "template_link_ratio": float(profile.get("template_ratio", 0.0)),
                "content_inbound": int(content_inbound_by_url.get(url, 0)),
                "template_inbound": int(template_inbound_by_url.get(url, 0)),
                "hreflang_outbound": int(hreflang_outbound_count.get(url, 0)),
                "hreflang_inbound": int(hreflang_inbound_count.get(url, 0)),
                "hreflang_declared": int(hreflang_source_count.get(url, 0)),
                "is_start": url == crawl_start,
                "depth": depth_by_url.get(url),
            }
        )

    def _node_score(item: Dict[str, object]) -> int:
        return int(item.get("inbound", 0)) + int(item.get("outbound", 0))

    top_hubs = sorted(nodes, key=lambda n: (_node_score(n), n["url"]), reverse=True)[:12]
    orphan_candidates = [
        {
            "url": n["url"],
            "path": n["path"],
            "outbound": n["outbound"],
        }
        for n in nodes
        if not bool(n.get("is_start")) and int(n.get("inbound", 0)) == 0
    ][:20]

    total_pages = len(nodes)
    total_edges = len(edges_filtered)
    avg_links_per_page = round(total_edges / max(1, total_pages), 2)
    orphan_count = sum(
        1 for node in nodes if not bool(node.get("is_start")) and int(node.get("inbound", 0)) == 0
    )
    dead_end_count = sum(1 for node in nodes if int(node.get("outbound", 0)) == 0)
    weak_inbound_count = sum(
        1 for node in nodes if not bool(node.get("is_start")) and int(node.get("inbound", 0)) <= 1
    )
    template_only_inbound_count = sum(
        1
        for node in nodes
        if not bool(node.get("is_start"))
        and int(node.get("inbound", 0)) > 0
        and int(node.get("content_inbound", 0)) == 0
        and int(node.get("template_inbound", 0)) >= 3
    )
    unreachable_count = sum(
        1 for node in nodes if not bool(node.get("is_start")) and node.get("depth") is None
    )
    reachable_count = total_pages - unreachable_count
    node_by_url: Dict[str, Dict[str, object]] = {str(node.get("url", "")): node for node in nodes}
    orphan_hreflang_only_nodes = [
        node
        for node in nodes
        if not bool(node.get("is_start"))
        and int(node.get("inbound", 0)) == 0
        and int(node.get("hreflang_inbound", 0)) > 0
    ]
    orphan_hreflang_only_count = len(orphan_hreflang_only_nodes)

    source_pool = [node for node in nodes if int(node.get("outbound", 0)) > 0]
    source_pool.sort(
        key=lambda node: (
            float(node.get("weighted_inbound", 0.0)) + float(node.get("weighted_outbound", 0.0)),
            int(node.get("inbound", 0)) + int(node.get("outbound", 0)),
            int(node.get("outbound", 0)),
        ),
        reverse=True,
    )
    source_pool = source_pool[:40]

    def _source_profile(source_url: str) -> Dict[str, object]:
        return context_profile_by_url.get(
            source_url,
            {
                "dominant_context": "content",
                "template_ratio": 0.0,
                "content_ratio": 0.0,
                "context_links_total": 0,
            },
        )

    def _pick_sources(target_node: Dict[str, object], prefer_editorial: bool = False) -> List[Dict[str, object]]:
        target_url = str(target_node.get("url", ""))
        target_path = str(target_node.get("path", "/"))
        target_segment = _segment_key(target_path)
        target_section = _section_key(target_path)
        target_locale = _locale_key(target_path)
        target_depth = target_node.get("depth")

        scored: List[Tuple[int, Dict[str, object]]] = []
        for source_node in source_pool:
            source_url = str(source_node.get("url", ""))
            if not source_url or source_url == target_url:
                continue
            if (source_url, target_url) in edge_lookup:
                continue

            source_path = str(source_node.get("path", "/"))
            source_segment = _segment_key(source_path)
            source_section = _section_key(source_path)
            source_locale = _locale_key(source_path)
            source_depth = source_node.get("depth")
            source_profile = _source_profile(source_url)
            template_ratio = float(source_profile.get("template_ratio", 0.0))
            content_ratio = float(source_profile.get("content_ratio", 0.0))
            dominant_context = str(source_profile.get("dominant_context", "content"))
            same_section = source_section == target_section

            score = int(source_node.get("outbound", 0)) + min(15, int(source_node.get("inbound", 0)))
            if same_section:
                score += 44
            if source_segment == target_segment:
                score += 18
            if target_locale and source_locale == target_locale:
                score += 15
            if target_locale and source_locale and source_locale != target_locale:
                score -= 8
            if isinstance(source_depth, int) and isinstance(target_depth, int) and source_depth < target_depth:
                score += 6
            score += int(content_ratio * 16)
            score -= int(template_ratio * 24)
            if dominant_context == "footer":
                score -= 10
            elif dominant_context == "menu":
                score -= 6
            if float(template_inbound_share_by_url.get(target_url, 0.0)) >= 0.7:
                score -= 6
            if prefer_editorial and dominant_context in TEMPLATE_CONTEXTS:
                score -= 12

            scored.append((score, source_node))

        scored.sort(key=lambda item: item[0], reverse=True)
        picked: List[Dict[str, object]] = []
        for score, source in scored[:3]:
            source_url = str(source.get("url", ""))
            source_profile = _source_profile(source_url)
            picked.append(
                {
                    "url": source_url,
                    "path": source.get("path", "/"),
                    "inbound": int(source.get("inbound", 0)),
                    "outbound": int(source.get("outbound", 0)),
                    "dominant_context": str(source_profile.get("dominant_context", "content")),
                    "template_ratio": float(source_profile.get("template_ratio", 0.0)),
                    "content_ratio": float(source_profile.get("content_ratio", 0.0)),
                    "section_key": _section_key(str(source.get("path", "/"))),
                    "segment_key": _segment_key(str(source.get("path", "/"))),
                    "score": score,
                }
            )
        return picked

    def _pick_hreflang_sources(target_url: str) -> List[Dict[str, object]]:
        sources: List[Dict[str, object]] = []
        for source_url in sorted(hreflang_reverse_lookup.get(target_url, set()))[:3]:
            source_node = node_by_url.get(source_url, {})
            source_profile = _source_profile(source_url)
            sources.append(
                {
                    "url": source_url,
                    "path": source_node.get("path", urlparse(source_url).path or "/"),
                    "inbound": int(source_node.get("inbound", 0)),
                    "outbound": int(source_node.get("outbound", 0)),
                    "dominant_context": str(source_profile.get("dominant_context", "content")),
                    "template_ratio": float(source_profile.get("template_ratio", 0.0)),
                    "content_ratio": float(source_profile.get("content_ratio", 0.0)),
                    "section_key": _section_key(str(source_node.get("path", "/"))),
                    "segment_key": _segment_key(str(source_node.get("path", "/"))),
                    "score": 50 + int(source_node.get("outbound", 0)),
                }
            )
        return sources

    recommendations: List[Dict[str, object]] = []
    for node in nodes:
        if bool(node.get("is_start")):
            continue

        inbound = int(node.get("inbound", 0))
        outbound = int(node.get("outbound", 0))
        hreflang_inbound = int(node.get("hreflang_inbound", 0))
        content_inbound = int(node.get("content_inbound", 0))
        template_inbound = int(node.get("template_inbound", 0))
        depth = node.get("depth")
        issue_type = ""
        priority = ""
        suggested_sources: List[Dict[str, object]] = []

        if inbound == 0 and hreflang_inbound > 0:
            issue_type = "orphan_hreflang_only"
            priority = "high"
            suggested_sources = _pick_hreflang_sources(str(node.get("url", "")))
        elif inbound == 0:
            issue_type = "orphan_no_inbound"
            priority = "high"
            suggested_sources = _pick_sources(node)
        elif inbound > 0 and content_inbound == 0 and template_inbound >= 3:
            issue_type = "template_only_inbound"
            priority = "medium"
            suggested_sources = _pick_sources(node, prefer_editorial=True)
        elif outbound == 0 and inbound > 0:
            issue_type = "dead_end_no_outbound"
            priority = "medium"
            suggested_sources = _pick_sources(node, prefer_editorial=True)
        elif inbound <= 1 and isinstance(depth, int) and depth >= 3:
            issue_type = "deep_weak_inbound"
            priority = "medium"
            suggested_sources = _pick_sources(node, prefer_editorial=True)
        else:
            continue

        recommendations.append(
            {
                "target_url": node.get("url", ""),
                "target_path": node.get("path", "/"),
                "priority": priority,
                "issue_type": issue_type,
                "current_inbound": inbound,
                "current_outbound": outbound,
                "current_hreflang_inbound": hreflang_inbound,
                "current_content_inbound": content_inbound,
                "current_template_inbound": template_inbound,
                "depth": depth,
                "suggested_sources": suggested_sources,
            }
        )

    seen_non_reciprocal_targets: Set[Tuple[str, str]] = set()
    for rel in hreflang_non_reciprocal:
        target_url = str(rel.get("to_url", ""))
        source_url = str(rel.get("from_url", ""))
        if not target_url or not source_url:
            continue
        dedupe_key = (target_url, source_url)
        if dedupe_key in seen_non_reciprocal_targets:
            continue
        seen_non_reciprocal_targets.add(dedupe_key)

        target_node = node_by_url.get(target_url, {})
        recommendations.append(
            {
                "target_url": target_url,
                "target_path": target_node.get("path", urlparse(target_url).path or "/"),
                "priority": "medium",
                "issue_type": "hreflang_missing_reciprocal",
                "current_inbound": int(target_node.get("inbound", 0)),
                "current_outbound": int(target_node.get("outbound", 0)),
                "current_hreflang_inbound": int(target_node.get("hreflang_inbound", 0)),
                "current_content_inbound": int(target_node.get("content_inbound", 0)),
                "current_template_inbound": int(target_node.get("template_inbound", 0)),
                "depth": target_node.get("depth"),
                "suggested_sources": [
                    {
                        "url": source_url,
                        "path": urlparse(source_url).path or "/",
                        "inbound": int(node_by_url.get(source_url, {}).get("inbound", 0)),
                        "outbound": int(node_by_url.get(source_url, {}).get("outbound", 0)),
                        "section_key": _section_key(urlparse(source_url).path or "/"),
                        "segment_key": _segment_key(urlparse(source_url).path or "/"),
                        "score": 60,
                    }
                ],
                "hreflang": str(rel.get("hreflang", "")),
            }
        )
        if len(seen_non_reciprocal_targets) >= 18:
            break

    priority_rank = {"high": 3, "medium": 2, "low": 1}
    recommendations.sort(
        key=lambda item: (
            priority_rank.get(str(item.get("priority", "")), 0),
            int(item.get("current_inbound", 0)) * -1,
            int(item.get("current_outbound", 0)),
            int(item.get("depth", -1)) if isinstance(item.get("depth"), int) else -1,
        ),
        reverse=True,
    )
    deduped_recommendations: List[Dict[str, object]] = []
    seen_recommendations: Set[Tuple[str, str]] = set()
    for rec in recommendations:
        key = (str(rec.get("target_url", "")), str(rec.get("issue_type", "")))
        if key in seen_recommendations:
            continue
        seen_recommendations.add(key)
        deduped_recommendations.append(rec)
        if len(deduped_recommendations) >= 24:
            break
    recommendations = deduped_recommendations

    def _anchor_recommendation(path: str) -> str:
        parts = [part for part in path.split("/") if part]
        if not parts:
            return "Home"
        if parts and parts[0] in LOCALE_SEGMENTS:
            parts = parts[1:]
        if not parts:
            return "Home"
        raw = parts[-1].replace("-", " ").replace("_", " ").strip()
        raw = _normalize_space(raw)
        if not raw:
            return "Voir la page"
        words = raw.split(" ")
        if len(words) > 7:
            words = words[:7]
        candidate = " ".join(words).strip()
        if not candidate:
            return "Voir la page"
        return candidate[0].upper() + candidate[1:]

    def _clamp(value: int, low: int, high: int) -> int:
        return max(low, min(high, value))

    opportunities: List[Dict[str, object]] = []
    seen_opportunities: Set[Tuple[str, str, str]] = set()
    priority_base = {"high": 58, "medium": 46, "low": 34}
    effort_base = {
        "orphan_no_inbound": 30,
        "orphan_hreflang_only": 26,
        "deep_weak_inbound": 24,
        "dead_end_no_outbound": 22,
        "template_only_inbound": 22,
        "hreflang_missing_reciprocal": 14,
    }
    template_cluster_budget: DefaultDict[Tuple[str, str], Set[str]] = defaultdict(set)

    for rec in recommendations:
        target_url = str(rec.get("target_url", ""))
        target_path = str(rec.get("target_path", "/"))
        issue_type = str(rec.get("issue_type", ""))
        priority = str(rec.get("priority", "low")).lower()
        target_locale = _locale_key(target_path)
        target_segment = _segment_key(target_path)
        target_section = _section_key(target_path)
        target_inbound = int(rec.get("current_inbound", 0))
        target_content_inbound = int(rec.get("current_content_inbound", 0))
        target_template_inbound = int(rec.get("current_template_inbound", 0))
        target_depth = rec.get("depth")
        suggested_sources = rec.get("suggested_sources", [])
        if not isinstance(suggested_sources, list):
            continue

        for source in suggested_sources:
            source_url = str(source.get("url", ""))
            source_path = str(source.get("path", "/"))
            if not source_url or not target_url:
                continue
            dedupe_key = (source_url, target_url, issue_type)
            if dedupe_key in seen_opportunities:
                continue
            seen_opportunities.add(dedupe_key)

            source_locale = _locale_key(source_path)
            source_segment = _segment_key(source_path)
            source_section = _section_key(source_path)
            source_score = int(source.get("score", 0))
            source_template_ratio = float(source.get("template_ratio", 0.0))
            source_content_ratio = float(source.get("content_ratio", 0.0))
            source_context = _normalize_link_context(str(source.get("dominant_context", "content")))
            same_segment = source_segment == target_segment
            same_section = source_section == target_section
            same_locale = bool(target_locale and source_locale == target_locale)
            target_template_share = float(template_inbound_share_by_url.get(target_url, 0.0))
            source_cluster = str(source.get("section_key", source_section or "home"))

            if source_context in TEMPLATE_CONTEXTS:
                cluster_key = f"{source_context}:{source_cluster}"
                dedupe_bucket = template_cluster_budget[(target_url, issue_type)]
                if cluster_key in dedupe_bucket:
                    continue
                dedupe_bucket.add(cluster_key)

            impact = int(priority_base.get(priority, 42))
            impact += min(14, max(0, source_score // 6))
            impact += int((1.0 - source_template_ratio) * 10)
            impact += int(source_content_ratio * 8)
            impact += 12 if same_section else 0
            impact += 5 if same_segment else 0
            impact += 4 if same_locale else 0
            impact += max(0, (2 - target_inbound) * 6)
            impact += 5 if target_content_inbound == 0 else 0
            impact -= int(target_template_share * 10)
            impact = _clamp(impact, 1, 100)

            effort = int(effort_base.get(issue_type, 24))
            if isinstance(target_depth, int) and target_depth >= 4:
                effort += 8
            elif isinstance(target_depth, int) and target_depth >= 2:
                effort += 4
            if source_context == "content":
                effort -= 8
            elif source_context == "menu":
                effort += 4
            elif source_context == "footer":
                effort += 7
            elif source_context == "breadcrumb":
                effort += 2
            if same_section:
                effort -= 4
            elif same_segment:
                effort -= 3
            effort = _clamp(effort, 5, 95)

            confidence = 52
            confidence += int(impact * 0.24)
            confidence -= int(effort * 0.18)
            confidence += 9 if same_section else 0
            confidence += 5 if same_locale else 0
            confidence -= int(source_template_ratio * 18)
            confidence -= 7 if source_context in {"footer", "menu"} else 0
            confidence += 4 if source_context == "content" else 0
            confidence = _clamp(confidence, 5, 99)
            confidence_level = "high" if confidence >= 75 else ("medium" if confidence >= 55 else "low")

            section_relevance = "cross_section"
            if same_section:
                section_relevance = "same_section"
            elif same_segment:
                section_relevance = "same_segment"

            quick_win = impact >= 72 and effort <= 32 and confidence >= 60
            opportunities.append(
                {
                    "source_url": source_url,
                    "source_path": source_path,
                    "source_context": source_context,
                    "source_template_ratio": round(source_template_ratio, 3),
                    "target_url": target_url,
                    "target_path": target_path,
                    "issue_type": issue_type,
                    "priority": priority,
                    "impact_score": impact,
                    "effort_score": effort,
                    "confidence_score": confidence,
                    "confidence_level": confidence_level,
                    "quick_win": quick_win,
                    "recommended_anchor": _anchor_recommendation(target_path),
                    "same_segment": same_segment,
                    "same_section": same_section,
                    "same_locale": same_locale,
                    "section_relevance": section_relevance,
                    "target_content_inbound": target_content_inbound,
                    "target_template_inbound": target_template_inbound,
                    "source_cluster": source_cluster,
                    "source_score": source_score,
                }
            )

    opportunities.sort(
        key=lambda row: (
            1 if bool(row.get("quick_win")) else 0,
            int(row.get("confidence_score", 0)),
            int(row.get("impact_score", 0)),
            -int(row.get("effort_score", 0)),
            int(row.get("source_score", 0)),
        ),
        reverse=True,
    )
    opportunities = opportunities[:260]
    opportunities_quick_wins = sum(1 for row in opportunities if bool(row.get("quick_win", False)))
    opportunities_contextual = sum(
        1
        for row in opportunities
        if str(row.get("source_context", "")) in {"content", "breadcrumb"}
    )

    js_like_seen: Set[str] = set()
    js_like_samples: List[str] = []
    for url in js_like_pages:
        if url in js_like_seen:
            continue
        js_like_seen.add(url)
        js_like_samples.append(url)
        if len(js_like_samples) >= 10:
            break

    js_like_count = len(js_like_seen)
    js_like_ratio = round(js_like_count / max(1, html_pages_scanned), 3)
    js_app_suspected = bool(
        (html_pages_scanned >= 3 and js_like_ratio >= 0.35) or js_like_count >= 8
    )

    hreflang_internal_edges_count = len(hreflang_edges_internal)
    hreflang_non_reciprocal_count = len(hreflang_non_reciprocal)
    hreflang_non_reciprocal_samples = hreflang_non_reciprocal[:12]
    hreflang_missing_x_default_samples = hreflang_missing_x_default_pages[:12]
    hreflang_duplicate_samples = hreflang_duplicate_by_page[:12]
    orphan_hreflang_only_samples = [
        {
            "url": str(node.get("url", "")),
            "path": str(node.get("path", "/")),
            "hreflang_inbound": int(node.get("hreflang_inbound", 0)),
        }
        for node in orphan_hreflang_only_nodes[:12]
    ]

    elapsed_ms = int((time.time() - started_at_total) * 1000)
    _emit_progress("completed", force=True, force_complete=True)

    return {
        "ok": True,
        "mesh": {
            "start_url": crawl_start,
            "host": start_host,
            "pages_scanned": len(nodes),
            "edges_count": len(edges_filtered),
            "max_pages": max_pages,
            "elapsed_ms": elapsed_ms,
            "runtime_limited": runtime_limited,
            "runtime_budget_ms": int(max_runtime_ms),
            "nodes": nodes,
            "edges": edges_filtered,
            "top_hubs": top_hubs,
            "orphan_candidates": orphan_candidates,
            "fetch_errors": fetch_errors[:20],
            "seed_mode": seed_mode,
            "seed_sitemaps": seed_sitemaps,
            "rendering_signals": {
                "js_app_suspected": js_app_suspected,
                "html_pages_scanned": html_pages_scanned,
                "js_like_pages_count": js_like_count,
                "js_like_ratio": js_like_ratio,
                "js_like_samples": js_like_samples,
            },
            "actionable": {
                "kpis": {
                    "avg_links_per_page": avg_links_per_page,
                    "orphan_pages": orphan_count,
                    "dead_end_pages": dead_end_count,
                    "weak_inbound_pages": weak_inbound_count,
                    "template_only_inbound_pages": template_only_inbound_count,
                    "unreachable_from_start": unreachable_count,
                    "reachable_from_start": reachable_count,
                    "hreflang_pages": pages_with_hreflang,
                    "hreflang_non_reciprocal": hreflang_non_reciprocal_count,
                    "template_dominant_targets": len(template_dominant_targets),
                    "quick_wins": opportunities_quick_wins,
                    "contextual_opportunities": opportunities_contextual,
                },
                "recommendations": recommendations,
                "opportunities": opportunities,
                "opportunities_total": len(opportunities),
                "opportunities_quick_wins": opportunities_quick_wins,
                "opportunities_contextual": opportunities_contextual,
            },
            "link_context_summary": {
                "content": int(edge_context_counts.get("content", 0)),
                "menu": int(edge_context_counts.get("menu", 0)),
                "footer": int(edge_context_counts.get("footer", 0)),
                "breadcrumb": int(edge_context_counts.get("breadcrumb", 0)),
                "template_dominant_targets": len(template_dominant_targets),
            },
            "hreflang": {
                "pages_with_hreflang": pages_with_hreflang,
                "internal_edges": hreflang_internal_edges_count,
                "external_edges": hreflang_external_count,
                "invalid_entries": hreflang_invalid_count,
                "non_reciprocal_count": hreflang_non_reciprocal_count,
                "non_reciprocal_samples": hreflang_non_reciprocal_samples,
                "missing_x_default_count": len(hreflang_missing_x_default_pages),
                "missing_x_default_samples": hreflang_missing_x_default_samples,
                "duplicate_lang_pages_count": len(hreflang_duplicate_by_page),
                "duplicate_lang_pages_samples": hreflang_duplicate_samples,
                "orphan_hreflang_only_count": orphan_hreflang_only_count,
                "orphan_hreflang_only_samples": orphan_hreflang_only_samples,
            },
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Minimal internal linking mesh audit")
    parser.add_argument("--start-url", required=True, help="Start URL, e.g. https://example.com/")
    parser.add_argument("--max-pages", type=int, default=80)
    parser.add_argument("--timeout", type=int, default=12)
    parser.add_argument("--max-edges", type=int, default=800)
    parser.add_argument("--max-runtime-ms", type=int, default=45000)
    parser.add_argument("--output-json", default="", help="Optional output JSON file path")
    parser.add_argument("--progress-json", default="", help="Optional progress JSON file path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    max_pages = max(10, min(300, int(args.max_pages)))
    timeout = max(3, min(30, int(args.timeout)))
    max_edges = max(100, min(2000, int(args.max_edges)))
    max_runtime_ms = max(10000, min(120000, int(args.max_runtime_ms)))
    progress_path = str(args.progress_json or "").strip()

    def write_progress(payload: Dict[str, object]) -> None:
        if not progress_path:
            return
        stamped = dict(payload)
        stamped["updated_at"] = int(time.time())
        _write_json_file(progress_path, stamped)

    write_progress(
        {
            "stage": "queued",
            "progress_pct": 0,
            "pages_scanned": 0,
            "pages_target": max_pages,
            "queue_size": 0,
            "edges_found": 0,
            "elapsed_ms": 0,
            "runtime_budget_ms": int(max_runtime_ms),
            "runtime_limited": False,
            "seed_mode": "crawl_only",
        }
    )

    try:
        payload = run_mesh(
            start_url=str(args.start_url),
            max_pages=max_pages,
            timeout=timeout,
            max_edges=max_edges,
            max_runtime_ms=max_runtime_ms,
            progress_callback=write_progress,
        )
        _write_json_file(str(args.output_json or ""), payload)
        if bool(payload.get("ok", False)):
            mesh = payload.get("mesh", {})
            if isinstance(mesh, dict):
                write_progress(
                    {
                        "stage": "completed",
                        "progress_pct": 100,
                        "pages_scanned": int(mesh.get("pages_scanned", 0)),
                        "pages_target": max_pages,
                        "queue_size": 0,
                        "edges_found": int(mesh.get("edges_count", 0)),
                        "elapsed_ms": int(mesh.get("elapsed_ms", 0)),
                        "runtime_budget_ms": int(mesh.get("runtime_budget_ms", max_runtime_ms)),
                        "runtime_limited": bool(mesh.get("runtime_limited", False)),
                        "seed_mode": str(mesh.get("seed_mode", "crawl_only")),
                    }
                )
        return _json_out(payload)
    except Exception as exc:
        payload = {"ok": False, "error": f"Unexpected mesh error: {exc}"}
        _write_json_file(str(args.output_json or ""), payload)
        write_progress(
            {
                "stage": "failed",
                "progress_pct": 100,
                "pages_scanned": 0,
                "pages_target": max_pages,
                "queue_size": 0,
                "edges_found": 0,
                "elapsed_ms": 0,
                "runtime_budget_ms": int(max_runtime_ms),
                "runtime_limited": False,
                "seed_mode": "crawl_only",
                "error": str(exc),
            }
        )
        return _json_out(payload)


if __name__ == "__main__":
    sys.exit(main())
