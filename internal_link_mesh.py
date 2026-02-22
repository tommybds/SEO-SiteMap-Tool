#!/usr/bin/env python3
"""Minimal internal linking mesh audit for a single host.

Outputs JSON only.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import sys
import time
from collections import defaultdict, deque
from html.parser import HTMLParser
from typing import DefaultDict, Dict, List, Optional, Set, Tuple
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


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: List[str] = []
        self.hreflang_links: List[Tuple[str, str, str]] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attrs_dict = {str(k).lower(): (v or "") for k, v in attrs}
        tag_name = tag.lower()
        href = attrs_dict.get("href", "").strip()
        if tag_name == "a" and href:
            self.links.append(href)

        hreflang = attrs_dict.get("hreflang", "").strip().lower()
        rel_tokens = [part for part in attrs_dict.get("rel", "").lower().split() if part]
        if href and hreflang and ("alternate" in rel_tokens or tag_name in {"link", "a"}):
            self.hreflang_links.append((hreflang, href, tag_name))


def _json_out(payload: Dict[str, object]) -> int:
    print(json.dumps(payload, ensure_ascii=False))
    return 0


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


def _parse_internal_links_and_hreflang(
    html_text: str,
    base_url: str,
    expected_hosts: Set[str],
) -> Tuple[List[str], List[Dict[str, object]]]:
    parser = LinkParser()
    try:
        parser.feed(html_text)
    except Exception:
        return [], []

    found: Set[str] = set()
    for href in parser.links:
        safe = _safe_internal_url(base_url, href, expected_hosts)
        if safe:
            found.add(safe)

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

    return sorted(found), hreflang_links


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


def run_mesh(start_url: str, max_pages: int, timeout: int, max_edges: int) -> Dict[str, object]:
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

    inbound_count: DefaultDict[str, int] = defaultdict(int)
    outbound_count: DefaultDict[str, int] = defaultdict(int)
    edges_set: Set[Tuple[str, str]] = set()
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

    started_at = time.time()

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

    while queue and len(visited_order) < max_pages:
        current = queue.popleft()
        queued.discard(current)

        if current in visited_set:
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
            continue

        visited_set.add(final_url)
        visited_order.append(final_url)

        if not bool(fetched.get("ok", False)):
            fetch_errors.append({"url": final_url, "error": str(fetched.get("error", "Fetch failed"))})
            outbound_count[final_url] = outbound_count.get(final_url, 0)
            continue

        content_type = str(fetched.get("content_type", "")).lower()
        is_html = "text/html" in content_type or "application/xhtml+xml" in content_type
        if not is_html:
            outbound_count[final_url] = outbound_count.get(final_url, 0)
            continue

        body = fetched.get("body", b"")
        if not isinstance(body, (bytes, bytearray)):
            outbound_count[final_url] = outbound_count.get(final_url, 0)
            continue

        html_text = _decode_html(bytes(body), content_type)
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

        unique_targets: Set[str] = set()
        for target in internal_links:
            if target == final_url:
                continue
            unique_targets.add(target)
            inbound_count[target] += 1
            if len(edges_set) < max_edges:
                edges_set.add((final_url, target))

        outbound_count[final_url] = len(unique_targets)

        for target in unique_targets:
            if target in visited_set or target in queued:
                continue
            if len(visited_order) + len(queue) >= max_pages:
                break
            queue.append(target)
            queued.add(target)

    edges_filtered = [
        {"source": source, "target": target}
        for source, target in sorted(edges_set)
        if source in visited_set and target in visited_set
    ]

    outgoing_map: DefaultDict[str, Set[str]] = defaultdict(set)
    edge_lookup: Set[Tuple[str, str]] = set()
    for edge in edges_filtered:
        source = str(edge.get("source", ""))
        target = str(edge.get("target", ""))
        if not source or not target:
            continue
        outgoing_map[source].add(target)
        edge_lookup.add((source, target))

    hreflang_edges_internal: Set[Tuple[str, str, str]] = set()
    hreflang_inbound_count: DefaultDict[str, int] = defaultdict(int)
    hreflang_outbound_count: DefaultDict[str, int] = defaultdict(int)
    hreflang_reverse_lookup: DefaultDict[str, Set[str]] = defaultdict(set)
    hreflang_duplicate_by_page: List[Dict[str, object]] = []
    hreflang_missing_x_default_pages: List[Dict[str, object]] = []
    pages_with_hreflang = 0

    for source_url in visited_order:
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
            if source_url not in visited_set or target_url not in visited_set:
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
    if crawl_start in visited_set:
        depth_queue: deque[Tuple[str, int]] = deque([(crawl_start, 0)])
        depth_by_url[crawl_start] = 0
        while depth_queue:
            current_url, depth = depth_queue.popleft()
            for target in sorted(outgoing_map.get(current_url, set())):
                if target in depth_by_url:
                    continue
                depth_by_url[target] = depth + 1
                depth_queue.append((target, depth + 1))

    nodes: List[Dict[str, object]] = []
    for url in visited_order:
        parsed = urlparse(url)
        nodes.append(
            {
                "url": url,
                "path": parsed.path or "/",
                "inbound": int(inbound_count.get(url, 0)),
                "outbound": int(outbound_count.get(url, 0)),
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
        key=lambda node: (int(node.get("inbound", 0)) + int(node.get("outbound", 0)), int(node.get("outbound", 0))),
        reverse=True,
    )
    source_pool = source_pool[:40]

    def _pick_sources(target_node: Dict[str, object]) -> List[Dict[str, object]]:
        target_url = str(target_node.get("url", ""))
        target_path = str(target_node.get("path", "/"))
        target_segment = _segment_key(target_path)
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
            source_locale = _locale_key(source_path)
            source_depth = source_node.get("depth")

            score = int(source_node.get("outbound", 0)) + min(15, int(source_node.get("inbound", 0)))
            if source_segment == target_segment:
                score += 35
            if target_locale and source_locale == target_locale:
                score += 15
            if target_locale and source_locale and source_locale != target_locale:
                score -= 8
            if isinstance(source_depth, int) and isinstance(target_depth, int) and source_depth < target_depth:
                score += 6

            scored.append((score, source_node))

        scored.sort(key=lambda item: item[0], reverse=True)
        picked: List[Dict[str, object]] = []
        for score, source in scored[:3]:
            picked.append(
                {
                    "url": source.get("url", ""),
                    "path": source.get("path", "/"),
                    "inbound": int(source.get("inbound", 0)),
                    "outbound": int(source.get("outbound", 0)),
                    "score": score,
                }
            )
        return picked

    def _pick_hreflang_sources(target_url: str) -> List[Dict[str, object]]:
        sources: List[Dict[str, object]] = []
        for source_url in sorted(hreflang_reverse_lookup.get(target_url, set()))[:3]:
            source_node = node_by_url.get(source_url, {})
            sources.append(
                {
                    "url": source_url,
                    "path": source_node.get("path", urlparse(source_url).path or "/"),
                    "inbound": int(source_node.get("inbound", 0)),
                    "outbound": int(source_node.get("outbound", 0)),
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
        elif outbound == 0 and inbound > 0:
            issue_type = "dead_end_no_outbound"
            priority = "medium"
            suggested_sources = _pick_sources(node)
        elif inbound <= 1 and isinstance(depth, int) and depth >= 3:
            issue_type = "deep_weak_inbound"
            priority = "medium"
            suggested_sources = _pick_sources(node)
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
                "depth": target_node.get("depth"),
                "suggested_sources": [
                    {
                        "url": source_url,
                        "path": urlparse(source_url).path or "/",
                        "inbound": int(node_by_url.get(source_url, {}).get("inbound", 0)),
                        "outbound": int(node_by_url.get(source_url, {}).get("outbound", 0)),
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

    elapsed_ms = int((time.time() - started_at) * 1000)

    return {
        "ok": True,
        "mesh": {
            "start_url": crawl_start,
            "host": start_host,
            "pages_scanned": len(nodes),
            "edges_count": len(edges_filtered),
            "max_pages": max_pages,
            "elapsed_ms": elapsed_ms,
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
                    "unreachable_from_start": unreachable_count,
                    "reachable_from_start": reachable_count,
                    "hreflang_pages": pages_with_hreflang,
                    "hreflang_non_reciprocal": hreflang_non_reciprocal_count,
                },
                "recommendations": recommendations,
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
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    max_pages = max(10, min(300, int(args.max_pages)))
    timeout = max(3, min(30, int(args.timeout)))
    max_edges = max(100, min(2000, int(args.max_edges)))

    try:
        payload = run_mesh(
            start_url=str(args.start_url),
            max_pages=max_pages,
            timeout=timeout,
            max_edges=max_edges,
        )
        return _json_out(payload)
    except Exception as exc:
        return _json_out({"ok": False, "error": f"Unexpected mesh error: {exc}"})


if __name__ == "__main__":
    sys.exit(main())
