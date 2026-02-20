#!/usr/bin/env python3
"""Audit SEO d'un sitemap (récursif) + scan robots.txt.

Usage:
  python seo_sitemap_checker.py --sitemap https://example.com/sitemap.xml
  python seo_sitemap_checker.py --sitemap https://example.com/sitemap_index.xml --output report.csv --workers 12
"""

from __future__ import annotations

import argparse
import csv
import gzip
import ipaddress
import json
import re
import socket
import sys
import time
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Dict, Iterable, List, Optional, Pattern, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener
import xml.etree.ElementTree as ET


TITLE_MIN = 30
TITLE_MAX = 60
DESC_MIN = 120
DESC_MAX = 160
THIN_CONTENT_WORDS = 250
RETRYABLE_HTTP_STATUSES = {408, 425, 429, 500, 502, 503, 504}
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
BLOCKED_HOSTS = {"localhost", "127.0.0.1", "::1"}
BLOCKED_HOST_SUFFIXES = (".local", ".localhost", ".internal", ".test", ".home.arpa")
MAX_REDIRECTS = 5
DNS_CACHE_TTL_SECONDS = 60
_DNS_CACHE: Dict[str, Tuple[float, List[str]]] = {}
HREFLANG_RE = re.compile(r"^(x-default|[a-z]{2,3}(?:-[a-z0-9]{2,8})*)$")


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int
    headers: Dict[str, str]
    body: bytes
    elapsed_ms: int
    error: Optional[str] = None


@dataclass
class RobotsRule:
    raw: str
    regex: Pattern[str]
    match_length: int


@dataclass
class RobotsPolicy:
    host: str
    source_url: str
    status: int
    fetch_error: str
    allow_rules: List[RobotsRule]
    disallow_rules: List[RobotsRule]
    sitemaps: List[str]


class SEOHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.meta_description = ""
        self.robots = ""
        self.h1_count = 0
        self.first_h1 = ""
        self.canonical = ""
        self.lang = ""
        self.images_missing_alt = 0
        self.word_count = 0
        self.hreflang_links: List[Tuple[str, str]] = []
        self.og_tags: Set[str] = set()
        self.twitter_tags: Set[str] = set()
        self.json_ld_count = 0
        self.json_ld_invalid_count = 0
        self.json_ld_types: Set[str] = set()

        self._in_title = False
        self._in_h1 = False
        self._ignored_tag_depth = 0
        self._title_parts: List[str] = []
        self._h1_parts: List[str] = []
        self._in_json_ld_script = False
        self._json_ld_parts: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        tag = tag.lower()
        attrs_dict = {k.lower(): (v or "") for k, v in attrs}

        if tag == "title":
            self._in_title = True
            self._title_parts = []

        if tag == "h1":
            self.h1_count += 1
            self._in_h1 = True
            self._h1_parts = []

        if tag in {"script", "style", "noscript"}:
            self._ignored_tag_depth += 1
            if tag == "script":
                script_type = attrs_dict.get("type", "").split(";", 1)[0].strip().lower()
                if script_type == "application/ld+json":
                    self._in_json_ld_script = True
                    self._json_ld_parts = []

        if tag == "meta":
            name = attrs_dict.get("name", "").strip().lower()
            prop = attrs_dict.get("property", "").strip().lower()
            if name == "description" and not self.meta_description:
                self.meta_description = attrs_dict.get("content", "").strip()
            if name == "robots" and not self.robots:
                self.robots = attrs_dict.get("content", "").strip().lower()

            if name.startswith("og:"):
                self.og_tags.add(name)
            if prop.startswith("og:"):
                self.og_tags.add(prop)
            if name.startswith("twitter:"):
                self.twitter_tags.add(name)
            if prop.startswith("twitter:"):
                self.twitter_tags.add(prop)

        if tag == "link":
            rel = attrs_dict.get("rel", "").strip().lower()
            rel_tokens = {token.strip() for token in rel.split() if token.strip()}
            if "canonical" in rel_tokens and not self.canonical:
                self.canonical = attrs_dict.get("href", "").strip()
            if "alternate" in rel_tokens:
                hreflang = attrs_dict.get("hreflang", "").strip().lower()
                href = attrs_dict.get("href", "").strip()
                if hreflang:
                    self.hreflang_links.append((hreflang, href))

        if tag == "img":
            alt = attrs_dict.get("alt")
            if alt is None or alt.strip() == "":
                self.images_missing_alt += 1

        if tag == "html" and not self.lang:
            self.lang = attrs_dict.get("lang", "").strip()

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
            self.title = " ".join(self._title_parts).strip()

        if tag == "h1":
            self._in_h1 = False
            if not self.first_h1:
                self.first_h1 = " ".join(self._h1_parts).strip()

        if tag in {"script", "style", "noscript"} and self._ignored_tag_depth > 0:
            if tag == "script" and self._in_json_ld_script:
                json_block = "".join(self._json_ld_parts).strip()
                if json_block:
                    try:
                        parsed = json.loads(json_block)
                        self.json_ld_count += 1
                        _collect_json_ld_types(parsed, self.json_ld_types)
                    except Exception:
                        self.json_ld_invalid_count += 1
                self._in_json_ld_script = False
                self._json_ld_parts = []
            self._ignored_tag_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._in_json_ld_script:
            self._json_ld_parts.append(data)

        text = data.strip()
        if not text:
            return

        if self._in_title:
            self._title_parts.append(text)

        if self._in_h1:
            self._h1_parts.append(text)

        if self._ignored_tag_depth == 0:
            words = re.findall(r"[A-Za-zÀ-ÿ0-9]+", text)
            self.word_count += len(words)


def _collect_json_ld_types(payload: object, out: Set[str]) -> None:
    if isinstance(payload, dict):
        value = payload.get("@type")
        if isinstance(value, str):
            out.add(value.strip())
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    out.add(item.strip())
        for child in payload.values():
            _collect_json_ld_types(child, out)
    elif isinstance(payload, list):
        for child in payload:
            _collect_json_ld_types(child, out)


def _decompress_if_needed(data: bytes, headers: Dict[str, str]) -> bytes:
    encoding = headers.get("content-encoding", "").lower()
    try:
        if "gzip" in encoding:
            return gzip.decompress(data)
        if "deflate" in encoding:
            return zlib.decompress(data)
    except Exception:
        return data
    return data


def _decode_body(data: bytes, headers: Dict[str, str]) -> str:
    content_type = headers.get("content-type", "")
    charset = None
    if "charset=" in content_type:
        charset = content_type.split("charset=", 1)[1].split(";", 1)[0].strip()

    if charset:
        try:
            return data.decode(charset, errors="replace")
        except Exception:
            pass

    for candidate in ("utf-8", "iso-8859-1"):
        try:
            return data.decode(candidate, errors="replace")
        except Exception:
            continue
    return data.decode(errors="replace")


def _host_key(url: str) -> str:
    parsed = urlparse(url)
    if parsed.netloc:
        return parsed.netloc.lower()
    return ""


def _hostname(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.hostname or "").lower()


def _base_url(url: str) -> Optional[str]:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _looks_like_sitemap_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    if path.endswith(".xml") or path.endswith(".xml.gz"):
        return True
    return "sitemap" in path


def _is_public_ip(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False

    if parsed.is_private or parsed.is_loopback or parsed.is_link_local:
        return False
    if parsed.is_reserved or parsed.is_multicast or parsed.is_unspecified:
        return False
    return True


def _resolve_host_ips(hostname: str) -> List[str]:
    now = time.time()
    cached = _DNS_CACHE.get(hostname)
    if cached and (now - cached[0]) <= DNS_CACHE_TTL_SECONDS:
        return cached[1]

    resolved: Set[str] = set()
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        infos = []

    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip = sockaddr[0]
        if ip:
            resolved.add(ip)

    resolved_list = sorted(resolved)
    _DNS_CACHE[hostname] = (now, resolved_list)
    return resolved_list


def _validate_url_for_ssrf(url: str) -> Tuple[bool, str]:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        return False, f"schema non autorise: {scheme or 'vide'}"

    if parsed.username or parsed.password:
        return False, "credentials dans URL non autorisees"

    host = (parsed.hostname or "").lower()
    if not host:
        return False, "host manquant"

    if host in BLOCKED_HOSTS:
        return False, f"host bloque: {host}"

    for suffix in BLOCKED_HOST_SUFFIXES:
        if host.endswith(suffix):
            return False, f"suffixe host bloque: {suffix}"

    if parsed.port is not None and (parsed.port < 1 or parsed.port > 65535):
        return False, "port invalide"

    if re.match(r"^\\d+\\.\\d+\\.\\d+\\.\\d+$", host) or ":" in host:
        if not _is_public_ip(host):
            return False, f"IP non publique: {host}"
        return True, ""

    ips = _resolve_host_ips(host)
    if not ips:
        return False, f"resolution DNS impossible: {host}"

    for ip in ips:
        if not _is_public_ip(ip):
            return False, f"host resolu vers IP non publique: {ip}"

    return True, ""


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def _fetch_once_follow_redirects(url: str, timeout: int, headers: Dict[str, str]) -> FetchResult:
    opener = build_opener(_NoRedirectHandler())
    start = time.perf_counter()
    current_url = url
    seen_urls: Set[str] = set()

    for _ in range(MAX_REDIRECTS + 1):
        is_allowed, reason = _validate_url_for_ssrf(current_url)
        if not is_allowed:
            elapsed = int((time.perf_counter() - start) * 1000)
            return FetchResult(
                url=url,
                final_url=current_url,
                status=0,
                headers={},
                body=b"",
                elapsed_ms=elapsed,
                error=f"URL bloquee (SSRF): {reason}",
            )

        seen_urls.add(current_url)
        req = Request(current_url, headers=headers)
        try:
            with opener.open(req, timeout=timeout) as response:
                raw = response.read()
                status = response.getcode() or 0
                final_url = response.geturl()
                resp_headers = {k.lower(): v for k, v in response.headers.items()}

            raw = _decompress_if_needed(raw, resp_headers)
            elapsed = int((time.perf_counter() - start) * 1000)
            return FetchResult(
                url=url,
                final_url=final_url,
                status=status,
                headers=resp_headers,
                body=raw,
                elapsed_ms=elapsed,
                error=None,
            )
        except HTTPError as exc:
            status = exc.code or 0
            headers_map = {k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])}

            if status in REDIRECT_STATUSES:
                location = headers_map.get("location", "").strip()
                if not location:
                    elapsed = int((time.perf_counter() - start) * 1000)
                    return FetchResult(
                        url=url,
                        final_url=current_url,
                        status=status,
                        headers=headers_map,
                        body=b"",
                        elapsed_ms=elapsed,
                        error="redirection sans en-tete Location",
                    )

                next_url = urljoin(current_url, location)
                if next_url in seen_urls:
                    elapsed = int((time.perf_counter() - start) * 1000)
                    return FetchResult(
                        url=url,
                        final_url=current_url,
                        status=status,
                        headers=headers_map,
                        body=b"",
                        elapsed_ms=elapsed,
                        error="boucle de redirection detectee",
                    )
                current_url = next_url
                continue

            try:
                raw = exc.read()
            except Exception:
                raw = b""

            raw = _decompress_if_needed(raw, headers_map)
            elapsed = int((time.perf_counter() - start) * 1000)
            return FetchResult(
                url=url,
                final_url=getattr(exc, "url", current_url),
                status=status,
                headers=headers_map,
                body=raw,
                elapsed_ms=elapsed,
                error=f"HTTP Error {status}: {getattr(exc, 'reason', 'Unknown')}",
            )
        except URLError as exc:
            elapsed = int((time.perf_counter() - start) * 1000)
            return FetchResult(
                url=url,
                final_url=current_url,
                status=0,
                headers={},
                body=b"",
                elapsed_ms=elapsed,
                error=f"URL Error: {exc.reason}",
            )
        except Exception as exc:
            elapsed = int((time.perf_counter() - start) * 1000)
            return FetchResult(
                url=url,
                final_url=current_url,
                status=0,
                headers={},
                body=b"",
                elapsed_ms=elapsed,
                error=str(exc),
            )

    elapsed = int((time.perf_counter() - start) * 1000)
    return FetchResult(
        url=url,
        final_url=current_url,
        status=0,
        headers={},
        body=b"",
        elapsed_ms=elapsed,
        error=f"trop de redirections (>{MAX_REDIRECTS})",
    )


def fetch_url(
    url: str,
    timeout: int,
    user_agent: str,
    retries: int = 2,
    retry_backoff: float = 0.6,
) -> FetchResult:
    headers = {
        "User-Agent": user_agent,
        "Accept": "application/xml,text/xml,text/html;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate",
    }

    attempts = max(1, retries + 1)

    for attempt in range(attempts):
        result = _fetch_once_follow_redirects(url, timeout, headers)
        error_lower = (result.error or "").lower()

        should_retry = (
            result.status in RETRYABLE_HTTP_STATUSES
            or (result.status == 0 and result.error and "bloquee (ssrf)" not in error_lower)
        )

        if attempt < attempts - 1 and should_retry:
            time.sleep(retry_backoff * (2 ** attempt))
            continue
        return result

    return FetchResult(
        url=url,
        final_url=url,
        status=0,
        headers={},
        body=b"",
        elapsed_ms=0,
        error="Unknown fetch error",
    )


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def parse_sitemap(xml_text: str) -> Tuple[List[str], List[str]]:
    child_sitemaps: List[str] = []
    page_urls: List[str] = []

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        # Fallback: certains sitemaps sont un simple fichier texte (1 URL par ligne).
        urls = re.findall(r"https?://[^\s<\"']+", xml_text)
        for found in urls:
            if _looks_like_sitemap_url(found):
                child_sitemaps.append(found)
            else:
                page_urls.append(found)
        return child_sitemaps, page_urls

    root_name = _local_name(root.tag)

    if root_name == "sitemapindex":
        for sitemap in root:
            if _local_name(sitemap.tag) != "sitemap":
                continue
            for child in sitemap:
                if _local_name(child.tag) == "loc" and child.text:
                    loc = child.text.strip()
                    if loc:
                        child_sitemaps.append(loc)

    elif root_name == "urlset":
        for url in root:
            if _local_name(url.tag) != "url":
                continue
            for child in url:
                if _local_name(child.tag) == "loc" and child.text:
                    loc = child.text.strip()
                    if loc:
                        page_urls.append(loc)

    else:
        # Format XML non standard: essaie de récupérer tous les <loc>.
        for elem in root.iter():
            if _local_name(elem.tag) == "loc" and elem.text:
                loc = elem.text.strip()
                if not loc:
                    continue
                if _looks_like_sitemap_url(loc):
                    child_sitemaps.append(loc)
                else:
                    page_urls.append(loc)

    return child_sitemaps, page_urls


def same_domain(url_a: str, url_b: str) -> bool:
    return _hostname(url_a) == _hostname(url_b)


def crawl_sitemap(
    start_sitemap: str,
    timeout: int,
    user_agent: str,
    max_urls: int,
    allow_external: bool,
    retries: int,
    retry_backoff: float,
) -> Tuple[List[str], List[str]]:
    visited: Set[str] = set()
    to_visit = [start_sitemap]
    pages: Set[str] = set()
    errors: List[str] = []

    while to_visit:
        sitemap_url = to_visit.pop()
        if sitemap_url in visited:
            continue
        visited.add(sitemap_url)

        result = fetch_url(
            sitemap_url,
            timeout=timeout,
            user_agent=user_agent,
            retries=retries,
            retry_backoff=retry_backoff,
        )

        if result.error or result.status >= 400:
            errors.append(
                f"Sitemap inaccessible: {sitemap_url} "
                f"(status={result.status}, erreur={result.error or 'N/A'})"
            )
            continue

        text = _decode_body(result.body, result.headers)
        child_sitemaps, page_urls = parse_sitemap(text)

        for child in child_sitemaps:
            if not allow_external and not same_domain(start_sitemap, child):
                continue
            if child not in visited:
                to_visit.append(child)

        for page in page_urls:
            if not allow_external and not same_domain(start_sitemap, page):
                continue
            pages.add(page)
            if max_urls > 0 and len(pages) >= max_urls:
                return sorted(pages), errors

    return sorted(pages), errors


def _build_robots_rule(pattern: str) -> Optional[RobotsRule]:
    raw = pattern.strip()
    if raw == "":
        return None

    ends_with_anchor = raw.endswith("$")
    if ends_with_anchor:
        raw = raw[:-1]

    escaped = re.escape(raw).replace(r"\*", ".*")
    regex_source = f"^{escaped}"
    if ends_with_anchor:
        regex_source += "$"

    try:
        compiled = re.compile(regex_source)
    except re.error:
        return None

    match_length = len(raw.replace("*", ""))
    return RobotsRule(raw=pattern, regex=compiled, match_length=match_length)


def parse_robots_txt(content: str, user_agent: str) -> Tuple[List[RobotsRule], List[RobotsRule], List[str]]:
    lines = content.splitlines()
    groups: List[Tuple[List[str], List[Tuple[str, str]]]] = []
    sitemaps: List[str] = []

    current_agents: List[str] = []
    current_rules: List[Tuple[str, str]] = []
    has_rules_in_current_group = False

    for raw_line in lines:
        cleaned = raw_line.split("#", 1)[0].strip()
        if not cleaned or ":" not in cleaned:
            continue

        key, value = cleaned.split(":", 1)
        key = key.strip().lower()
        value = value.strip()

        if key == "user-agent":
            if has_rules_in_current_group:
                groups.append((current_agents, current_rules))
                current_agents = []
                current_rules = []
                has_rules_in_current_group = False
            current_agents.append(value.lower())
        elif key in {"allow", "disallow"}:
            if not current_agents:
                continue
            current_rules.append((key, value))
            has_rules_in_current_group = True
        elif key == "sitemap" and value:
            sitemaps.append(value)

    if current_agents or current_rules:
        groups.append((current_agents, current_rules))

    normalized_agent = user_agent.lower()
    normalized_agent_token = normalized_agent.split("/", 1)[0]

    wildcard_rules: List[Tuple[str, str]] = []
    specific_rules: List[Tuple[str, str]] = []

    for agents, rules in groups:
        normalized_agents = [a.strip().lower() for a in agents if a.strip()]
        if not normalized_agents:
            continue

        if "*" in normalized_agents:
            wildcard_rules.extend(rules)

        for agent in normalized_agents:
            if agent == "*":
                continue
            if normalized_agent.startswith(agent) or normalized_agent_token.startswith(agent):
                specific_rules.extend(rules)
                break

    selected_rules = specific_rules + wildcard_rules if specific_rules else wildcard_rules

    allow_rules: List[RobotsRule] = []
    disallow_rules: List[RobotsRule] = []

    for directive, value in selected_rules:
        built = _build_robots_rule(value)
        if not built:
            continue
        if directive == "allow":
            allow_rules.append(built)
        else:
            disallow_rules.append(built)

    return allow_rules, disallow_rules, sitemaps


def is_blocked_by_robots(path: str, policy: RobotsPolicy) -> bool:
    if policy.status != 200 or policy.fetch_error:
        return False

    normalized_path = path or "/"

    best_allow = -1
    best_disallow = -1

    for rule in policy.allow_rules:
        if rule.regex.match(normalized_path):
            best_allow = max(best_allow, rule.match_length)

    for rule in policy.disallow_rules:
        if rule.regex.match(normalized_path):
            best_disallow = max(best_disallow, rule.match_length)

    return best_disallow >= 0 and best_disallow > best_allow


def scan_robots_txt(
    start_sitemap: str,
    page_urls: List[str],
    timeout: int,
    user_agent: str,
    retries: int,
    retry_backoff: float,
) -> Dict[str, RobotsPolicy]:
    bases: Set[str] = set()

    start_base = _base_url(start_sitemap)
    if start_base:
        bases.add(start_base)

    for page_url in page_urls:
        base = _base_url(page_url)
        if base:
            bases.add(base)

    policies: Dict[str, RobotsPolicy] = {}

    for base in sorted(bases):
        host = _host_key(base)
        robots_url = f"{base.rstrip('/')}/robots.txt"
        result = fetch_url(
            robots_url,
            timeout=timeout,
            user_agent=user_agent,
            retries=retries,
            retry_backoff=retry_backoff,
        )

        if result.error and result.status == 0:
            policies[host] = RobotsPolicy(
                host=host,
                source_url=robots_url,
                status=0,
                fetch_error=result.error,
                allow_rules=[],
                disallow_rules=[],
                sitemaps=[],
            )
            continue

        if result.status == 404:
            policies[host] = RobotsPolicy(
                host=host,
                source_url=robots_url,
                status=404,
                fetch_error="",
                allow_rules=[],
                disallow_rules=[],
                sitemaps=[],
            )
            continue

        if result.status >= 400:
            policies[host] = RobotsPolicy(
                host=host,
                source_url=robots_url,
                status=result.status,
                fetch_error=result.error or f"HTTP {result.status}",
                allow_rules=[],
                disallow_rules=[],
                sitemaps=[],
            )
            continue

        text = _decode_body(result.body, result.headers)
        allow_rules, disallow_rules, sitemaps = parse_robots_txt(text, user_agent)
        policies[host] = RobotsPolicy(
            host=host,
            source_url=robots_url,
            status=result.status,
            fetch_error="",
            allow_rules=allow_rules,
            disallow_rules=disallow_rules,
            sitemaps=sitemaps,
        )

    return policies


def append_issue(row: Dict[str, object], issue: str) -> None:
    existing = str(row.get("issues", "")).strip()
    if not existing:
        row["issues"] = issue
        return

    existing_items = [item.strip() for item in existing.split(" | ") if item.strip()]
    if issue in existing_items:
        return

    existing_items.append(issue)
    row["issues"] = " | ".join(existing_items)


def _extract_count_from_issue(issue: str) -> int:
    match = re.search(r"\((\d+)", issue)
    if not match:
        return 1
    try:
        return int(match.group(1))
    except ValueError:
        return 1


def _issue_weight(issue: str) -> int:
    normalized = issue.lower().strip()

    if normalized.startswith("erreur requête") or normalized.startswith("erreur parsing html"):
        return 45
    if normalized.startswith("http "):
        return 35
    if "noindex" in normalized:
        return 34
    if normalized == "bloquée par robots.txt":
        return 34
    if normalized == "conflit sitemap/indexation":
        return 28
    if normalized.startswith("canonical cross-domain"):
        return 24
    if normalized == "canonical invalide":
        return 22
    if normalized == "canonical manquant":
        return 18
    if normalized == "title manquant":
        return 20
    if normalized == "meta description manquante":
        return 16
    if normalized == "h1 manquant":
        return 14
    if normalized.startswith("url non https"):
        return 12
    if normalized.startswith("title trop"):
        return 7
    if normalized.startswith("meta description trop"):
        return 6
    if normalized.startswith("h1 multiples"):
        return 7
    if normalized.startswith("attribut lang manquant"):
        return 6
    if normalized.startswith("contenu léger"):
        return 5
    if normalized.startswith("hreflang invalide"):
        return 8
    if normalized.startswith("hreflang dupliqué"):
        return 7
    if normalized.startswith("hreflang sans href"):
        return 7
    if normalized == "hreflang absent":
        return 4
    if normalized == "open graph incomplet":
        return 5
    if normalized == "twitter card incomplet":
        return 4
    if normalized.startswith("json-ld invalide"):
        return 8
    if normalized == "json-ld absent":
        return 5
    if normalized.startswith("images sans alt"):
        return min(14, 4 + _extract_count_from_issue(issue) // 8)
    if normalized.startswith("title dupliqué") or normalized.startswith("meta description dupliquée"):
        return 8
    if normalized.startswith("h1 dupliqué"):
        return 6
    if "nofollow" in normalized:
        return 6
    return 5


def _priority_level_from_score(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 45:
        return "high"
    if score >= 20:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def compute_priority_for_row(row: Dict[str, object]) -> None:
    raw_issues = str(row.get("issues", "")).strip()
    if not raw_issues:
        row["priority_score"] = 0
        row["priority_level"] = "none"
        return

    issues = [part.strip() for part in raw_issues.split(" | ") if part.strip()]
    unique_issues = list(dict.fromkeys(issues))
    score = sum(_issue_weight(issue) for issue in unique_issues)
    score = min(100, score)

    row["priority_score"] = score
    row["priority_level"] = _priority_level_from_score(score)


def _analyze_hreflang_links(links: List[Tuple[str, str]]) -> Dict[str, object]:
    values = [value.strip().lower() for value, _ in links if value.strip()]
    values_non_empty = [value for value in values if value]

    invalid_count = 0
    missing_href_count = 0
    for hreflang, href in links:
        normalized = hreflang.strip().lower()
        if not HREFLANG_RE.fullmatch(normalized):
            invalid_count += 1
        if not href.strip():
            missing_href_count += 1

    occurrences: Dict[str, int] = {}
    for value in values_non_empty:
        occurrences[value] = occurrences.get(value, 0) + 1

    duplicate_count = sum(max(0, count - 1) for count in occurrences.values())
    values_unique = sorted(occurrences.keys())

    return {
        "count": len(values_non_empty),
        "values": ",".join(values_unique),
        "invalid_count": invalid_count,
        "missing_href_count": missing_href_count,
        "duplicate_count": duplicate_count,
        "has_x_default": "x-default" in occurrences,
    }


def _analyze_canonical(canonical: str, final_url: str) -> Dict[str, object]:
    canonical = canonical.strip()
    if not canonical:
        return {
            "resolved_url": "",
            "host": "",
            "is_cross_domain": False,
            "is_invalid": False,
        }

    resolved = urljoin(final_url, canonical)
    parsed = urlparse(resolved)
    final_host = (urlparse(final_url).hostname or "").lower()
    canonical_host = (parsed.hostname or "").lower()
    scheme = parsed.scheme.lower()

    invalid = scheme not in {"http", "https"} or canonical_host == ""
    cross_domain = bool(final_host and canonical_host and canonical_host != final_host)

    return {
        "resolved_url": resolved,
        "host": canonical_host,
        "is_cross_domain": cross_domain,
        "is_invalid": invalid,
    }


def evaluate_issues(data: Dict[str, object]) -> List[str]:
    issues: List[str] = []

    status = int(data.get("status", 0))
    if status != 200:
        issues.append(f"HTTP {status}")

    url = str(data.get("url", ""))
    if url and not url.lower().startswith("https://"):
        issues.append("URL non HTTPS")

    title_len = int(data.get("title_length", 0))
    if title_len == 0:
        issues.append("Title manquant")
    elif title_len < TITLE_MIN:
        issues.append(f"Title trop court ({title_len})")
    elif title_len > TITLE_MAX:
        issues.append(f"Title trop long ({title_len})")

    desc_len = int(data.get("meta_description_length", 0))
    if desc_len == 0:
        issues.append("Meta description manquante")
    elif desc_len < DESC_MIN:
        issues.append(f"Meta description trop courte ({desc_len})")
    elif desc_len > DESC_MAX:
        issues.append(f"Meta description trop longue ({desc_len})")

    h1_count = int(data.get("h1_count", 0))
    if h1_count == 0:
        issues.append("H1 manquant")
    elif h1_count > 1:
        issues.append(f"H1 multiples ({h1_count})")

    canonical = str(data.get("canonical", ""))
    if not canonical:
        issues.append("Canonical manquant")
    else:
        if bool(data.get("canonical_invalid", False)):
            issues.append("Canonical invalide")
        elif bool(data.get("canonical_cross_domain", False)):
            canonical_host = str(data.get("canonical_host", "")).strip()
            if canonical_host:
                issues.append(f"Canonical cross-domain ({canonical_host})")
            else:
                issues.append("Canonical cross-domain")

    hreflang_count = int(data.get("hreflang_count", 0))
    if hreflang_count == 0:
        issues.append("Hreflang absent")
    hreflang_invalid_count = int(data.get("hreflang_invalid_count", 0))
    if hreflang_invalid_count > 0:
        issues.append(f"Hreflang invalide ({hreflang_invalid_count})")
    hreflang_duplicate_count = int(data.get("hreflang_duplicate_count", 0))
    if hreflang_duplicate_count > 0:
        issues.append(f"Hreflang dupliqué ({hreflang_duplicate_count})")
    hreflang_missing_href_count = int(data.get("hreflang_missing_href_count", 0))
    if hreflang_missing_href_count > 0:
        issues.append(f"Hreflang sans href ({hreflang_missing_href_count})")

    if not bool(data.get("og_complete", False)):
        issues.append("Open Graph incomplet")
    if not bool(data.get("twitter_complete", False)):
        issues.append("Twitter card incomplet")

    json_ld_count = int(data.get("json_ld_count", 0))
    if json_ld_count == 0:
        issues.append("JSON-LD absent")
    json_ld_invalid_count = int(data.get("json_ld_invalid_count", 0))
    if json_ld_invalid_count > 0:
        issues.append(f"JSON-LD invalide ({json_ld_invalid_count})")

    robots = str(data.get("robots_meta", "")).lower()
    if "noindex" in robots:
        issues.append("Meta robots noindex")
    if "nofollow" in robots:
        issues.append("Meta robots nofollow")

    x_robots = str(data.get("x_robots_tag", "")).lower()
    if "noindex" in x_robots:
        issues.append("X-Robots-Tag noindex")
    if "nofollow" in x_robots:
        issues.append("X-Robots-Tag nofollow")

    if not str(data.get("lang", "")).strip():
        issues.append("Attribut lang manquant")

    images_missing_alt = int(data.get("images_missing_alt", 0))
    if images_missing_alt > 0:
        issues.append(f"Images sans alt ({images_missing_alt})")

    word_count = int(data.get("word_count", 0))
    if word_count > 0 and word_count < THIN_CONTENT_WORDS:
        issues.append(f"Contenu léger ({word_count} mots)")

    if bool(data.get("robots_txt_blocked", False)):
        issues.append("Bloquée par robots.txt")

    if bool(data.get("sitemap_indexation_conflict", False)):
        issues.append("Conflit sitemap/indexation")

    return issues


def analyze_page(
    url: str,
    timeout: int,
    user_agent: str,
    retries: int,
    retry_backoff: float,
    robots_policies: Dict[str, RobotsPolicy],
) -> Dict[str, object]:
    result = fetch_url(
        url,
        timeout=timeout,
        user_agent=user_agent,
        retries=retries,
        retry_backoff=retry_backoff,
    )

    host = _host_key(result.final_url or url)
    robots_policy = robots_policies.get(host)

    robots_status = robots_policy.status if robots_policy else 0
    robots_source = robots_policy.source_url if robots_policy else ""
    robots_error = robots_policy.fetch_error if robots_policy else ""
    robots_sitemaps_count = len(robots_policy.sitemaps) if robots_policy else 0

    path_for_robots = urlparse(result.final_url or url).path or "/"
    robots_blocked = is_blocked_by_robots(path_for_robots, robots_policy) if robots_policy else False

    row: Dict[str, object] = {
        "url": url,
        "final_url": result.final_url,
        "status": result.status,
        "load_ms": result.elapsed_ms,
        "title": "",
        "title_length": 0,
        "meta_description": "",
        "meta_description_length": 0,
        "h1_count": 0,
        "first_h1": "",
        "first_h1_length": 0,
        "canonical": "",
        "canonical_resolved_url": "",
        "canonical_host": "",
        "canonical_cross_domain": False,
        "canonical_invalid": False,
        "lang": "",
        "hreflang_count": 0,
        "hreflang_values": "",
        "hreflang_invalid_count": 0,
        "hreflang_missing_href_count": 0,
        "hreflang_duplicate_count": 0,
        "hreflang_has_x_default": False,
        "robots_meta": "",
        "x_robots_tag": result.headers.get("x-robots-tag", "").strip().lower(),
        "og_title_present": False,
        "og_description_present": False,
        "og_type_present": False,
        "og_url_present": False,
        "og_complete": False,
        "twitter_card_present": False,
        "twitter_title_present": False,
        "twitter_description_present": False,
        "twitter_complete": False,
        "json_ld_count": 0,
        "json_ld_invalid_count": 0,
        "json_ld_types": "",
        "images_missing_alt": 0,
        "word_count": 0,
        "robots_txt_url": robots_source,
        "robots_txt_status": robots_status,
        "robots_txt_blocked": robots_blocked,
        "robots_txt_fetch_error": robots_error,
        "robots_txt_sitemaps_count": robots_sitemaps_count,
        "sitemap_indexation_conflict": False,
        "sitemap_indexation_conflict_reasons": "",
        "duplicate_title_count": 1,
        "duplicate_meta_description_count": 1,
        "duplicate_first_h1_count": 1,
        "is_indexable": False,
        "issues": "",
        "fetch_error": result.error or "",
    }

    if result.error:
        row["issues"] = f"Erreur requête: {result.error}"
        return row

    html = _decode_body(result.body, result.headers)

    parser = SEOHTMLParser()
    try:
        parser.feed(html)
    except Exception as exc:
        row["issues"] = f"Erreur parsing HTML: {exc}"
        return row

    row.update(
        {
            "title": parser.title,
            "title_length": len(parser.title),
            "meta_description": parser.meta_description,
            "meta_description_length": len(parser.meta_description),
            "h1_count": parser.h1_count,
            "first_h1": parser.first_h1,
            "first_h1_length": len(parser.first_h1),
            "canonical": parser.canonical,
            "lang": parser.lang,
            "robots_meta": parser.robots,
            "og_title_present": "og:title" in parser.og_tags,
            "og_description_present": "og:description" in parser.og_tags,
            "og_type_present": "og:type" in parser.og_tags,
            "og_url_present": "og:url" in parser.og_tags,
            "twitter_card_present": "twitter:card" in parser.twitter_tags,
            "twitter_title_present": "twitter:title" in parser.twitter_tags,
            "twitter_description_present": "twitter:description" in parser.twitter_tags,
            "json_ld_count": parser.json_ld_count,
            "json_ld_invalid_count": parser.json_ld_invalid_count,
            "json_ld_types": ",".join(sorted(t for t in parser.json_ld_types if t.strip())),
            "images_missing_alt": parser.images_missing_alt,
            "word_count": parser.word_count,
        }
    )

    hreflang_info = _analyze_hreflang_links(parser.hreflang_links)
    row.update(
        {
            "hreflang_count": hreflang_info["count"],
            "hreflang_values": hreflang_info["values"],
            "hreflang_invalid_count": hreflang_info["invalid_count"],
            "hreflang_missing_href_count": hreflang_info["missing_href_count"],
            "hreflang_duplicate_count": hreflang_info["duplicate_count"],
            "hreflang_has_x_default": hreflang_info["has_x_default"],
        }
    )

    canonical_info = _analyze_canonical(parser.canonical, result.final_url or url)
    row.update(
        {
            "canonical_resolved_url": canonical_info["resolved_url"],
            "canonical_host": canonical_info["host"],
            "canonical_cross_domain": canonical_info["is_cross_domain"],
            "canonical_invalid": canonical_info["is_invalid"],
        }
    )

    row["og_complete"] = bool(row["og_title_present"] and row["og_description_present"] and row["og_type_present"])
    row["twitter_complete"] = bool(
        row["twitter_card_present"] and (row["twitter_title_present"] or row["twitter_description_present"])
    )

    conflict_reasons: List[str] = []
    robots_meta_value = str(row.get("robots_meta", "")).lower()
    x_robots_value = str(row.get("x_robots_tag", "")).lower()
    if robots_blocked:
        conflict_reasons.append("robots.txt blocked")
    if "noindex" in robots_meta_value:
        conflict_reasons.append("meta robots noindex")
    if "noindex" in x_robots_value:
        conflict_reasons.append("x-robots-tag noindex")

    if conflict_reasons:
        row["sitemap_indexation_conflict"] = True
        row["sitemap_indexation_conflict_reasons"] = " | ".join(conflict_reasons)

    issues = evaluate_issues(row)
    row["issues"] = " | ".join(issues)

    has_noindex = "noindex" in robots_meta_value or "noindex" in x_robots_value
    row["is_indexable"] = result.status == 200 and not has_noindex and not robots_blocked
    return row


def _normalize_for_duplicate(value: object) -> str:
    text = str(value or "")
    text = re.sub(r"\s+", " ", text).strip().lower()
    return text


def mark_sitewide_duplicates(rows: List[Dict[str, object]]) -> None:
    fields = [
        ("title", "duplicate_title_count", "Title dupliqué"),
        ("meta_description", "duplicate_meta_description_count", "Meta description dupliquée"),
        ("first_h1", "duplicate_first_h1_count", "H1 dupliqué"),
    ]

    for source_field, counter_field, issue_label in fields:
        counts: Dict[str, int] = {}
        for row in rows:
            value = _normalize_for_duplicate(row.get(source_field, ""))
            if not value:
                continue
            counts[value] = counts.get(value, 0) + 1

        for row in rows:
            value = _normalize_for_duplicate(row.get(source_field, ""))
            duplicate_count = counts.get(value, 1) if value else 1
            row[counter_field] = duplicate_count
            if duplicate_count > 1:
                append_issue(row, f"{issue_label} ({duplicate_count} pages)")


def apply_priority_scoring(rows: List[Dict[str, object]]) -> None:
    for row in rows:
        compute_priority_for_row(row)


def build_sitemap_indexation_conflicts(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    conflicts: List[Dict[str, object]] = []
    for row in rows:
        if not bool(row.get("sitemap_indexation_conflict", False)):
            continue
        conflicts.append(
            {
                "url": row.get("url", ""),
                "final_url": row.get("final_url", ""),
                "status": row.get("status", 0),
                "is_indexable": row.get("is_indexable", False),
                "sitemap_indexation_conflict_reasons": row.get("sitemap_indexation_conflict_reasons", ""),
                "robots_txt_blocked": row.get("robots_txt_blocked", False),
                "robots_meta": row.get("robots_meta", ""),
                "x_robots_tag": row.get("x_robots_tag", ""),
            }
        )
    return conflicts


def _conflicts_output_path(report_path: str) -> str:
    if report_path.lower().endswith(".csv"):
        return report_path[:-4] + "_sitemap_indexation_conflicts.csv"
    return report_path + "_sitemap_indexation_conflicts.csv"


def write_conflicts_csv(path: str, rows: List[Dict[str, object]]) -> None:
    fieldnames = [
        "url",
        "final_url",
        "status",
        "is_indexable",
        "sitemap_indexation_conflict_reasons",
        "robots_txt_blocked",
        "robots_meta",
        "x_robots_tag",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_csv(path: str, rows: Iterable[Dict[str, object]]) -> None:
    fieldnames = [
        "url",
        "final_url",
        "status",
        "load_ms",
        "is_indexable",
        "title",
        "title_length",
        "meta_description",
        "meta_description_length",
        "h1_count",
        "first_h1",
        "first_h1_length",
        "canonical",
        "canonical_resolved_url",
        "canonical_host",
        "canonical_cross_domain",
        "canonical_invalid",
        "lang",
        "hreflang_count",
        "hreflang_values",
        "hreflang_invalid_count",
        "hreflang_missing_href_count",
        "hreflang_duplicate_count",
        "hreflang_has_x_default",
        "robots_meta",
        "x_robots_tag",
        "og_title_present",
        "og_description_present",
        "og_type_present",
        "og_url_present",
        "og_complete",
        "twitter_card_present",
        "twitter_title_present",
        "twitter_description_present",
        "twitter_complete",
        "json_ld_count",
        "json_ld_invalid_count",
        "json_ld_types",
        "images_missing_alt",
        "word_count",
        "robots_txt_url",
        "robots_txt_status",
        "robots_txt_blocked",
        "robots_txt_fetch_error",
        "robots_txt_sitemaps_count",
        "sitemap_indexation_conflict",
        "sitemap_indexation_conflict_reasons",
        "duplicate_title_count",
        "duplicate_meta_description_count",
        "duplicate_first_h1_count",
        "priority_score",
        "priority_level",
        "issues",
        "fetch_error",
    ]

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def summarize_robots(policies: Dict[str, RobotsPolicy]) -> None:
    if not policies:
        print("\nScan robots.txt: aucun domaine détecté")
        return

    print("\nScan robots.txt:")
    for host in sorted(policies):
        policy = policies[host]
        if policy.fetch_error:
            print(f"- {host}: erreur ({policy.fetch_error})")
            continue

        if policy.status == 404:
            print(f"- {host}: robots.txt absent (404)")
            continue

        print(
            f"- {host}: HTTP {policy.status}, "
            f"allow={len(policy.allow_rules)}, disallow={len(policy.disallow_rules)}, "
            f"sitemaps={len(policy.sitemaps)}"
        )


def summarize(rows: List[Dict[str, object]]) -> None:
    total = len(rows)
    bad = [r for r in rows if str(r.get("issues", "")).strip()]
    ok = total - len(bad)

    print(f"\nPages analysées : {total}")
    print(f"Pages sans alerte SEO : {ok}")
    print(f"Pages avec alerte(s) : {len(bad)}")
    conflicts_count = sum(1 for row in rows if bool(row.get("sitemap_indexation_conflict", False)))
    print(f"Conflits sitemap/indexation : {conflicts_count}")
    priority_counts: Dict[str, int] = {}
    for row in rows:
        level = str(row.get("priority_level", "none")).lower()
        priority_counts[level] = priority_counts.get(level, 0) + 1

    print(
        "Priorités : "
        f"critical={priority_counts.get('critical', 0)}, "
        f"high={priority_counts.get('high', 0)}, "
        f"medium={priority_counts.get('medium', 0)}, "
        f"low={priority_counts.get('low', 0)}, "
        f"none={priority_counts.get('none', 0)}"
    )

    issue_counts: Dict[str, int] = {}
    for row in bad:
        for issue in str(row.get("issues", "")).split(" | "):
            issue = issue.strip()
            if not issue:
                continue
            issue_counts[issue] = issue_counts.get(issue, 0) + 1

    if issue_counts:
        print("\nTop problèmes détectés :")
        for issue, count in sorted(issue_counts.items(), key=lambda x: x[1], reverse=True)[:12]:
            print(f"- {issue}: {count}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit SEO récursif depuis un sitemap")
    parser.add_argument("--sitemap", required=True, help="URL du sitemap principal")
    parser.add_argument("--output", default="seo_report.csv", help="Chemin du CSV de sortie")
    parser.add_argument("--timeout", type=int, default=15, help="Timeout HTTP en secondes")
    parser.add_argument("--workers", type=int, default=8, help="Nombre de workers paralleles")
    parser.add_argument(
        "--max-urls",
        type=int,
        default=0,
        help="Limite du nombre de pages à auditer (0 = pas de limite)",
    )
    parser.add_argument(
        "--allow-external",
        action="store_true",
        help="Autorise les URLs hors domaine du sitemap de départ",
    )
    parser.add_argument(
        "--user-agent",
        default="SEO-Sitemap-Checker/2.0 (+https://localhost)",
        help="User-Agent HTTP",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="Nombre de retries HTTP après la tentative initiale",
    )
    parser.add_argument(
        "--retry-backoff",
        type=float,
        default=0.6,
        help="Backoff de base en secondes pour les retries (exponentiel)",
    )
    parser.add_argument(
        "--skip-robots-txt",
        action="store_true",
        help="Désactive le scan robots.txt",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    print(f"[1/4] Crawl sitemap récursif : {args.sitemap}")
    pages, sitemap_errors = crawl_sitemap(
        start_sitemap=args.sitemap,
        timeout=args.timeout,
        user_agent=args.user_agent,
        max_urls=args.max_urls,
        allow_external=args.allow_external,
        retries=args.retries,
        retry_backoff=args.retry_backoff,
    )

    for err in sitemap_errors:
        print(f"WARN: {err}", file=sys.stderr)

    if not pages:
        print("Aucune page trouvée dans le sitemap.", file=sys.stderr)
        return 1

    robots_policies: Dict[str, RobotsPolicy] = {}
    if args.skip_robots_txt:
        print("[2/4] Scan robots.txt sauté (--skip-robots-txt)")
    else:
        print("[2/4] Scan robots.txt")
        robots_policies = scan_robots_txt(
            start_sitemap=args.sitemap,
            page_urls=pages,
            timeout=args.timeout,
            user_agent=args.user_agent,
            retries=args.retries,
            retry_backoff=args.retry_backoff,
        )
        summarize_robots(robots_policies)

    print(f"\n[3/4] Audit SEO de {len(pages)} page(s) avec {args.workers} worker(s)")
    rows: List[Dict[str, object]] = []
    done = 0

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = [
            pool.submit(
                analyze_page,
                url,
                args.timeout,
                args.user_agent,
                args.retries,
                args.retry_backoff,
                robots_policies,
            )
            for url in pages
        ]
        for future in as_completed(futures):
            rows.append(future.result())
            done += 1
            if done % 25 == 0 or done == len(pages):
                print(f"  - Progression: {done}/{len(pages)}")

    rows.sort(key=lambda r: str(r.get("url", "")))
    mark_sitewide_duplicates(rows)
    apply_priority_scoring(rows)

    print(f"[4/4] Écriture du rapport : {args.output}")
    write_csv(args.output, rows)
    conflicts = build_sitemap_indexation_conflicts(rows)
    conflicts_path = _conflicts_output_path(args.output)
    write_conflicts_csv(conflicts_path, conflicts)
    summarize(rows)
    print(f"Rapport conflits sitemap/indexation : {conflicts_path} ({len(conflicts)} URL(s))")
    if conflicts:
        print("\nURLs en conflit sitemap/indexation (max 20):")
        for conflict in conflicts[:20]:
            print(
                f"- {conflict['url']} -> "
                f"{conflict['sitemap_indexation_conflict_reasons']}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
