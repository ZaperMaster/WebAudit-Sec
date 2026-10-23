"""Extracción de enlaces del mismo sitio para el rastreo (HTML y sitemap.xml)."""

import html
import re
from urllib.parse import urljoin, urlparse, urlunparse

import requests

from . import config
from .html_page import ParsedPage, read_page
from .network import default_port, fetch


SITEMAP_LOC = re.compile(rb"<loc>\s*(.*?)\s*</loc>", re.IGNORECASE | re.DOTALL)
ROBOTS_SITEMAP = re.compile(rb"^\s*sitemap:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
MAX_SITEMAP_BYTES = 2 * 1024 * 1024
MAX_SITEMAP_FILES = 5
MAX_SITEMAP_LINKS = 500


def _normalize_link(page_url, href, base, allowed_host, include_subdomains) -> str | None:
    """Devuelve el enlace normalizado si pertenece al alcance; si no, None."""

    candidate = urlparse(urljoin(page_url, href))
    if candidate.scheme not in {"http", "https"}:
        return None
    if candidate.username or candidate.password or not candidate.hostname:
        return None
    try:
        candidate_port = candidate.port or default_port(candidate.scheme)
    except ValueError:
        return None

    candidate_host = candidate.hostname.lower()
    if include_subdomains:
        # Rastreo de todo el dominio: cualquier subdominio, esquema y puerto
        # (ej. http.badssl.com o tls-v1-0.badssl.com:1010).
        if candidate_host != allowed_host and not candidate_host.endswith("." + allowed_host):
            return None
    else:
        base_port = base.port or default_port(base.scheme)
        if (
            candidate.scheme != base.scheme
            or candidate_host != allowed_host
            or candidate_port != base_port
        ):
            return None
    if len(candidate.geturl()) > config.MAX_URL_LENGTH:
        return None

    return urlunparse((
        candidate.scheme,
        candidate.netloc,
        candidate.path or "/",
        candidate.params,
        candidate.query,
        "",
    ))


def same_origin_links(
    page_url: str,
    response,
    scope_host: str | None = None,
    include_subdomains: bool = False,
) -> tuple[list[str], bool]:
    """Lee el HTML de `response` y devuelve (enlaces en el alcance, ¿lectura truncada?)."""

    return links_in_scope(page_url, read_page(response), scope_host, include_subdomains)


def links_in_scope(
    page_url: str,
    page: ParsedPage | None,
    scope_host: str | None = None,
    include_subdomains: bool = False,
) -> tuple[list[str], bool]:
    """Devuelve (enlaces de `page` dentro del alcance, ¿lectura truncada?)."""

    if page is None:
        return [], False

    base = urlparse(page_url)
    allowed_host = (scope_host or base.hostname or "").lower()
    links = []
    for href in page.anchors:
        link = _normalize_link(page_url, href, base, allowed_host, include_subdomains)
        if link and link not in links:
            links.append(link)

    return links, page.truncated


def _read_text(url: str) -> bytes | None:
    """Cuerpo de una respuesta 200, como mucho MAX_SITEMAP_BYTES."""

    try:
        with fetch(url, timeout=5) as response:
            if response.status_code != 200:
                return None
            content = b""
            for chunk in response.iter_content(chunk_size=65536):
                content += chunk
                if len(content) >= MAX_SITEMAP_BYTES:
                    break
            return content[:MAX_SITEMAP_BYTES]
    except requests.RequestException:
        return None


def sitemap_links(
    site_url: str,
    scope_host: str | None = None,
    include_subdomains: bool = False,
) -> list[str]:
    """Páginas del sitemap del sitio (indicado en robots.txt o en /sitemap.xml)
    que entran en el alcance del rastreo. Encuentra páginas sin enlaces hacia ellas."""

    base = urlparse(site_url)
    root = f"{base.scheme}://{base.netloc}"
    robots = _read_text(root + "/robots.txt") or b""
    pending = [url.decode("utf-8", "replace") for url in ROBOTS_SITEMAP.findall(robots)]
    pending = pending or [root + "/sitemap.xml"]

    allowed_host = (scope_host or base.hostname or "").lower()
    links, seen_files = [], set()
    while pending and len(seen_files) < MAX_SITEMAP_FILES and len(links) < MAX_SITEMAP_LINKS:
        sitemap_url = pending.pop(0)
        if sitemap_url in seen_files:
            continue
        seen_files.add(sitemap_url)
        content = _read_text(sitemap_url)
        if not content:
            continue

        is_index = b"<sitemapindex" in content[:2048].lower()
        for raw in SITEMAP_LOC.findall(content):
            location = html.unescape(raw.decode("utf-8", "replace"))
            if is_index:
                pending.append(location)  # Un índice apunta a otros sitemaps
                continue
            link = _normalize_link(site_url, location, base, allowed_host, include_subdomains)
            if link and link not in links:
                links.append(link)
                if len(links) >= MAX_SITEMAP_LINKS:
                    break
    return links
