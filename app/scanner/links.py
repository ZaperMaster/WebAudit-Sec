"""Extracción de enlaces del mismo sitio para el rastreo."""

from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urlunparse

from . import config
from .network import default_port


class AnchorCollector(HTMLParser):
    """Recoge los href de las etiquetas <a> hasta MAX_LINKS_PER_PAGE."""

    def __init__(self):
        super().__init__()
        self.hrefs = []
        self.truncated = False

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        href = next((value for name, value in attrs if name.lower() == "href"), None)
        if not href:
            return
        if len(self.hrefs) >= config.MAX_LINKS_PER_PAGE:
            self.truncated = True
            return
        self.hrefs.append(href)


def _read_html(response, parser: HTMLParser) -> int:
    """Alimenta el parser con como máximo MAX_HTML_BYTES. Devuelve los bytes leídos."""

    encoding = response.encoding or "utf-8"
    read_bytes = 0
    for chunk in response.iter_content(chunk_size=8192):
        remaining = config.MAX_HTML_BYTES - read_bytes
        if remaining <= 0:
            break
        chunk = chunk[:remaining]
        parser.feed(chunk.decode(encoding, errors="replace"))
        read_bytes += len(chunk)
        if read_bytes >= config.MAX_HTML_BYTES:
            break
    return read_bytes


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
    host_allowed = candidate_host == allowed_host or (
        include_subdomains and candidate_host.endswith("." + allowed_host)
    )
    base_port = base.port or default_port(base.scheme)
    if candidate.scheme != base.scheme or not host_allowed or candidate_port != base_port:
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
    """Devuelve (enlaces dentro del alcance, ¿se truncó la lectura?)."""

    if response.status_code != 200:
        return [], False
    if "text/html" not in response.headers.get("Content-Type", "").lower():
        return [], False

    parser = AnchorCollector()
    read_bytes = _read_html(response, parser)

    base = urlparse(page_url)
    allowed_host = (scope_host or base.hostname or "").lower()
    links = []
    for href in parser.hrefs:
        link = _normalize_link(page_url, href, base, allowed_host, include_subdomains)
        if link and link not in links:
            links.append(link)

    return links, parser.truncated or read_bytes >= config.MAX_HTML_BYTES
