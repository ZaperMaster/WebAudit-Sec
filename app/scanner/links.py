"""Extracción de enlaces del mismo sitio para el rastreo."""

from urllib.parse import urljoin, urlparse, urlunparse

from . import config
from .html_page import ParsedPage, read_page
from .network import default_port


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
