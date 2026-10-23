"""Punto de entrada del análisis: una página o rastreo del sitio."""

from collections.abc import Callable
from time import monotonic
from urllib.parse import urlparse

import requests

from . import page_checks, site_checks, tls_checks
from .config import MAX_CRAWL_PAGES, MAX_CRAWL_SECONDS
from .html_page import read_page
from .links import links_in_scope
from .network import fetch, header_map, registrable_domain, set_cookie_headers, validate_target
from .results import Report, build_scan_result


def scan_security_headers(
    url: str,
    discover_links: bool = False,
    site_level: bool = True,
    scope_host: str | None = None,
    include_subdomains: bool = False,
    host_level: bool | None = None,
) -> dict:
    """Audita una sola página.

    - `discover_links`: además devuelve los enlaces del mismo sitio (para rastrear).
    - `site_level`: añade métodos HTTP y security.txt. En un rastreo solo se
      hacen para la primera página.
    - `host_level`: añade transporte (TLS y redirección). En un rastreo se hace
      en la primera página de cada host. Por defecto, igual que `site_level`.
    """

    if host_level is None:
        host_level = site_level

    url = validate_target(url)
    parsed = urlparse(url)
    report = Report()

    with fetch(url) as response:
        headers = header_map(response)
        page = read_page(response)  # None si no es una página HTML

        discovered_links, discovery_incomplete = (
            links_in_scope(
                url, page,
                scope_host=scope_host,
                include_subdomains=include_subdomains,
            )
            if discover_links
            else ([], False)
        )

        page_checks.check_security_headers(report, headers)
        page_checks.check_csp(report, headers)
        if parsed.scheme == "https":
            page_checks.check_hsts(report, headers)
        page_checks.check_cookies(report, set_cookie_headers(response), parsed.scheme == "https")
        page_checks.check_information_disclosure(report, headers)
        page_checks.check_cors(report, headers)
        page_checks.check_content_type(report, headers)
        page_checks.check_cache_control(report, headers)
        if page is not None:
            if parsed.scheme == "https":
                page_checks.check_mixed_content(report, page, url)
            page_checks.check_subresource_integrity(report, page, url)

        if host_level:
            site_checks.check_transport(report, parsed)
        if site_level:
            site_checks.check_http_methods(report, url)
            site_checks.check_security_txt(report, parsed)

        return build_scan_result(
            url,
            response.status_code,
            report.findings,
            report.checks,
            discovered_links if discover_links else None,
            discovery_incomplete,
        )


def scan_website(
    url: str,
    crawl: bool = False,
    on_progress: Callable[[dict], None] | None = None,
    should_cancel: Callable[[], bool] | None = None,
) -> dict:
    """Analiza la URL y, si `crawl` es True, las páginas enlazadas del mismo dominio.

    - `on_progress`: se llama al empezar cada página y al terminar el análisis
      con {pages_scanned, page_limit, queued, current_page, findings}.
    - `should_cancel`: si devuelve True, el análisis se detiene antes de la
      siguiente página y devuelve lo analizado hasta entonces.
    """

    target = validate_target(url)
    scope_host = registrable_domain(urlparse(target).hostname or "")
    page_limit = MAX_CRAWL_PAGES if crawl else 1
    deadline = monotonic() + MAX_CRAWL_SECONDS

    queue = [target]
    visited = set()
    checked_hosts = set()  # (esquema, host:puerto) con el transporte ya comprobado
    scanned_pages = []
    failed_pages = []
    findings = []
    checks = []
    root_status = None
    discovery_incomplete = False
    cancelled = False

    def report_progress(current_page: str | None) -> None:
        if on_progress:
            on_progress({
                "pages_scanned": len(scanned_pages) + len(failed_pages),
                "page_limit": page_limit,
                "queued": len([link for link in queue if link not in visited]),
                "current_page": current_page,
                "findings": len(findings),
            })

    while queue and len(visited) < page_limit and monotonic() < deadline:
        if should_cancel and should_cancel():
            cancelled = True
            break
        page_url = queue.pop(0)
        if page_url in visited:
            continue
        visited.add(page_url)
        report_progress(page_url)
        parsed_page = urlparse(page_url)
        host_key = (parsed_page.scheme, parsed_page.netloc.lower())

        try:
            result = scan_security_headers(
                page_url,
                discover_links=crawl,
                site_level=not scanned_pages,
                scope_host=scope_host,
                include_subdomains=crawl,
                host_level=host_key not in checked_hosts,
            )
        except requests.exceptions.SSLError as exc:
            # Ni el modo permisivo negocia TLS: el propio fallo es el hallazgo.
            scanned_pages.append(page_url)
            checked_hosts.add(host_key)
            report = Report()
            tls_checks.report_unreachable_tls(report, str(exc))
            for item in report.findings:
                item["page"] = page_url
                findings.append(item)
            for item in report.checks:
                item["page"] = page_url
                checks.append(item)
            continue
        except (ValueError, requests.RequestException):
            if not scanned_pages:
                raise  # Si falla la primera página, el análisis entero falla
            failed_pages.append(page_url)
            checks.append({
                "id": "CRAWL-PAGE-UNAVAILABLE",
                "category": "crawl",
                "status": "unknown",
                "title": "No se pudo analizar una página del sitio",
                "details": page_url,
            })
            continue

        if root_status is None:
            root_status = result["http_status"]
        scanned_pages.append(page_url)
        checked_hosts.add(host_key)
        discovery_incomplete = discovery_incomplete or result.get("discovery_incomplete", False)

        for finding in result["findings"]:
            finding["page"] = page_url
            findings.append(finding)
        for check in result["checks"]:
            check["page"] = page_url
            checks.append(check)

        for link in result.get("discovered_links", []):
            if link not in visited and link not in queue:
                queue.append(link)

    report_progress(None)

    stop_reasons = ["cancelled"] if cancelled else []
    if failed_pages:
        stop_reasons.append("page_error")
    if discovery_incomplete:
        stop_reasons.append("link_or_content_limit")
    if queue and len(visited) >= page_limit:
        stop_reasons.append("page_limit")
    elif queue and not cancelled and monotonic() >= deadline:
        stop_reasons.append("time_limit")

    result = build_scan_result(target, root_status or 0, findings, checks)
    result.update({
        "pages_scanned": len(scanned_pages),
        "scanned_pages": scanned_pages,
        "page_limit": page_limit,
        "crawl_complete": not stop_reasons,
        "crawl_stop_reason": stop_reasons[0] if stop_reasons else "completed",
        "crawl_stop_reasons": stop_reasons,
        "failed_pages": failed_pages,
    })
    return result
