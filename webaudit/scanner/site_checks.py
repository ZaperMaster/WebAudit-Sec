"""Comprobaciones a nivel de sitio y de host.

- Transporte (TLS en tls_checks.py y redirección HTTP->HTTPS): una vez por host.
- OPTIONS y security.txt: una sola vez, en la primera página.
"""

import re
from urllib.parse import urljoin, urlunparse

import requests

from .config import EXPOSED_FILES, RISKY_HTTP_METHODS, SEVERITY_ORDER
from .network import fetch
from .results import Report, tr
from .tls_checks import check_tls


SNIFF_BYTES = 4096


def check_transport(report: Report, parsed) -> None:
    if parsed.scheme == "http":
        report.check(
            "HTTPS-TRANSPORT", "transport", "fail", "La URL utiliza HTTP",
            details="La dirección de entrada no utiliza HTTPS.",
            severity="high",
        )
        report.finding(
            "WEB-HTTPS-NOT-USED",
            "La URL analizada utiliza HTTP",
            "high",
            "La dirección de entrada no utiliza HTTPS.",
            "Usa HTTPS y redirige HTTP hacia HTTPS.",
        )
        return

    report.check("HTTPS-TRANSPORT", "transport", "pass", "La URL utiliza HTTPS")
    check_tls(report, parsed.hostname, parsed.port or 443)
    check_http_to_https_redirect(report, parsed)


def check_http_to_https_redirect(report: Report, parsed) -> None:
    http_url = urlunparse(("http", parsed.netloc, parsed.path or "/", parsed.params, parsed.query, ""))
    try:
        response = fetch(http_url, timeout=5)
    except requests.RequestException:
        report.check(
            "HTTPS-REDIRECT", "transport", "unknown",
            "No se pudo comprobar la redirección HTTP→HTTPS",
        )
        return

    with response:
        location = response.headers.get("Location", "")
        redirected = (
            300 <= response.status_code < 400
            and location.lower().startswith("https://")
        )
        report.check(
            "HTTPS-REDIRECT",
            "transport",
            "pass" if redirected else "warning",
            "Redirección de HTTP a HTTPS",
            details=(
                f"{response.status_code} → {location[:180]}"
                if location
                else tr("HTTP respondió {status} sin Location HTTPS.", status=response.status_code)
            ),
            severity=None if redirected else "medium",
        )
        if not redirected:
            report.finding(
                "WEB-HTTPS-REDIRECT",
                "HTTP no redirige a HTTPS",
                "medium",
                tr("{url} respondió {status}.", url=f"http://{parsed.hostname}", status=response.status_code),
                "Redirige todas las peticiones HTTP hacia HTTPS.",
            )


def check_http_methods(report: Report, url: str) -> None:
    try:
        response = fetch(url, method="OPTIONS", timeout=5)
    except requests.RequestException:
        report.check(
            "HTTP-METHODS", "configuration", "unknown",
            "No se pudieron comprobar los métodos HTTP",
        )
        return

    with response:
        allowed = response.headers.get("Allow", "")
        risky = [method for method in RISKY_HTTP_METHODS if method in allowed.upper()]

        if risky:
            report.check(
                "HTTP-METHODS", "configuration", "fail",
                "Métodos HTTP potencialmente peligrosos",
                details=allowed[:200], severity="high",
            )
            report.finding(
                "WEB-HTTP-METHODS",
                tr("El servidor anuncia métodos sensibles: {methods}", methods=", ".join(risky)),
                "high",
                allowed[:200],
                "Deshabilita TRACE/TRACK/DEBUG si no son necesarios.",
            )
        elif allowed:
            report.check(
                "HTTP-METHODS", "configuration", "info",
                "Métodos anunciados por el servidor", details=allowed[:200],
            )
        else:
            report.check(
                "HTTP-METHODS", "configuration", "info",
                "El servidor no anuncia métodos en Allow",
            )


def check_security_txt(report: Report, parsed) -> None:
    security_txt = urljoin(f"{parsed.scheme}://{parsed.netloc}", "/.well-known/security.txt")
    try:
        response = fetch(security_txt, timeout=5)
    except requests.RequestException:
        report.check(
            "SECURITY-TXT", "configuration", "unknown",
            "No se pudo consultar security.txt",
        )
        return

    with response:
        present = response.status_code == 200
        report.check(
            "SECURITY-TXT",
            "configuration",
            "pass" if present else "info",
            "Archivo security.txt",
            details=f"{security_txt} → {response.status_code}",
            severity=None if present else "info",
        )
        if not present:
            report.finding(
                "WEB-SECURITY-TXT",
                "No se ha encontrado security.txt",
                "info",
                tr("{url} respondió {status}.", url=security_txt, status=response.status_code),
                "Publica /.well-known/security.txt para el contacto de seguridad.",
            )


def _read_start(url: str) -> tuple[int, bytes] | None:
    """(código HTTP, primeros bytes del cuerpo) sin seguir redirecciones."""

    try:
        with fetch(url, timeout=5) as response:
            body = b""
            if response.status_code == 200:
                for chunk in response.iter_content(chunk_size=SNIFF_BYTES):
                    body = chunk[:SNIFF_BYTES]
                    break
            return response.status_code, body
    except requests.RequestException:
        return None


def check_exposed_files(report: Report, parsed) -> None:
    """Archivos que no deberían ser públicos (.git, .env, copias de seguridad...).

    Se hace una vez por sitio. Solo cuenta si el contenido coincide con lo
    esperado, para no confundir páginas de error que responden 200 a cualquier ruta.
    """

    base = f"{parsed.scheme}://{parsed.netloc}"
    found = {}  # título -> URL (evita repetir, p. ej., /.git/HEAD y /.git/config)
    for path, pattern, severity, title in EXPOSED_FILES:
        if title in found:
            continue
        result = _read_start(base + path)
        if result and result[0] == 200 and re.search(pattern, result[1], re.MULTILINE):
            found[title] = (base + path, severity)

    if not found:
        report.check(
            "EXPOSED-FILES", "exposure", "pass", "Archivos sensibles expuestos",
            details=tr("Rutas comprobadas: {count}. Ninguna expuesta.", count=len(EXPOSED_FILES)),
        )
        return

    worst = min((severity for _, severity in found.values()), key=SEVERITY_ORDER.get)
    report.check(
        "EXPOSED-FILES", "exposure", "fail", "Archivos sensibles expuestos",
        details=", ".join(url for url, _ in found.values())[:220], severity=worst,
    )
    for title, (url, severity) in found.items():
        report.finding(
            "WEB-EXPOSED-FILE", title, severity, url,
            "Bloquea el acceso público a ese archivo y revisa si se han filtrado contraseñas o claves.",
        )


def check_favicon_redirect(report: Report, parsed) -> None:
    """Sin <link rel=icon>, el navegador pide /favicon.ico: en una página HTTPS
    no debe redirigir a HTTP (contenido mixto que el HTML no muestra)."""

    url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
    try:
        with fetch(url, timeout=5) as response:
            location = response.headers.get("Location", "")
            status = response.status_code
    except requests.RequestException:
        return
    if not (300 <= status < 400 and location.lower().startswith("http://")):
        return

    evidence = f"{url} → {location[:180]}"
    report.check(
        "MIXED-FAVICON", "content", "warning", "Icono de la web por HTTP",
        details=evidence, severity="low",
    )
    report.finding(
        "WEB-MIXED-FAVICON", "El icono de la web (/favicon.ico) redirige a HTTP",
        "low", evidence,
        "Sirve /favicon.ico por HTTPS o declara el icono con un enlace rel=icon por HTTPS.",
    )
