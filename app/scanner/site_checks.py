"""Comprobaciones a nivel de sitio y de host.

- Transporte (TLS y redirección HTTP->HTTPS): una vez por cada host distinto.
- OPTIONS y security.txt: una sola vez, en la primera página.
"""

import ssl
from urllib.parse import urljoin, urlunparse

import requests

from .config import OBSOLETE_TLS_PROTOCOLS, RISKY_HTTP_METHODS, TLS_EXPIRY_WARNING_DAYS
from .network import fetch, inspect_tls, legacy_tls_context
from .results import Report


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
    check_tls_certificate(report, parsed.hostname, parsed.port or 443)
    check_http_to_https_redirect(report, parsed)


def check_tls_certificate(report: Report, hostname: str, port: int) -> None:
    try:
        tls = inspect_tls(hostname, port)
    except ssl.SSLCertVerificationError as exc:
        error = str(exc)[:220]
        report.check(
            "TLS-CERTIFICATE", "transport", "fail",
            "El certificado TLS no se ha podido validar",
            details=error, severity="high",
        )
        report.finding(
            "WEB-TLS-INVALID",
            "El certificado TLS no es de confianza",
            "high",
            error,
            "Instala un certificado válido emitido por una CA reconocida.",
        )
        return
    except ssl.SSLError as exc:
        check_weak_tls_handshake(report, hostname, port, str(exc)[:220])
        return
    except OSError:
        report.check(
            "TLS-CERTIFICATE", "transport", "unknown",
            "No se pudo inspeccionar el certificado TLS",
        )
        return

    protocol = tls.get("protocol") or "desconocido"
    days_left = tls.get("days_left")
    details = f"Protocolo {protocol}"
    if tls.get("expires_at"):
        details += f". Certificado válido hasta {tls['expires_at'][:10]}."

    status, severity = "pass", None
    if protocol in OBSOLETE_TLS_PROTOCOLS:
        status, severity = "fail", "high"
        report.finding(
            "WEB-TLS-PROTOCOL",
            f"El servidor usa un protocolo TLS obsoleto ({protocol})",
            severity, details,
            "Deshabilita TLS 1.0/1.1 y usa TLS 1.2 o superior.",
        )
    elif isinstance(days_left, int) and days_left < 0:
        status, severity = "fail", "high"
        report.finding(
            "WEB-TLS-EXPIRED", "El certificado TLS ha caducado",
            severity, details, "Renueva el certificado cuanto antes.",
        )
    elif isinstance(days_left, int) and days_left < TLS_EXPIRY_WARNING_DAYS:
        status, severity = "warning", "medium"
        report.finding(
            "WEB-TLS-EXPIRING", "El certificado TLS caduca pronto",
            severity, details, "Planifica la renovación del certificado.",
        )

    report.check(
        "TLS-CERTIFICATE", "transport", status, "Certificado y protocolo TLS",
        details=details, severity=severity,
    )


def check_weak_tls_handshake(report: Report, hostname: str, port: int, error: str) -> None:
    """Un cliente moderno rechazó el handshake: se reintenta en modo permisivo
    para identificar el protocolo y el cifrado débiles que ofrece el servidor."""

    try:
        tls = inspect_tls(hostname, port, context=legacy_tls_context())
        details = f"Protocolo {tls.get('protocol')}, cifrado {tls.get('cipher')}. {error}"
    except OSError:
        details = error

    report.check(
        "TLS-CERTIFICATE", "transport", "fail",
        "Configuración TLS rechazada por clientes modernos",
        details=details, severity="high",
    )
    report.finding(
        "WEB-TLS-WEAK",
        "El servidor solo ofrece TLS o cifrados obsoletos",
        "high",
        details,
        "Usa TLS 1.2 o superior con cifrados modernos y claves de al menos 2048 bits.",
    )


def report_unreachable_tls(report: Report, error: str) -> None:
    """No se pudo negociar TLS ni aceptando protocolos y cifrados obsoletos."""

    details = error[-220:]
    report.check(
        "TLS-CERTIFICATE", "transport", "fail",
        "No se puede establecer una conexión TLS",
        details=details, severity="high",
    )
    report.finding(
        "WEB-TLS-WEAK",
        "El servidor solo ofrece cifrados tan antiguos que no se puede conectar",
        "high",
        details,
        "Usa TLS 1.2 o superior con cifrados modernos (sin RC4, 3DES ni DH débil).",
    )


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
                else f"HTTP respondió {response.status_code} sin Location HTTPS."
            ),
            severity=None if redirected else "medium",
        )
        if not redirected:
            report.finding(
                "WEB-HTTPS-REDIRECT",
                "HTTP no redirige a HTTPS",
                "medium",
                f"http://{parsed.hostname} respondió {response.status_code}.",
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
                f"El servidor anuncia métodos sensibles: {', '.join(risky)}",
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
                f"{security_txt} respondió {response.status_code}.",
                "Publica /.well-known/security.txt para el contacto de seguridad.",
            )
