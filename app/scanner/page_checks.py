"""Comprobaciones sobre la respuesta de una página (cabeceras y cookies).

Cada función recibe un `Report` y añade sus checks/findings en él.
"""

import re

from .analyzers import (
    analyze_csp,
    analyze_hsts,
    analyze_security_header_values,
    cookie_attribute_names,
)
from .config import DISCLOSURE_HEADERS, SECURITY_HEADERS
from .results import Report


def check_security_headers(report: Report, headers: dict[str, str]) -> None:
    csp_value = headers.get("content-security-policy", "")

    for header, (severity, recommendation) in SECURITY_HEADERS.items():
        present = header in headers
        # frame-ancestors en la CSP sustituye a X-Frame-Options
        if header == "x-frame-options" and "frame-ancestors" in csp_value.lower():
            present = True

        report.check(
            f"HEADER-{header.upper()}",
            "headers",
            "pass" if present else "warning",
            f"Cabecera {header}",
            details=(
                headers.get(header, "")[:220]
                if present
                else f"Cabecera ausente. Severidad: {severity}."
            ),
            severity=None if present else severity,
        )
        if not present:
            report.finding(
                f"WEB-HEADER-{header.upper()}",
                f"Falta la cabecera {header}",
                severity,
                f"Cabecera ausente: {header}",
                recommendation,
            )

    for issue in analyze_security_header_values(headers, csp_value):
        check_id = f"HEADER-{issue.header.upper()}-QUALITY"
        report.check(
            check_id, "headers", "warning", issue.title,
            details=issue.evidence, severity=issue.severity,
        )
        report.finding(
            f"WEB-{check_id}", issue.title, issue.severity,
            issue.evidence, issue.recommendation,
        )


def check_csp(report: Report, headers: dict[str, str]) -> None:
    csp_value = headers.get("content-security-policy", "")
    if not csp_value:
        return  # La ausencia ya se reporta en check_security_headers

    issues = analyze_csp(csp_value)
    report.check(
        "HEADER-CSP-QUALITY",
        "headers",
        "warning" if issues else "pass",
        "Calidad de Content-Security-Policy",
        details=csp_value[:220],
        severity=issues[0].severity if issues else None,
    )
    for issue in issues:
        report.finding(
            "WEB-CSP-QUALITY", issue.title, issue.severity, issue.evidence,
            "Elimina unsafe-inline/unsafe-eval y evita comodines amplios.",
        )


def check_hsts(report: Report, headers: dict[str, str]) -> None:
    """Solo aplica a URLs HTTPS."""

    value = headers.get("strict-transport-security")
    report.check(
        "HEADER-HSTS",
        "headers",
        "pass" if value else "warning",
        "HTTP Strict Transport Security",
        details=value or "Cabecera ausente.",
        severity=None if value else "medium",
    )
    if not value:
        report.finding(
            "WEB-HEADER-HSTS",
            "Falta la cabecera HSTS",
            "medium",
            "Strict-Transport-Security ausente",
            "Configura HSTS después de verificar que HTTPS funciona correctamente.",
        )
        return

    issues = analyze_hsts(value)
    report.check(
        "HEADER-HSTS-QUALITY",
        "headers",
        "warning" if issues else "pass",
        "Calidad de HSTS",
        details=value[:220],
        severity=issues[0].severity if issues else None,
    )
    for issue in issues:
        report.finding(
            "WEB-HSTS-QUALITY", issue.title, issue.severity, issue.evidence,
            "Usa un max-age largo e includeSubDomains cuando sea seguro.",
        )


def check_cookies(report: Report, cookies: list[str], is_https: bool) -> None:
    if not cookies:
        report.check(
            "COOKIE-SET",
            "cookies",
            "info",
            "El servidor no ha enviado Set-Cookie",
            details="No hay cookies que evaluar en esta respuesta.",
        )
        return

    # atributo -> (severidad si falta, recomendación)
    cookie_rules = {
        "secure": (
            "medium" if is_https else "low",
            "Añade Secure a las cookies que deban transmitirse solo por HTTPS.",
        ),
        "httponly": ("medium", "Añade HttpOnly a las cookies de sesión."),
        "samesite": ("low", "Define SameSite según las necesidades de la aplicación."),
    }

    for index, cookie in enumerate(cookies, start=1):
        name = cookie.split("=", 1)[0].strip()[:80]
        attributes = cookie_attribute_names(cookie)
        details = f"Cookie: {name}. Atributos: {', '.join(sorted(attributes)) or 'ninguno'}"

        for attribute, (severity, recommendation) in cookie_rules.items():
            present = attribute in attributes
            report.check(
                f"COOKIE-{index}-{attribute.upper()}",
                "cookies",
                "pass" if present else "warning",
                f"Cookie {name} con atributo {attribute}",
                details=details,
                severity=None if present else severity,
            )
            if not present:
                report.finding(
                    f"WEB-COOKIE-{attribute.upper()}",
                    f"Cookie {name} sin atributo {attribute}",
                    severity,
                    f"No se ha identificado {attribute} en {name}.",
                    recommendation,
                )

        same_site_none = re.search(
            r"(?:^|;)\s*samesite\s*=\s*none(?:\s*;|$)", cookie, re.IGNORECASE
        )
        if same_site_none and "secure" not in attributes:
            report.check(
                f"COOKIE-{index}-SAMESITE-NONE",
                "cookies",
                "fail",
                f"Cookie {name}: SameSite=None sin Secure",
                details=details,
                severity="high",
            )
            report.finding(
                "WEB-COOKIE-SAMESITE-NONE",
                f"Cookie {name}: SameSite=None requiere Secure",
                "high",
                f"Se detectó SameSite=None sin Secure en {name}.",
                "Si usas SameSite=None, añade también Secure.",
            )


def check_information_disclosure(report: Report, headers: dict[str, str]) -> None:
    for header in DISCLOSURE_HEADERS:
        value = headers.get(header)
        report.check(
            f"INFO-{header.upper()}",
            "disclosure",
            "warning" if value else "pass",
            f"Divulgación mediante {header}",
            details=value[:200] if value else "Cabecera no presente.",
            severity="info" if value else None,
        )
        if value:
            report.finding(
                f"WEB-INFO-{header.upper()}",
                f"El servidor revela información mediante {header}",
                "info",
                f"{header}: {value[:200]}",
                "Valora reducir la información tecnológica expuesta si no es necesaria.",
            )


def check_cors(report: Report, headers: dict[str, str]) -> None:
    allow_origin = headers.get("access-control-allow-origin", "")
    allow_credentials = headers.get("access-control-allow-credentials", "").lower()

    if allow_origin == "*" and allow_credentials == "true":
        title = "CORS permite cualquier origen con credenciales"
        report.check(
            "CORS-WILDCARD-CREDENTIALS", "cors", "fail", title,
            details="Access-Control-Allow-Origin: * y Allow-Credentials: true",
            severity="high",
        )
        report.finding(
            "WEB-CORS-WILDCARD-CREDENTIALS", title, "high",
            "Access-Control-Allow-Origin: * junto a Allow-Credentials: true",
            "No combines el comodín CORS con credenciales.",
        )
    elif allow_origin == "*":
        title = "CORS permite cualquier origen"
        report.check(
            "CORS-WILDCARD", "cors", "warning", title,
            details="Access-Control-Allow-Origin: *",
            severity="low",
        )
        report.finding(
            "WEB-CORS-WILDCARD", title, "low",
            "Access-Control-Allow-Origin: *",
            "Comprueba si el acceso desde cualquier origen es intencionado.",
        )
    else:
        report.check(
            "CORS-WILDCARD", "cors", "pass", "CORS no usa un comodín global",
            details=allow_origin or "Sin Access-Control-Allow-Origin.",
        )


def check_content_type(report: Report, headers: dict[str, str]) -> None:
    content_type = headers.get("content-type", "")
    report.check(
        "HEADER-CONTENT-TYPE",
        "headers",
        "pass" if content_type else "warning",
        "Cabecera Content-Type",
        details=content_type or "Cabecera ausente.",
        severity=None if content_type else "low",
    )
    if not content_type:
        report.finding(
            "WEB-HEADER-CONTENT-TYPE",
            "Falta la cabecera Content-Type",
            "low",
            "Content-Type ausente",
            "Envía un Content-Type explícito, preferiblemente con charset.",
        )
        return

    lowered = content_type.lower()
    if "text/" in lowered and "charset=" not in lowered:
        report.check(
            "HEADER-CHARSET", "headers", "warning", "Charset en Content-Type",
            details=content_type, severity="low",
        )
        report.finding(
            "WEB-HEADER-CHARSET",
            "Content-Type no declara charset",
            "low",
            content_type,
            "Añade charset=utf-8 en las respuestas de texto.",
        )


def check_cache_control(report: Report, headers: dict[str, str]) -> None:
    value = headers.get("cache-control", "")
    if any(token in value.lower() for token in ("no-store", "private")):
        report.check("HEADER-CACHE", "headers", "pass", "Control de caché", details=value)
    else:
        report.check(
            "HEADER-CACHE", "headers", "info", "Control de caché",
            details=value or "Cache-Control no presente.",
            severity="info",
        )
