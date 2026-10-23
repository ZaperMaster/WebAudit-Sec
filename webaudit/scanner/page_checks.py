"""Comprobaciones sobre la respuesta de una página (cabeceras, cookies y HTML).

Cada función recibe un `Report` y añade sus checks/findings en él.
"""

import re
from urllib.parse import urljoin, urlparse

from .analyzers import (
    analyze_csp,
    analyze_hsts,
    analyze_security_header_values,
    cookie_attributes,
    cookie_lifetime_days,
    outdated_software,
)
from .config import (
    COOKIE_PREFIX_RULES,
    DISCLOSURE_HEADERS,
    MAX_SESSION_COOKIE_DAYS,
    SECURITY_HEADERS,
    SESSION_COOKIE_NAME,
)
from .html_page import ParsedPage
from .results import Report, tr


MAX_URLS_IN_EVIDENCE = 5


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
            tr("Cabecera {header}", header=header),
            details=(
                headers.get(header, "")[:220]
                if present
                else "Cabecera ausente."
            ),
            severity=None if present else severity,
        )
        if not present:
            report.finding(
                f"WEB-HEADER-{header.upper()}",
                tr("Falta la cabecera {header}", header=header),
                severity,
                tr("Cabecera ausente: {header}", header=header),
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
    report_only = headers.get("content-security-policy-report-only", "")
    if report_only and not csp_value:
        # Solo informa de las infracciones: no bloquea nada.
        report.check(
            "HEADER-CSP-REPORT-ONLY", "headers", "warning",
            "Content-Security-Policy solo en modo report-only",
            details=report_only[:220], severity="medium",
        )
        report.finding(
            "WEB-CSP-REPORT-ONLY",
            "La CSP está solo en modo report-only y no bloquea nada",
            "medium", report_only[:220],
            "Cuando hayas revisado los informes, publica la política como Content-Security-Policy.",
        )
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
        values = cookie_attributes(cookie)
        attributes = set(values)
        details = (
            tr("Cookie: {name}. Atributos: {attributes}", name=name, attributes=", ".join(sorted(attributes)))
            if attributes
            else tr("Cookie: {name}. Sin atributos", name=name)
        )

        for attribute, (severity, recommendation) in cookie_rules.items():
            present = attribute in attributes
            report.check(
                f"COOKIE-{index}-{attribute.upper()}",
                "cookies",
                "pass" if present else "warning",
                tr("Cookie {name} con atributo {attribute}", name=name, attribute=attribute),
                details=details,
                severity=None if present else severity,
            )
            if not present:
                report.finding(
                    f"WEB-COOKIE-{attribute.upper()}",
                    tr("Cookie {name} sin atributo {attribute}", name=name, attribute=attribute),
                    severity,
                    tr("No se ha identificado {attribute} en {name}.", attribute=attribute, name=name),
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
                tr("Cookie {name}: SameSite=None sin Secure", name=name),
                details=details,
                severity="high",
            )
            report.finding(
                "WEB-COOKIE-SAMESITE-NONE",
                tr("Cookie {name}: SameSite=None requiere Secure", name=name),
                "high",
                tr("Se detectó SameSite=None sin Secure en {name}.", name=name),
                "Si usas SameSite=None, añade también Secure.",
            )

        _check_cookie_prefix(report, index, name, values)
        _check_session_lifetime(report, index, name, values)


def _check_cookie_prefix(report: Report, index: int, name: str, values: dict[str, str]) -> None:
    """__Secure- exige Secure; __Host- exige además Path=/ y ningún Domain."""

    lowered = name.lower()
    if lowered.startswith("__host-"):
        prefix = "__Host-"
        valid = "secure" in values and values.get("path") == "/" and "domain" not in values
    elif lowered.startswith("__secure-"):
        prefix = "__Secure-"
        valid = "secure" in values
    else:
        return

    report.check(
        f"COOKIE-{index}-PREFIX", "cookies", "pass" if valid else "fail",
        tr("Cookie {name}: prefijo {prefix}", name=name, prefix=prefix),
        details=COOKIE_PREFIX_RULES[prefix], severity=None if valid else "medium",
    )
    if not valid:
        report.finding(
            "WEB-COOKIE-PREFIX",
            tr("Cookie {name}: no cumple las reglas del prefijo {prefix}", name=name, prefix=prefix),
            "medium", COOKIE_PREFIX_RULES[prefix],
            "Ajusta los atributos de la cookie o quita el prefijo: el navegador la rechazará.",
        )


def _check_session_lifetime(report: Report, index: int, name: str, values: dict[str, str]) -> None:
    """Las cookies de sesión que duran meses alargan el riesgo si se roban."""

    if not SESSION_COOKIE_NAME.search(name):
        return
    days = cookie_lifetime_days(values)
    if days is None or days <= MAX_SESSION_COOKIE_DAYS:
        return

    report.check(
        f"COOKIE-{index}-LIFETIME", "cookies", "warning",
        tr("Cookie de sesión {name}: caducidad", name=name),
        details=tr("Caduca en {days} días.", days=days), severity="low",
    )
    report.finding(
        "WEB-COOKIE-LONG-SESSION",
        tr("Cookie de sesión {name} con caducidad muy larga ({days} días)", name=name, days=days),
        "low", tr("Caduca en {days} días.", days=days),
        "Usa una caducidad corta para las cookies de sesión (horas o pocos días).",
    )


def check_information_disclosure(report: Report, headers: dict[str, str]) -> None:
    for header in DISCLOSURE_HEADERS:
        value = headers.get(header)
        report.check(
            f"INFO-{header.upper()}",
            "disclosure",
            "warning" if value else "pass",
            tr("Divulgación mediante {header}", header=header),
            details=value[:200] if value else "Cabecera no presente.",
            severity="info" if value else None,
        )
        if value:
            report.finding(
                f"WEB-INFO-{header.upper()}",
                tr("El servidor revela información mediante {header}", header=header),
                "info",
                f"{header}: {value[:200]}",
                "Valora reducir la información tecnológica expuesta si no es necesaria.",
            )

    outdated = outdated_software(" ".join(headers.get(header, "") for header in DISCLOSURE_HEADERS))
    if outdated:
        software = ", ".join(outdated)
        report.check(
            "INFO-OUTDATED", "disclosure", "fail", "Versiones de software anunciadas",
            details=software, severity="medium",
        )
        report.finding(
            "WEB-INFO-OUTDATED",
            tr("El servidor anuncia software sin soporte: {software}", software=software),
            "medium", software,
            "Actualiza el software del servidor a una versión con soporte de seguridad y oculta su versión.",
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


def _resolve(page_url: str, url: str):
    return urlparse(urljoin(page_url, url))


def _url_list(urls: list[str]) -> str:
    """Las primeras URL afectadas, para la evidencia."""

    shown = ", ".join(urls[:MAX_URLS_IN_EVIDENCE])
    return shown + (" …" if len(urls) > MAX_URLS_IN_EVIDENCE else "")


def check_mixed_content(report: Report, page: ParsedPage, page_url: str) -> None:
    """Recursos y formularios por HTTP dentro de una página HTTPS."""

    def insecure(url):
        return _resolve(page_url, url).scheme == "http"

    active = [r.url for r in page.resources if r.active and insecure(r.url)]
    passive = [r.url for r in page.resources if not r.active and insecure(r.url)]
    forms = [action for action in page.form_actions if insecure(action)]

    if not (active or passive or forms):
        report.check(
            "MIXED-CONTENT", "content", "pass", "Contenido mixto",
            details="La página no carga recursos ni envía formularios por HTTP.",
        )
        return

    severity = "medium" if active or forms else "low"
    report.check(
        "MIXED-CONTENT", "content", "fail" if severity == "medium" else "warning",
        "Contenido mixto",
        details=tr(
            "Recursos activos por HTTP: {active}. Imágenes o multimedia por HTTP: {passive}. "
            "Formularios que envían por HTTP: {forms}.",
            active=len(active), passive=len(passive), forms=len(forms),
        ),
        severity=severity,
    )
    if active:
        report.finding(
            "WEB-MIXED-ACTIVE",
            tr("Scripts, estilos o iframes cargados por HTTP: {count}", count=len(active)),
            "medium", _url_list(active),
            "Carga todos los scripts, estilos e iframes por HTTPS; los navegadores los bloquean.",
        )
    if passive:
        report.finding(
            "WEB-MIXED-PASSIVE",
            tr("Imágenes o multimedia cargados por HTTP: {count}", count=len(passive)),
            "low", _url_list(passive),
            "Sirve también las imágenes y el contenido multimedia por HTTPS.",
        )
    if forms:
        report.finding(
            "WEB-MIXED-FORM",
            tr("Formularios que envían datos por HTTP: {count}", count=len(forms)),
            "medium", _url_list(forms),
            "Haz que los formularios envíen sus datos a direcciones HTTPS.",
        )


def check_subresource_integrity(report: Report, page: ParsedPage, page_url: str) -> None:
    """Scripts y hojas de estilo de otros dominios sin atributo integrity (SRI)."""

    page_host = (urlparse(page_url).hostname or "").lower()
    external = [
        resource for resource in page.resources
        if resource.tag in ("script", "link") and resource.active  # Sin iconos
        and (_resolve(page_url, resource.url).hostname or page_host).lower() != page_host
    ]
    missing = [resource.url for resource in external if not resource.integrity]

    if not external:
        report.check(
            "SRI", "content", "pass", "Integridad de recursos externos (SRI)",
            details="La página no carga scripts ni estilos de otros dominios.",
        )
        return

    details = tr(
        "Scripts y estilos externos: {total}. Con integrity: {protected}.",
        total=len(external), protected=len(external) - len(missing),
    )
    if not missing:
        report.check(
            "SRI", "content", "pass", "Integridad de recursos externos (SRI)", details=details,
        )
        return

    report.check(
        "SRI", "content", "warning", "Integridad de recursos externos (SRI)",
        details=details, severity="low",
    )
    report.finding(
        "WEB-SRI-MISSING",
        tr("Scripts o estilos externos sin integridad (SRI): {count}", count=len(missing)),
        "low", _url_list(missing),
        "Añade integrity y crossorigin a los scripts y estilos de terceros que no cambian, "
        "o alójalos en tu propio dominio.",
    )
