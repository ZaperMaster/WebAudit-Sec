
import ipaddress
import re
import socket
import ssl
import warnings
from datetime import datetime, timezone
from html.parser import HTMLParser
from time import monotonic
from urllib.parse import urljoin, urlparse, urlunparse

import requests
import tldextract
from urllib3.exceptions import InsecureRequestWarning


USER_AGENT = "WebAudit-Sec/1.0"
MAX_CRAWL_PAGES = 50
MAX_CRAWL_SECONDS = 120
MAX_HTML_BYTES = 256 * 1024
MAX_LINKS_PER_PAGE = 300
PUBLIC_SUFFIX_EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=(),
    fallback_to_snapshot=True,
)
SEVERITY_ORDER = {
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

SECURITY_HEADERS = {
    "content-security-policy": (
        "high",
        "Configura una Content-Security-Policy que limite scripts, estilos y orígenes.",
        15,
    ),
    "x-content-type-options": (
        "low",
        "Configura X-Content-Type-Options: nosniff.",
        5,
    ),
    "referrer-policy": (
        "low",
        "Define una política Referrer-Policy.",
        5,
    ),
    "permissions-policy": (
        "low",
        "Define una Permissions-Policy adecuada.",
        5,
    ),
    "x-frame-options": (
        "medium",
        "Configura X-Frame-Options o frame-ancestors en CSP.",
        10,
    ),
    "cross-origin-opener-policy": (
        "medium",
        "Configura Cross-Origin-Opener-Policy, por ejemplo same-origin.",
        8,
    ),
    "cross-origin-resource-policy": (
        "low",
        "Configura Cross-Origin-Resource-Policy según el uso del recurso.",
        4,
    ),
    "x-permitted-cross-domain-policies": (
        "low",
        "Configura X-Permitted-Cross-Domain-Policies: none si no usas Flash/PDF cross-domain.",
        3,
    ),
}

OWASP_TOP10_CATEGORIES = {
    "configuration": "A02:2025 - Security Misconfiguration",
    "cryptography": "A04:2025 - Cryptographic Failures",
    "session": "A07:2025 - Authentication Failures",
}

OWASP_CHEAT_SHEETS = {
    "headers": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
    "csp": "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
    "tls": "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    "session": "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
    "disclosure": "https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html",
}


def validate_target(url: str) -> str:
    """Permite únicamente destinos HTTP(S) con IP pública."""

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Solo se permite HTTP o HTTPS.")

    if not parsed.hostname:
        raise ValueError("El dominio no es válido.")

    if parsed.username or parsed.password:
        raise ValueError("No se permiten credenciales en la URL.")

    if parsed.port is not None and parsed.port not in (80, 443):
        raise ValueError("Solo se permiten los puertos 80 y 443.")

    hostname = parsed.hostname.lower()

    if (
        hostname == "localhost"
        or hostname.endswith(".localhost")
        or hostname.endswith(".local")
    ):
        raise ValueError("No se permiten destinos locales.")

    try:
        addresses = {
            ipaddress.ip_address(hostname.strip("[]"))
        }
    except ValueError:
        try:
            addresses = {
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(
                    hostname,
                    parsed.port or (
                        443 if parsed.scheme == "https" else 80
                    ),
                    type=socket.SOCK_STREAM,
                )
            }
        except socket.gaierror as exc:
            raise ValueError(
                "No se pudo resolver el dominio."
            ) from exc

    if not addresses or any(
        not address.is_global for address in addresses
    ):
        raise ValueError(
            "El destino debe resolver únicamente a IP públicas."
        )

    return url


def registrable_domain(hostname: str) -> str:
    hostname = hostname.lower().rstrip(".")
    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        extracted = PUBLIC_SUFFIX_EXTRACTOR(hostname)
        return extracted.top_domain_under_public_suffix or hostname


def add_finding(
    findings: list,
    check_id: str,
    title: str,
    severity: str,
    evidence: str,
    recommendation: str,
    deduction: int,
):
    if check_id.startswith("WEB-COOKIE-"):
        category = OWASP_TOP10_CATEGORIES["session"]
        reference = OWASP_CHEAT_SHEETS["session"]
    elif check_id.startswith(("WEB-TLS-", "WEB-HTTPS-")):
        category = OWASP_TOP10_CATEGORIES["cryptography"]
        reference = OWASP_CHEAT_SHEETS["tls"]
    elif check_id == "WEB-SECURITY-TXT":
        category = "Guía OWASP de divulgación (fuera del Top 10)"
        reference = OWASP_CHEAT_SHEETS["disclosure"]
    else:
        category = OWASP_TOP10_CATEGORIES["configuration"]
        reference = (
            OWASP_CHEAT_SHEETS["csp"]
            if check_id.startswith("WEB-CSP-")
            else OWASP_CHEAT_SHEETS["headers"]
        )

    findings.append({
        "id": check_id,
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "recommendation": recommendation,
        "owasp_category": category,
        "owasp_reference": reference,
    })


def add_check(
    checks: list,
    check_id: str,
    category: str,
    status: str,
    title: str,
    details: str = "",
    severity: str | None = None,
):
    check = {
        "id": check_id,
        "category": category,
        "status": status,
        "title": title,
        "details": details,
    }
    if severity:
        check["severity"] = severity
    checks.append(check)


def build_scan_result(
    url: str,
    status_code: int,
    findings: list,
    checks: list,
    discovered_links: list[str] | None = None,
    discovery_incomplete: bool = False,
) -> dict:
    findings.sort(key=lambda item: SEVERITY_ORDER.get(item["severity"], 9))
    summary = {
        severity: sum(item["severity"] == severity for item in findings)
        for severity in ("high", "medium", "low", "info")
    }
    result = {
        "target": url,
        "http_status": status_code,
        "findings_count": len(findings),
        "summary": summary,
        "checks": checks,
        "findings": findings,
    }
    if discovered_links is not None:
        result["discovered_links"] = discovered_links
        result["discovery_incomplete"] = discovery_incomplete
    return result


def fetch(url: str, method: str = "GET", timeout: int = 8):
    request_options = {
        "timeout": timeout,
        "allow_redirects": False,
        "headers": {"User-Agent": USER_AGENT},
        "stream": True,
    }
    try:
        return requests.request(method, url, verify=True, **request_options)
    except requests.exceptions.SSLError:
        if urlparse(url).scheme != "https":
            raise
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", InsecureRequestWarning)
            return requests.request(method, url, verify=False, **request_options)


class AnchorCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs = []
        self.truncated = False

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        href = next((value for name, value in attrs if name.lower() == "href"), None)
        if href:
            if len(self.hrefs) >= MAX_LINKS_PER_PAGE:
                self.truncated = True
                return
            self.hrefs.append(href)


def same_origin_links(
    page_url: str,
    response,
    scope_host: str | None = None,
    include_subdomains: bool = False,
) -> tuple[list[str], bool]:
    if response.status_code != 200:
        return [], False

    content_type = response.headers.get("Content-Type", "").lower()
    if "text/html" not in content_type:
        return [], False

    parser = AnchorCollector()
    encoding = response.encoding or "utf-8"
    read_bytes = 0
    for chunk in response.iter_content(chunk_size=8192):
        remaining = MAX_HTML_BYTES - read_bytes
        if remaining <= 0:
            break
        chunk = chunk[:remaining]
        parser.feed(chunk.decode(encoding, errors="replace"))
        read_bytes += len(chunk)
        if read_bytes >= MAX_HTML_BYTES:
            break

    base = urlparse(page_url)
    allowed_host = (scope_host or base.hostname or "").lower()
    base_port = base.port or (443 if base.scheme == "https" else 80)
    links = []
    for href in parser.hrefs:
        candidate = urlparse(urljoin(page_url, href))
        if candidate.scheme not in {"http", "https"}:
            continue
        if candidate.username or candidate.password or not candidate.hostname:
            continue
        try:
            candidate_port = candidate.port or (
                443 if candidate.scheme == "https" else 80
            )
        except ValueError:
            continue
        candidate_host = candidate.hostname.lower()
        host_allowed = candidate_host == allowed_host or (
            include_subdomains and candidate_host.endswith("." + allowed_host)
        )
        if candidate.scheme != base.scheme or not host_allowed or candidate_port != base_port:
            continue
        if len(candidate.geturl()) > 2048:
            continue

        normalized = urlunparse((
            candidate.scheme,
            candidate.netloc,
            candidate.path or "/",
            candidate.params,
            candidate.query,
            "",
        ))
        if normalized not in links:
            links.append(normalized)
    return links, parser.truncated or read_bytes >= MAX_HTML_BYTES


def header_map(response) -> dict[str, str]:
    return {
        key.lower(): value
        for key, value in response.headers.items()
    }


def cookie_attribute_names(set_cookie: str) -> set[str]:
    return {
        part.strip().split("=", 1)[0].lower()
        for part in set_cookie.split(";")
        if part.strip()
    }


def set_cookie_headers(response) -> list[str]:
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    getlist = getattr(raw_headers, "getlist", None)
    if getlist:
        return getlist("Set-Cookie")

    cookie = response.headers.get("Set-Cookie")
    return [cookie] if cookie else []


def analyze_security_header_values(
    headers: dict[str, str],
    csp_value: str = "",
) -> list[tuple[str, str, str, str, str, int]]:
    issues = []
    value = headers.get("x-content-type-options", "").strip().lower()
    if value and value != "nosniff":
        issues.append((
            "x-content-type-options",
            "X-Content-Type-Options tiene un valor no efectivo",
            "low",
            f"X-Content-Type-Options: {value}",
            "Configura X-Content-Type-Options: nosniff.",
            4,
        ))

    value = headers.get("x-frame-options", "").strip().lower()
    has_frame_ancestors = "frame-ancestors" in csp_value.lower()
    if value and value not in {"deny", "sameorigin"} and not has_frame_ancestors:
        issues.append((
            "x-frame-options",
            "X-Frame-Options tiene un valor no efectivo",
            "medium",
            f"X-Frame-Options: {value}",
            "Usa DENY o SAMEORIGIN, o define frame-ancestors en CSP.",
            8,
        ))

    value = headers.get("referrer-policy", "").strip().lower()
    valid_policies = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
    }
    if value and value not in valid_policies:
        issues.append((
            "referrer-policy",
            "Referrer-Policy tiene un valor no reconocido",
            "low",
            f"Referrer-Policy: {value}",
            "Configura una política Referrer-Policy válida y restrictiva.",
            3,
        ))
    elif value == "unsafe-url":
        issues.append((
            "referrer-policy",
            "Referrer-Policy puede exponer la URL completa",
            "low",
            "Referrer-Policy: unsafe-url",
            "Usa strict-origin-when-cross-origin o una política más restrictiva.",
            4,
        ))

    return issues


def inspect_tls(hostname: str, port: int = 443) -> dict:
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=6) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls:
            cert = tls.getpeercert()
            protocol = tls.version()

    not_after = cert.get("notAfter") if cert else None
    expires_at = None
    days_left = None
    if not_after:
        expires_at = datetime.strptime(
            not_after,
            "%b %d %H:%M:%S %Y %Z",
        ).replace(tzinfo=timezone.utc)
        days_left = (expires_at - datetime.now(timezone.utc)).days

    return {
        "protocol": protocol,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "days_left": days_left,
    }


def analyze_csp(value: str) -> list[tuple[str, str, str, int]]:
    lowered = value.lower()
    issues = []
    directives = {
        parts[0]: parts[1:]
        for part in lowered.split(";")
        if (parts := part.strip().split())
    }

    if "unsafe-inline" in lowered:
        issues.append((
            "La CSP permite 'unsafe-inline'",
            "medium",
            "Se ha detectado 'unsafe-inline' en Content-Security-Policy.",
            8,
        ))
    if "unsafe-eval" in lowered:
        issues.append((
            "La CSP permite 'unsafe-eval'",
            "high",
            "Se ha detectado 'unsafe-eval' en Content-Security-Policy.",
            12,
        ))
    if re.search(r"(?:default-src|script-src)[^;]*\*", lowered):
        issues.append((
            "La CSP usa un comodín demasiado amplio",
            "medium",
            "default-src o script-src parece permitir cualquier origen.",
            8,
        ))
    if not any(token in lowered for token in ("default-src", "script-src")):
        issues.append((
            "La CSP no limita scripts de forma explícita",
            "medium",
            "No se ha encontrado default-src ni script-src.",
            8,
        ))
    object_sources = directives.get("object-src")
    if not object_sources or "'none'" not in object_sources:
        issues.append((
            "CSP no bloquea objetos incrustados",
            "medium",
            "Se recomienda definir object-src 'none' para impedir contenido de plugins.",
            6,
        ))
    if "base-uri" not in directives:
        issues.append((
            "CSP no restringe base-uri",
            "low",
            "No se ha encontrado base-uri; limita los destinos del elemento <base>.",
            4,
        ))
    return issues


def analyze_hsts(value: str) -> list[tuple[str, str, str, int]]:
    lowered = value.lower()
    issues = []
    match = re.search(r"max-age\s*=\s*(\d+)", lowered)
    if not match:
        issues.append((
            "HSTS no define max-age",
            "medium",
            "Strict-Transport-Security no incluye max-age.",
            8,
        ))
    elif int(match.group(1)) < 15552000:
        issues.append((
            "HSTS tiene un max-age corto",
            "low",
            f"max-age={match.group(1)}. Se recomienda al menos 15552000 (180 días).",
            4,
        ))
    if "includesubdomains" not in lowered:
        issues.append((
            "HSTS no incluye subdominios",
            "low",
            "Falta includeSubDomains en Strict-Transport-Security.",
            3,
        ))
    return issues


def scan_security_headers(
    url: str,
    discover_links: bool = False,
    site_level: bool = True,
    scope_host: str | None = None,
    include_subdomains: bool = False,
) -> dict:
    """Auditoría básica de configuración HTTP y HTTPS."""

    url = validate_target(url)
    parsed = urlparse(url)

    response = fetch(url)

    try:
        status_code = response.status_code
        headers = header_map(response)
        if discover_links:
            discovered_links, discovery_incomplete = same_origin_links(
                url,
                response,
                scope_host=scope_host,
                include_subdomains=include_subdomains,
            )
        else:
            discovered_links, discovery_incomplete = [], False
        findings = []
        checks = []
        csp_value = headers.get("content-security-policy", "")

        for header, rule in SECURITY_HEADERS.items():
            severity, recommendation, deduction = rule
            present = header in headers

            if header == "x-frame-options" and (
                "frame-ancestors" in csp_value.lower()
            ):
                present = True

            add_check(
                checks,
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
                add_finding(
                    findings,
                    f"WEB-HEADER-{header.upper()}",
                    f"Falta la cabecera {header}",
                    severity,
                    f"Cabecera ausente: {header}",
                    recommendation,
                    deduction,
                )

        for header, title, severity, evidence, recommendation, deduction in (
            analyze_security_header_values(headers, csp_value)
        ):
            add_check(
                checks,
                f"HEADER-{header.upper()}-QUALITY",
                "headers",
                "warning",
                title,
                details=evidence,
                severity=severity,
            )
            add_finding(
                findings,
                f"WEB-HEADER-{header.upper()}-QUALITY",
                title,
                severity,
                evidence,
                recommendation,
                deduction,
            )

        if csp_value:
            csp_issues = analyze_csp(csp_value)
            add_check(
                checks,
                "HEADER-CSP-QUALITY",
                "headers",
                "warning" if csp_issues else "pass",
                "Calidad de Content-Security-Policy",
                details=csp_value[:220],
                severity=csp_issues[0][1] if csp_issues else None,
            )
            for title, severity, evidence, deduction in csp_issues:
                add_finding(
                    findings,
                    "WEB-CSP-QUALITY",
                    title,
                    severity,
                    evidence,
                    "Elimina unsafe-inline/unsafe-eval y evita comodines amplios.",
                    deduction,
                )

        if parsed.scheme == "https":
            present = "strict-transport-security" in headers
            add_check(
                checks,
                "HEADER-HSTS",
                "headers",
                "pass" if present else "warning",
                "HTTP Strict Transport Security",
                details=headers.get("strict-transport-security", "Cabecera ausente."),
                severity=None if present else "medium",
            )
            if not present:
                add_finding(
                    findings,
                    "WEB-HEADER-HSTS",
                    "Falta la cabecera HSTS",
                    "medium",
                    "Strict-Transport-Security ausente",
                    "Configura HSTS después de verificar que HTTPS funciona correctamente.",
                    10,
                )
            else:
                hsts_issues = analyze_hsts(headers["strict-transport-security"])
                add_check(
                    checks,
                    "HEADER-HSTS-QUALITY",
                    "headers",
                    "warning" if hsts_issues else "pass",
                    "Calidad de HSTS",
                    details=headers["strict-transport-security"][:220],
                    severity=hsts_issues[0][1] if hsts_issues else None,
                )
                for title, severity, evidence, deduction in hsts_issues:
                    add_finding(
                        findings,
                        "WEB-HSTS-QUALITY",
                        title,
                        severity,
                        evidence,
                        "Usa un max-age largo e includeSubDomains cuando sea seguro.",
                        deduction,
                    )

        cookies = set_cookie_headers(response)
        if cookies:
            cookie_rules = [
                (
                    "secure",
                    "medium" if parsed.scheme == "https" else "low",
                    "Añade Secure a las cookies que deban transmitirse solo por HTTPS.",
                    6,
                ),
                (
                    "httponly",
                    "medium",
                    "Añade HttpOnly a las cookies de sesión.",
                    6,
                ),
                (
                    "samesite",
                    "low",
                    "Define SameSite según las necesidades de la aplicación.",
                    3,
                ),
            ]

            for cookie_index, cookie in enumerate(cookies, start=1):
                cookie_name = cookie.split("=", 1)[0].strip()[:80]
                attributes = cookie_attribute_names(cookie)
                details = (
                    f"Cookie: {cookie_name}. Atributos: "
                    f"{', '.join(sorted(attributes)) or 'ninguno'}"
                )

                for attribute, severity, recommendation, deduction in cookie_rules:
                    present = attribute in attributes
                    add_check(
                        checks,
                        f"COOKIE-{cookie_index}-{attribute.upper()}",
                        "cookies",
                        "pass" if present else "warning",
                        f"Cookie {cookie_name} con atributo {attribute}",
                        details=details,
                        severity=None if present else severity,
                    )
                    if not present:
                        add_finding(
                            findings,
                            f"WEB-COOKIE-{attribute.upper()}",
                            f"Cookie {cookie_name} sin atributo {attribute}",
                            severity,
                            f"No se ha identificado {attribute} en {cookie_name}.",
                            recommendation,
                            deduction,
                        )

                same_site_none = re.search(
                    r"(?:^|;)\s*samesite\s*=\s*none(?:\s*;|$)",
                    cookie,
                    re.IGNORECASE,
                )
                if same_site_none and "secure" not in attributes:
                    add_check(
                        checks,
                        f"COOKIE-{cookie_index}-SAMESITE-NONE",
                        "cookies",
                        "fail",
                        f"Cookie {cookie_name}: SameSite=None sin Secure",
                        details=details,
                        severity="high",
                    )
                    add_finding(
                        findings,
                        "WEB-COOKIE-SAMESITE-NONE",
                        f"Cookie {cookie_name}: SameSite=None requiere Secure",
                        "high",
                        f"Se detectó SameSite=None sin Secure en {cookie_name}.",
                        "Si usas SameSite=None, añade también Secure.",
                        12,
                    )
        else:
            add_check(
                checks,
                "COOKIE-SET",
                "cookies",
                "info",
                "El servidor no ha enviado Set-Cookie",
                details="No hay cookies que evaluar en esta respuesta.",
            )

        for header in ("server", "x-powered-by", "x-aspnet-version"):
            value = headers.get(header)
            add_check(
                checks,
                f"INFO-{header.upper()}",
                "disclosure",
                "warning" if value else "pass",
                f"Divulgación mediante {header}",
                details=value[:200] if value else "Cabecera no presente.",
                severity="info" if value else None,
            )
            if value:
                add_finding(
                    findings,
                    f"WEB-INFO-{header.upper()}",
                    f"El servidor revela información mediante {header}",
                    "info",
                    f"{header}: {value[:200]}",
                    "Valora reducir la información tecnológica expuesta si no es necesaria.",
                    0,
                )

        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower()
        if acao == "*" and acac == "true":
            add_check(
                checks,
                "CORS-WILDCARD-CREDENTIALS",
                "cors",
                "fail",
                "CORS permite cualquier origen con credenciales",
                details="Access-Control-Allow-Origin: * y Allow-Credentials: true",
                severity="high",
            )
            add_finding(
                findings,
                "WEB-CORS-WILDCARD-CREDENTIALS",
                "CORS permite cualquier origen con credenciales",
                "high",
                "Access-Control-Allow-Origin: * junto a Allow-Credentials: true",
                "No combines el comodín CORS con credenciales.",
                15,
            )
        elif acao == "*":
            add_check(
                checks,
                "CORS-WILDCARD",
                "cors",
                "warning",
                "CORS permite cualquier origen",
                details="Access-Control-Allow-Origin: *",
                severity="low",
            )
            add_finding(
                findings,
                "WEB-CORS-WILDCARD",
                "CORS permite cualquier origen",
                "low",
                "Access-Control-Allow-Origin: *",
                "Comprueba si el acceso desde cualquier origen es intencionado.",
                3,
            )
        else:
            add_check(
                checks,
                "CORS-WILDCARD",
                "cors",
                "pass",
                "CORS no usa un comodín global",
                details=acao or "Sin Access-Control-Allow-Origin.",
            )

        content_type = headers.get("content-type", "")
        add_check(
            checks,
            "HEADER-CONTENT-TYPE",
            "headers",
            "pass" if content_type else "warning",
            "Cabecera Content-Type",
            details=content_type or "Cabecera ausente.",
            severity=None if content_type else "low",
        )
        if not content_type:
            add_finding(
                findings,
                "WEB-HEADER-CONTENT-TYPE",
                "Falta la cabecera Content-Type",
                "low",
                "Content-Type ausente",
                "Envía un Content-Type explícito, preferiblemente con charset.",
                3,
            )
        elif "text/" in content_type.lower() and "charset=" not in content_type.lower():
            add_check(
                checks,
                "HEADER-CHARSET",
                "headers",
                "warning",
                "Charset en Content-Type",
                details=content_type,
                severity="low",
            )
            add_finding(
                findings,
                "WEB-HEADER-CHARSET",
                "Content-Type no declara charset",
                "low",
                content_type,
                "Añade charset=utf-8 en las respuestas de texto.",
                3,
            )

        cache_control = headers.get("cache-control", "").lower()
        if any(token in cache_control for token in ("no-store", "private")):
            add_check(
                checks,
                "HEADER-CACHE",
                "headers",
                "pass",
                "Control de caché",
                details=headers.get("cache-control", ""),
            )
        else:
            add_check(
                checks,
                "HEADER-CACHE",
                "headers",
                "info",
                "Control de caché",
                details=headers.get("cache-control", "Cache-Control no presente."),
                severity="info",
            )

        if not site_level:
            return build_scan_result(
                url,
                status_code,
                findings,
                checks,
                discovered_links if discover_links else None,
                discovery_incomplete,
            )

        if parsed.scheme == "http":
            add_check(
                checks,
                "HTTPS-TRANSPORT",
                "transport",
                "fail",
                "La URL utiliza HTTP",
                details="La dirección de entrada no utiliza HTTPS.",
                severity="high",
            )
            add_finding(
                findings,
                "WEB-HTTPS-NOT-USED",
                "La URL analizada utiliza HTTP",
                "high",
                "La dirección de entrada no utiliza HTTPS.",
                "Usa HTTPS y redirige HTTP hacia HTTPS.",
                15,
            )
        else:
            add_check(
                checks,
                "HTTPS-TRANSPORT",
                "transport",
                "pass",
                "La URL utiliza HTTPS",
            )

            try:
                tls = inspect_tls(
                    parsed.hostname,
                    parsed.port or 443,
                )
                protocol = tls.get("protocol") or "desconocido"
                days_left = tls.get("days_left")
                details = f"Protocolo {protocol}"
                if tls.get("expires_at"):
                    details += f". Certificado válido hasta {tls['expires_at'][:10]}."

                tls_status = "pass"
                tls_severity = None
                if protocol in {"TLSv1", "TLSv1.1", "SSLv3"}:
                    tls_status = "fail"
                    tls_severity = "high"
                    add_finding(
                        findings,
                        "WEB-TLS-PROTOCOL",
                        f"El servidor usa un protocolo TLS obsoleto ({protocol})",
                        "high",
                        details,
                        "Deshabilita TLS 1.0/1.1 y usa TLS 1.2 o superior.",
                        15,
                    )
                elif isinstance(days_left, int) and days_left < 0:
                    tls_status = "fail"
                    tls_severity = "high"
                    add_finding(
                        findings,
                        "WEB-TLS-EXPIRED",
                        "El certificado TLS ha caducado",
                        "high",
                        details,
                        "Renueva el certificado cuanto antes.",
                        20,
                    )
                elif isinstance(days_left, int) and days_left < 21:
                    tls_status = "warning"
                    tls_severity = "medium"
                    add_finding(
                        findings,
                        "WEB-TLS-EXPIRING",
                        "El certificado TLS caduca pronto",
                        "medium",
                        details,
                        "Planifica la renovación del certificado.",
                        8,
                    )

                add_check(
                    checks,
                    "TLS-CERTIFICATE",
                    "transport",
                    tls_status,
                    "Certificado y protocolo TLS",
                    details=details,
                    severity=tls_severity,
                )
            except ssl.SSLError as exc:
                add_check(
                    checks,
                    "TLS-CERTIFICATE",
                    "transport",
                    "fail",
                    "El certificado TLS no se ha podido validar",
                    details=str(exc)[:220],
                    severity="high",
                )
                add_finding(
                    findings,
                    "WEB-TLS-INVALID",
                    "El certificado TLS no es de confianza",
                    "high",
                    str(exc)[:220],
                    "Instala un certificado válido emitido por una CA reconocida.",
                    18,
                )
            except OSError:
                add_check(
                    checks,
                    "TLS-CERTIFICATE",
                    "transport",
                    "unknown",
                    "No se pudo inspeccionar el certificado TLS",
                )

            http_url = urlunparse(("http", parsed.netloc, parsed.path or "/", parsed.params, parsed.query, ""))
            try:
                http_response = fetch(http_url, timeout=5)
                try:
                    location = http_response.headers.get("Location", "")
                    redirected = (
                        300 <= http_response.status_code < 400
                        and location.lower().startswith("https://")
                    )
                    add_check(
                        checks,
                        "HTTPS-REDIRECT",
                        "transport",
                        "pass" if redirected else "warning",
                        "Redirección de HTTP a HTTPS",
                        details=(
                            f"{http_response.status_code} → {location[:180]}"
                            if location
                            else f"HTTP respondió {http_response.status_code} sin Location HTTPS."
                        ),
                        severity=None if redirected else "medium",
                    )
                    if not redirected:
                        add_finding(
                            findings,
                            "WEB-HTTPS-REDIRECT",
                            "HTTP no redirige a HTTPS",
                            "medium",
                            f"http://{parsed.hostname} respondió {http_response.status_code}.",
                            "Redirige todas las peticiones HTTP hacia HTTPS.",
                            8,
                        )
                finally:
                    http_response.close()
            except requests.RequestException:
                add_check(
                    checks,
                    "HTTPS-REDIRECT",
                    "transport",
                    "unknown",
                    "No se pudo comprobar la redirección HTTP→HTTPS",
                )

        try:
            options = fetch(url, method="OPTIONS", timeout=5)
            try:
                allowed = options.headers.get("Allow", "")
                risky = [
                    method
                    for method in ("TRACE", "TRACK", "DEBUG")
                    if method in allowed.upper()
                ]
                if risky:
                    add_check(
                        checks,
                        "HTTP-METHODS",
                        "configuration",
                        "fail",
                        "Métodos HTTP potencialmente peligrosos",
                        details=allowed[:200],
                        severity="high",
                    )
                    add_finding(
                        findings,
                        "WEB-HTTP-METHODS",
                        f"El servidor anuncia métodos sensibles: {', '.join(risky)}",
                        "high",
                        allowed[:200],
                        "Deshabilita TRACE/TRACK/DEBUG si no son necesarios.",
                        12,
                    )
                elif allowed:
                    add_check(
                        checks,
                        "HTTP-METHODS",
                        "configuration",
                        "info",
                        "Métodos anunciados por el servidor",
                        details=allowed[:200],
                    )
                else:
                    add_check(
                        checks,
                        "HTTP-METHODS",
                        "configuration",
                        "info",
                        "El servidor no anuncia métodos en Allow",
                    )
            finally:
                options.close()
        except requests.RequestException:
            add_check(
                checks,
                "HTTP-METHODS",
                "configuration",
                "unknown",
                "No se pudieron comprobar los métodos HTTP",
            )

        security_txt = urljoin(f"{parsed.scheme}://{parsed.netloc}", "/.well-known/security.txt")
        try:
            txt_response = fetch(security_txt, timeout=5)
            try:
                present = txt_response.status_code == 200
                add_check(
                    checks,
                    "SECURITY-TXT",
                    "configuration",
                    "pass" if present else "info",
                    "Archivo security.txt",
                    details=f"{security_txt} → {txt_response.status_code}",
                    severity=None if present else "info",
                )
                if not present:
                    add_finding(
                        findings,
                        "WEB-SECURITY-TXT",
                        "No se ha encontrado security.txt",
                        "info",
                        f"{security_txt} respondió {txt_response.status_code}.",
                        "Publica /.well-known/security.txt para el contacto de seguridad.",
                        0,
                    )
            finally:
                txt_response.close()
        except requests.RequestException:
            add_check(
                checks,
                "SECURITY-TXT",
                "configuration",
                "unknown",
                "No se pudo consultar security.txt",
            )

        return build_scan_result(
            url,
            status_code,
            findings,
            checks,
            discovered_links if discover_links else None,
            discovery_incomplete,
        )

    finally:
        response.close()


def scan_website(
    url: str,
    crawl: bool = False,
) -> dict:
    target = validate_target(url)
    target_host = registrable_domain(urlparse(target).hostname or "")
    page_limit = MAX_CRAWL_PAGES if crawl else 1
    deadline = monotonic() + MAX_CRAWL_SECONDS
    queue = [target]
    visited = set()
    scanned_pages = []
    findings = []
    checks = []
    failed_pages = []
    root_status = None
    discovery_incomplete = False

    while (
        queue
        and len(visited) < page_limit
        and monotonic() < deadline
    ):
        page_url = queue.pop(0)
        if page_url in visited:
            continue
        visited.add(page_url)

        try:
            result = scan_security_headers(
                page_url,
                discover_links=crawl,
                site_level=not scanned_pages,
                scope_host=target_host,
                include_subdomains=crawl,
            )
        except (ValueError, requests.RequestException):
            if not scanned_pages:
                raise
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
        discovery_incomplete = (
            discovery_incomplete or result.get("discovery_incomplete", False)
        )

        for finding in result["findings"]:
            finding["page"] = page_url
            findings.append(finding)
        for check in result["checks"]:
            check["page"] = page_url
            checks.append(check)

        for link in result.get("discovered_links", []):
            if link not in visited and link not in queue:
                queue.append(link)

    result = build_scan_result(target, root_status or 0, findings, checks)
    result["pages_scanned"] = len(scanned_pages)
    result["scanned_pages"] = scanned_pages
    result["page_limit"] = page_limit
    stop_reasons = []
    if failed_pages:
        stop_reasons.append("page_error")
    if discovery_incomplete:
        stop_reasons.append("link_or_content_limit")
    if queue and len(visited) >= page_limit:
        stop_reasons.append("page_limit")
    elif queue and monotonic() >= deadline:
        stop_reasons.append("time_limit")
    result["crawl_complete"] = not stop_reasons
    result["crawl_stop_reason"] = stop_reasons[0] if stop_reasons else "completed"
    result["crawl_stop_reasons"] = stop_reasons
    result["failed_pages"] = failed_pages
    return result
