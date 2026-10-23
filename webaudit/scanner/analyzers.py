"""Análisis puros (sin red) del valor de cabeceras y cookies."""

import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import NamedTuple

from .config import HSTS_MIN_MAX_AGE, UNSUPPORTED_BELOW, VALID_REFERRER_POLICIES
from .results import tr


class Issue(NamedTuple):
    title: str
    severity: str
    evidence: str


class HeaderValueIssue(NamedTuple):
    header: str
    title: str
    severity: str
    evidence: str
    recommendation: str


NONCE_OR_HASH = ("'nonce-", "'sha256-", "'sha384-", "'sha512-")
SOFTWARE_VERSION = re.compile(r"\b(apache|nginx|php|microsoft-iis|openssl)/(\d+(?:\.\d+)+)", re.IGNORECASE)


def cookie_attribute_names(set_cookie: str) -> set[str]:
    return set(cookie_attributes(set_cookie))


def cookie_attributes(set_cookie: str) -> dict[str, str]:
    """Atributos de un Set-Cookie (sin el par nombre=valor), en minúsculas."""

    attributes = {}
    for part in set_cookie.split(";")[1:]:
        name, _, value = part.strip().partition("=")
        if name:
            attributes[name.strip().lower()] = value.strip()
    return attributes


def analyze_security_header_values(
    headers: dict[str, str],
    csp_value: str = "",
) -> list[HeaderValueIssue]:
    issues = []

    value = headers.get("x-content-type-options", "").strip().lower()
    if value and value != "nosniff":
        issues.append(HeaderValueIssue(
            "x-content-type-options",
            "X-Content-Type-Options tiene un valor no efectivo",
            "low",
            f"X-Content-Type-Options: {value}",
            "Configura X-Content-Type-Options: nosniff.",
        ))

    value = headers.get("x-frame-options", "").strip().lower()
    has_frame_ancestors = "frame-ancestors" in csp_value.lower()
    if value and value not in {"deny", "sameorigin"} and not has_frame_ancestors:
        issues.append(HeaderValueIssue(
            "x-frame-options",
            "X-Frame-Options tiene un valor no efectivo",
            "medium",
            f"X-Frame-Options: {value}",
            "Usa DENY o SAMEORIGIN, o define frame-ancestors en CSP.",
        ))

    value = headers.get("referrer-policy", "").strip().lower()
    if value and value not in VALID_REFERRER_POLICIES:
        issues.append(HeaderValueIssue(
            "referrer-policy",
            "Referrer-Policy tiene un valor no reconocido",
            "low",
            f"Referrer-Policy: {value}",
            "Configura una política Referrer-Policy válida y restrictiva.",
        ))
    elif value == "unsafe-url":
        issues.append(HeaderValueIssue(
            "referrer-policy",
            "Referrer-Policy puede exponer la URL completa",
            "low",
            "Referrer-Policy: unsafe-url",
            "Usa strict-origin-when-cross-origin o una política más restrictiva.",
        ))

    return issues


def analyze_csp(value: str) -> list[Issue]:
    lowered = value.lower()
    directives = {
        parts[0]: parts[1:]
        for part in lowered.split(";")
        if (parts := part.strip().split())
    }
    issues = []

    default_sources = directives.get("default-src", [])
    script_sources = directives.get("script-src", default_sources)
    style_sources = directives.get("style-src", default_sources)
    # Con nonce o hash, los navegadores ignoran 'unsafe-inline' en scripts (CSP 2+).
    script_nonce_or_hash = any(source.startswith(NONCE_OR_HASH) for source in script_sources)

    if "'unsafe-inline'" in script_sources and not script_nonce_or_hash:
        issues.append(Issue(
            "La CSP permite 'unsafe-inline'",
            "medium",
            "Se ha detectado 'unsafe-inline' en Content-Security-Policy.",
        ))
    if "'unsafe-inline'" in style_sources:
        issues.append(Issue(
            "La CSP permite estilos inline ('unsafe-inline')",
            "low",
            "style-src permite 'unsafe-inline'; el riesgo es menor que en scripts.",
        ))
    if "unsafe-eval" in lowered:
        issues.append(Issue(
            "La CSP permite 'unsafe-eval'",
            "high",
            "Se ha detectado 'unsafe-eval' en Content-Security-Policy.",
        ))
    if re.search(r"(?:default-src|script-src)[^;]*\*", lowered):
        issues.append(Issue(
            "La CSP usa un comodín demasiado amplio",
            "medium",
            "default-src o script-src parece permitir cualquier origen.",
        ))
    if not any(token in lowered for token in ("default-src", "script-src")):
        issues.append(Issue(
            "La CSP no limita scripts de forma explícita",
            "medium",
            "No se ha encontrado default-src ni script-src.",
        ))
    object_sources = directives.get("object-src")
    if not object_sources or "'none'" not in object_sources:
        issues.append(Issue(
            "CSP no bloquea objetos incrustados",
            "medium",
            "Se recomienda definir object-src 'none' para impedir contenido de plugins.",
        ))
    if "base-uri" not in directives:
        issues.append(Issue(
            "CSP no restringe base-uri",
            "low",
            "No se ha encontrado base-uri; limita los destinos del elemento <base>.",
        ))
    return issues


def analyze_hsts(value: str) -> list[Issue]:
    lowered = value.lower()
    issues = []

    match = re.search(r"max-age\s*=\s*(\d+)", lowered)
    if not match:
        issues.append(Issue(
            "HSTS no define max-age",
            "medium",
            "Strict-Transport-Security no incluye max-age.",
        ))
    elif int(match.group(1)) < HSTS_MIN_MAX_AGE:
        issues.append(Issue(
            "HSTS tiene un max-age corto",
            "low",
            tr(
                "max-age={value}. Se recomienda al menos {minimum} (180 días).",
                value=match.group(1), minimum=HSTS_MIN_MAX_AGE,
            ),
        ))
    if "includesubdomains" not in lowered:
        issues.append(Issue(
            "HSTS no incluye subdominios",
            "low",
            "Falta includeSubDomains en Strict-Transport-Security.",
        ))
    return issues


def cookie_lifetime_days(attributes: dict[str, str]) -> int | None:
    """Días hasta que caduca la cookie (Max-Age tiene prioridad sobre Expires).
    None si es una cookie de sesión del navegador (sin caducidad)."""

    max_age = attributes.get("max-age", "")
    if re.fullmatch(r"-?\d+", max_age):
        return int(max_age) // 86400
    expires = attributes.get("expires")
    if expires:
        try:
            date = parsedate_to_datetime(expires)
        except (TypeError, ValueError):
            return None
        if date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)
        return (date - datetime.now(timezone.utc)).days
    return None


def outdated_software(text: str) -> list[str]:
    """Productos con versión sin soporte anunciados en Server o X-Powered-By."""

    outdated = []
    for product, version in SOFTWARE_VERSION.findall(text):
        minimum = UNSUPPORTED_BELOW.get(product.lower())
        numbers = tuple(int(part) for part in version.split(".")[:2])
        if minimum and numbers < minimum:
            outdated.append(f"{product}/{version}")
    return outdated
