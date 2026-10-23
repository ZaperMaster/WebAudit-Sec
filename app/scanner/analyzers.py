"""Análisis puros (sin red) del valor de cabeceras y cookies."""

import re
from typing import NamedTuple

from .config import HSTS_MIN_MAX_AGE, VALID_REFERRER_POLICIES


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


def cookie_attribute_names(set_cookie: str) -> set[str]:
    return {
        part.strip().split("=", 1)[0].lower()
        for part in set_cookie.split(";")
        if part.strip()
    }


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

    if "unsafe-inline" in lowered:
        issues.append(Issue(
            "La CSP permite 'unsafe-inline'",
            "medium",
            "Se ha detectado 'unsafe-inline' en Content-Security-Policy.",
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
            f"max-age={match.group(1)}. Se recomienda al menos {HSTS_MIN_MAX_AGE} (180 días).",
        ))
    if "includesubdomains" not in lowered:
        issues.append(Issue(
            "HSTS no incluye subdominios",
            "low",
            "Falta includeSubDomains en Strict-Transport-Security.",
        ))
    return issues
