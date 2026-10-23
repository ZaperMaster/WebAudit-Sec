"""Estructuras de resultados: comprobaciones (checks) y hallazgos (findings)."""

from .config import OWASP_CHEAT_SHEETS, OWASP_TOP10_CATEGORIES, SEVERITIES, SEVERITY_ORDER


TEXT_FIELDS = ("title", "details", "evidence", "recommendation")


class Text(str):
    """Texto en español que conserva su plantilla y sus datos.

    Se serializa como el texto normal; además, add_check/add_finding guardan la
    plantilla en `i18n` para que la interfaz pueda mostrarlo en otro idioma
    (catálogo en static/js/i18n.js). Los textos fijos se traducen por
    coincidencia exacta y no necesitan Text.
    """

    def __new__(cls, template: str, **params):
        text = super().__new__(cls, template.format(**params))
        text.template = template
        text.params = {key: str(value) for key, value in params.items()}
        return text


def tr(template: str, **params) -> Text:
    return Text(template, **params)


def _i18n(item: dict) -> dict:
    return {
        field: {"template": value.template, "params": value.params}
        for field in TEXT_FIELDS
        if isinstance(value := item.get(field), Text)
    }


def owasp_mapping(check_id: str) -> tuple[str, str]:
    """Devuelve (categoría OWASP, URL de la guía) para un identificador de hallazgo."""

    if check_id.startswith("WEB-COOKIE-"):
        return OWASP_TOP10_CATEGORIES["session"], OWASP_CHEAT_SHEETS["session"]
    if check_id.startswith(("WEB-TLS-", "WEB-HTTPS-", "WEB-MIXED-")):
        return OWASP_TOP10_CATEGORIES["cryptography"], OWASP_CHEAT_SHEETS["tls"]
    if check_id.startswith("WEB-SRI-"):
        return OWASP_TOP10_CATEGORIES["integrity"], OWASP_CHEAT_SHEETS["third_party_js"]
    if check_id == "WEB-SECURITY-TXT":
        return "Guía OWASP de divulgación (fuera del Top 10)", OWASP_CHEAT_SHEETS["disclosure"]
    if check_id.startswith("WEB-CSP-"):
        return OWASP_TOP10_CATEGORIES["configuration"], OWASP_CHEAT_SHEETS["csp"]
    return OWASP_TOP10_CATEGORIES["configuration"], OWASP_CHEAT_SHEETS["headers"]


def add_finding(
    findings: list,
    check_id: str,
    title: str,
    severity: str,
    evidence: str,
    recommendation: str,
) -> None:
    category, reference = owasp_mapping(check_id)
    finding = {
        "id": check_id,
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "recommendation": recommendation,
        "owasp_category": category,
        "owasp_reference": reference,
    }
    if i18n := _i18n(finding):
        finding["i18n"] = i18n
    findings.append(finding)


def add_check(
    checks: list,
    check_id: str,
    category: str,
    status: str,
    title: str,
    details: str = "",
    severity: str | None = None,
) -> None:
    check = {
        "id": check_id,
        "category": category,
        "status": status,
        "title": title,
        "details": details,
    }
    if severity:
        check["severity"] = severity
    if i18n := _i18n(check):
        check["i18n"] = i18n
    checks.append(check)


class Report:
    """Acumula checks y findings de un análisis con una API corta."""

    def __init__(self):
        self.checks: list[dict] = []
        self.findings: list[dict] = []

    def check(self, check_id, category, status, title, details="", severity=None):
        add_check(self.checks, check_id, category, status, title, details, severity)

    def finding(self, check_id, title, severity, evidence, recommendation):
        add_finding(self.findings, check_id, title, severity, evidence, recommendation)


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
        for severity in SEVERITIES
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
