"""Estructuras de resultados: comprobaciones (checks) y hallazgos (findings)."""

from .config import OWASP_CHEAT_SHEETS, OWASP_TOP10_CATEGORIES, SEVERITIES, SEVERITY_ORDER


def owasp_mapping(check_id: str) -> tuple[str, str]:
    """Devuelve (categoría OWASP, URL de la guía) para un identificador de hallazgo."""

    if check_id.startswith("WEB-COOKIE-"):
        return OWASP_TOP10_CATEGORIES["session"], OWASP_CHEAT_SHEETS["session"]
    if check_id.startswith(("WEB-TLS-", "WEB-HTTPS-")):
        return OWASP_TOP10_CATEGORIES["cryptography"], OWASP_CHEAT_SHEETS["tls"]
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
