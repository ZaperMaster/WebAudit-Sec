"""Comprobaciones DNS del dominio: SPF, DMARC y CAA.

Protegen frente a la suplantación del dominio en correos (SPF, DMARC) y
limitan qué autoridades pueden emitir certificados para él (CAA).
"""

import ipaddress
import re

import dns.exception
import dns.resolver

from .network import registrable_domain
from .results import Report, tr


DNS_TIMEOUT = 4
SPF_ALL = re.compile(r"(?:^|\s)([+?~-]?)all(?:\s|$)", re.IGNORECASE)
DMARC_POLICY = re.compile(r"(?:^|;)\s*p\s*=\s*(\w+)", re.IGNORECASE)


class DnsUnavailable(Exception):
    """El DNS no respondió (distinto de «no existe el registro»)."""


def _resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    return resolver


def _query(name: str, record_type: str) -> list:
    try:
        return list(_resolver().resolve(name, record_type))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
        raise DnsUnavailable() from exc


def _txt_records(name: str) -> list[str]:
    # Un TXT puede venir troceado en varias cadenas de 255 bytes.
    return [
        b"".join(record.strings).decode("utf-8", errors="replace")
        for record in _query(name, "TXT")
    ]


def check_dns(report: Report, hostname: str) -> None:
    domain = registrable_domain(hostname)
    try:
        ipaddress.ip_address(domain)
        return  # Una IP no tiene registros de dominio que revisar
    except ValueError:
        pass

    for check in (_check_spf, _check_dmarc, _check_caa):
        try:
            check(report, domain)
        except DnsUnavailable:
            report.check(
                f"DNS-{check.__name__[7:].upper()}", "dns", "unknown",
                tr("No se pudo consultar el DNS de {domain}", domain=domain),
            )


def _check_spf(report: Report, domain: str) -> None:
    records = [txt for txt in _txt_records(domain) if txt.lower().startswith("v=spf1")]
    title = tr("Registro SPF de {domain}", domain=domain)

    if not records:
        report.check("DNS-SPF", "dns", "warning", title, details="Sin registro SPF.", severity="low")
        report.finding(
            "WEB-DNS-SPF-MISSING",
            tr("El dominio {domain} no publica un registro SPF", domain=domain),
            "low", tr("{domain} no tiene un registro TXT v=spf1.", domain=domain),
            "Publica SPF con los servidores que envían tu correo; si el dominio no envía correo, usa 'v=spf1 -all'.",
        )
        return
    if len(records) > 1:
        report.check("DNS-SPF", "dns", "fail", title, details=" | ".join(records)[:220], severity="medium")
        report.finding(
            "WEB-DNS-SPF-MULTIPLE", "Hay varios registros SPF y el estándar solo permite uno",
            "medium", " | ".join(records)[:220],
            "Une los registros SPF en uno solo; con varios, los servidores de correo lo dan por no válido.",
        )
        return

    record = records[0]
    match = SPF_ALL.search(record)
    qualifier = match.group(1) if match else None
    if qualifier in ("", "+"):
        report.check("DNS-SPF", "dns", "fail", title, details=record[:220], severity="high")
        report.finding(
            "WEB-DNS-SPF-PERMISSIVE",
            "El SPF permite enviar correo en nombre del dominio desde cualquier servidor (+all)",
            "high", record[:220], "Termina el registro SPF con '-all' o '~all'.",
        )
    elif qualifier == "?" or match is None:
        report.check("DNS-SPF", "dns", "warning", title, details=record[:220], severity="low")
        report.finding(
            "WEB-DNS-SPF-NEUTRAL", "El SPF no indica qué hacer con los correos no autorizados",
            "low", record[:220], "Termina el registro SPF con '-all' o '~all'.",
        )
    else:
        report.check("DNS-SPF", "dns", "pass", title, details=record[:220])


def _check_dmarc(report: Report, domain: str) -> None:
    records = [txt for txt in _txt_records(f"_dmarc.{domain}") if txt.lower().startswith("v=dmarc1")]
    title = tr("Política DMARC de {domain}", domain=domain)

    if not records:
        report.check("DNS-DMARC", "dns", "warning", title, details="Sin registro DMARC.", severity="low")
        report.finding(
            "WEB-DNS-DMARC-MISSING",
            tr("El dominio {domain} no publica DMARC", domain=domain),
            "low", tr("_dmarc.{domain} no tiene un registro v=DMARC1.", domain=domain),
            "Publica DMARC en _dmarc: empieza con p=none para observar y pasa a quarantine o reject.",
        )
        return

    record = records[0]
    policy = DMARC_POLICY.search(record)
    if policy and policy.group(1).lower() == "none":
        report.check("DNS-DMARC", "dns", "warning", title, details=record[:220], severity="low")
        report.finding(
            "WEB-DNS-DMARC-NONE", "DMARC solo observa (p=none): no protege frente a la suplantación",
            "low", record[:220],
            "Cuando hayas revisado los informes, sube la política a quarantine o reject.",
        )
    else:
        report.check("DNS-DMARC", "dns", "pass", title, details=record[:220])


def _check_caa(report: Report, domain: str) -> None:
    records = [record.to_text() for record in _query(domain, "CAA")]
    title = tr("Registros CAA de {domain}", domain=domain)

    if records:
        report.check("DNS-CAA", "dns", "pass", title, details=" | ".join(records)[:220])
        return
    report.check("DNS-CAA", "dns", "info", title, details="Sin registros CAA.", severity="info")
    report.finding(
        "WEB-DNS-CAA-MISSING",
        "El dominio no limita qué autoridades pueden emitir sus certificados (sin CAA)",
        "info", tr("{domain} no tiene registros CAA.", domain=domain),
        "Publica registros CAA con las autoridades que usas, por ejemplo letsencrypt.org.",
    )
