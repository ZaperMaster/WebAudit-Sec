"""Comprobaciones TLS de un host: certificado y cadena, clave, versiones y revocación."""

import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from . import tls
from .config import OBSOLETE_TLS_PROTOCOLS, TLS_EXPIRY_WARNING_DAYS
from .network import legacy_tls_context
from .results import Report, tr


MIN_RSA_BITS = 2048
MIN_EC_BITS = 256
WEAK_SIGNATURE_HASHES = {"md5", "sha1"}

# Código de error de OpenSSL -> (id, título, severidad, recomendación)
CERTIFICATE_ERRORS = {
    10: (
        "WEB-TLS-EXPIRED", "El certificado TLS ha caducado", "high",
        "Renueva el certificado cuanto antes.",
    ),
    18: (
        "WEB-TLS-SELF-SIGNED", "El certificado TLS es autofirmado", "high",
        "Usa un certificado emitido por una CA reconocida, por ejemplo Let's Encrypt.",
    ),
    19: (
        "WEB-TLS-UNTRUSTED-ROOT", "La cadena termina en una CA raíz que no es de confianza", "high",
        "Instala un certificado válido emitido por una CA reconocida.",
    ),
    62: (
        "WEB-TLS-HOSTNAME", "El certificado no corresponde a este dominio", "high",
        "Usa un certificado que incluya este dominio entre sus nombres (SAN).",
    ),
    68: (
        "WEB-TLS-WEAK-SIGNATURE", "La cadena del certificado usa una firma débil", "high",
        "Reemite el certificado y sus intermedios con SHA-256 o superior.",
    ),
}
INCOMPLETE_CHAIN = (
    "WEB-TLS-INCOMPLETE-CHAIN", "El servidor no envía la cadena de certificados completa", "medium",
    "Configura el servidor para enviar también los certificados intermedios.",
)
UNKNOWN_ISSUER = (
    "WEB-TLS-UNTRUSTED-ROOT", "El emisor del certificado no es de confianza", "high",
    "Instala un certificado válido emitido por una CA reconocida.",
)


def check_tls(report: Report, hostname: str, port: int) -> None:
    verify_error = handshake_error = None
    try:
        info = tls.handshake(hostname, port)
    except ssl.SSLCertVerificationError as exc:
        verify_error = exc
        info = None
    except ssl.SSLError as exc:
        handshake_error = str(exc)[:220]
        info = None
    except OSError:
        info = None

    if info is None:
        # Conexión permisiva: aunque el certificado no valga, se puede inspeccionar.
        try:
            info = tls.handshake(hostname, port, legacy_tls_context())
        except ssl.SSLError as exc:
            report_unreachable_tls(report, str(exc))
            return
        except OSError:
            report.check(
                "TLS-CERTIFICATE", "transport", "unknown",
                "No se pudo inspeccionar el certificado TLS",
            )
            return

    leaf = info.chain[0] if info.chain else None
    _check_certificate(report, info, leaf, verify_error, handshake_error)
    if leaf is not None:
        _check_key(report, leaf, already_reported=_error_code(verify_error) == 68)
    _check_versions(report, hostname, port, info.protocol)
    _check_revocation(report, info.chain)


def _error_code(error) -> int | None:
    return getattr(error, "verify_code", None)


def _certificate_summary(leaf: x509.Certificate | None):
    if leaf is None:
        return ""
    return tr(
        "Emitido para {subject} por {issuer}. Válido hasta {date}.",
        subject=_common_name(leaf.subject),
        issuer=_common_name(leaf.issuer),
        date=leaf.not_valid_after_utc.date().isoformat(),
    )


def _common_name(name: x509.Name) -> str:
    attributes = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return str(attributes[0].value) if attributes else (name.rfc4514_string() or "?")


def _check_certificate(report, info, leaf, verify_error, handshake_error) -> None:
    summary = _certificate_summary(leaf)

    if handshake_error:
        # Un cliente moderno rechaza la conexión; la permisiva sí funciona.
        details = tr(
            "Protocolo {protocol}, cifrado {cipher}. {error}",
            protocol=info.protocol, cipher=info.cipher, error=handshake_error,
        )
        report.check(
            "TLS-CERTIFICATE", "transport", "fail",
            "Configuración TLS rechazada por clientes modernos",
            details=details, severity="high",
        )
        report.finding(
            "WEB-TLS-WEAK",
            "El servidor solo ofrece TLS o cifrados obsoletos",
            "high", details,
            "Usa TLS 1.2 o superior con cifrados modernos y claves de al menos 2048 bits.",
        )
        return

    if verify_error is not None:
        code = _error_code(verify_error)
        if code in CERTIFICATE_ERRORS:
            finding_id, title, severity, recommendation = CERTIFICATE_ERRORS[code]
        elif code in (20, 21) and leaf is not None and len(info.chain) == 1 and leaf.issuer != leaf.subject:
            finding_id, title, severity, recommendation = INCOMPLETE_CHAIN
        elif code in (2, 20, 21):
            finding_id, title, severity, recommendation = UNKNOWN_ISSUER
        else:
            finding_id, title, severity, recommendation = (
                "WEB-TLS-INVALID", "El certificado TLS no es de confianza", "high",
                "Instala un certificado válido emitido por una CA reconocida.",
            )

        # En la comprobación, el motivo técnico de OpenSSL; en el hallazgo, el certificado.
        error = getattr(verify_error, "verify_message", "") or str(verify_error)[:220]
        report.check("TLS-CERTIFICATE", "transport", "fail", title, details=error, severity=severity)
        report.finding(finding_id, title, severity, summary or error, recommendation)
        return

    if leaf is None:
        report.check(
            "TLS-CERTIFICATE", "transport", "unknown",
            "No se pudo inspeccionar el certificado TLS",
        )
        return

    days_left = (leaf.not_valid_after_utc - datetime.now(timezone.utc)).days
    if days_left < TLS_EXPIRY_WARNING_DAYS:
        report.check(
            "TLS-CERTIFICATE", "transport", "warning", "El certificado TLS caduca pronto",
            details=summary, severity="medium",
        )
        report.finding(
            "WEB-TLS-EXPIRING", "El certificado TLS caduca pronto",
            "medium", summary, "Planifica la renovación del certificado.",
        )
    else:
        report.check("TLS-CERTIFICATE", "transport", "pass", "Certificado TLS válido", details=summary)


def _check_key(report: Report, leaf: x509.Certificate, already_reported: bool) -> None:
    key = leaf.public_key()
    key_type, bits, weak_key = "?", 0, False
    if isinstance(key, rsa.RSAPublicKey):
        key_type, bits = "RSA", key.key_size
        weak_key = bits < MIN_RSA_BITS
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_type, bits = "EC", key.curve.key_size
        weak_key = bits < MIN_EC_BITS

    algorithm = leaf.signature_hash_algorithm.name if leaf.signature_hash_algorithm else "?"
    weak_signature = algorithm in WEAK_SIGNATURE_HASHES
    details = tr(
        "Clave {key_type} de {bits} bits, firma {algorithm}.",
        key_type=key_type, bits=bits, algorithm=algorithm,
    )

    failed = weak_key or (weak_signature and not already_reported)
    report.check(
        "TLS-KEY", "transport", "fail" if failed else "pass",
        "Clave y firma del certificado", details=details,
        severity="high" if failed else None,
    )
    if weak_key:
        report.finding(
            "WEB-TLS-WEAK-KEY",
            tr("El certificado usa una clave demasiado corta ({bits} bits)", bits=bits),
            "high", details,
            "Usa una clave RSA de al menos 2048 bits o una clave EC de al menos 256 bits.",
        )
    if weak_signature and not already_reported:
        report.finding(
            "WEB-TLS-WEAK-SIGNATURE", "La cadena del certificado usa una firma débil",
            "high", details, "Reemite el certificado y sus intermedios con SHA-256 o superior.",
        )


def _check_versions(report: Report, hostname: str, port: int, negotiated: str | None) -> None:
    versions = tls.supported_tls_versions(hostname, port, negotiated)
    if not versions:
        report.check(
            "TLS-VERSIONS", "transport", "unknown",
            "No se pudieron determinar las versiones de TLS",
        )
        return

    details = tr("Versiones aceptadas: {versions}", versions=", ".join(versions))
    obsolete = [version for version in versions if version in OBSOLETE_TLS_PROTOCOLS]
    if obsolete:
        report.check(
            "TLS-VERSIONS", "transport", "fail", "Versiones de TLS aceptadas",
            details=details, severity="high",
        )
        report.finding(
            "WEB-TLS-PROTOCOL",
            tr("El servidor acepta protocolos TLS obsoletos: {versions}", versions=", ".join(obsolete)),
            "high", details,
            "Deshabilita TLS 1.0/1.1 y usa TLS 1.2 o superior.",
        )
    elif "TLSv1.3" not in versions:
        report.check(
            "TLS-VERSIONS", "transport", "warning", "Versiones de TLS aceptadas",
            details=details, severity="low",
        )
        report.finding(
            "WEB-TLS-NO-TLS13", "El servidor no admite TLS 1.3",
            "low", details, "Activa TLS 1.3 para mejorar la seguridad y el rendimiento.",
        )
    else:
        report.check("TLS-VERSIONS", "transport", "pass", "Versiones de TLS aceptadas", details=details)


def _check_revocation(report: Report, chain: list[x509.Certificate]) -> None:
    result = tls.check_revocation(chain)
    if result.status == "revoked":
        details = tr(
            "Revocado el {date} (según {method}).",
            date=result.detail or "?", method=result.method,
        )
        report.check(
            "TLS-REVOCATION", "transport", "fail", "El certificado TLS ha sido revocado",
            details=details, severity="high",
        )
        report.finding(
            "WEB-TLS-REVOKED", "El certificado TLS ha sido revocado",
            "high", details, "Sustituye el certificado por uno nuevo cuanto antes.",
        )
    elif result.status == "good":
        report.check(
            "TLS-REVOCATION", "transport", "pass", "Estado de revocación del certificado",
            details=tr("No revocado (consultado por {method}).", method=result.method),
        )
    else:
        report.check(
            "TLS-REVOCATION", "transport", "unknown", "No se pudo comprobar la revocación",
            details=result.detail,
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
