"""Inspección TLS a bajo nivel: handshake, cadena, versiones y revocación.

No genera hallazgos; tls_checks.py interpreta estos datos.
"""

import socket
import ssl
from functools import lru_cache
from time import sleep, time
from typing import NamedTuple

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from .config import USER_AGENT
from .network import legacy_tls_context, validate_target


HANDSHAKE_TIMEOUT = 6
REVOCATION_TIMEOUT = 8
MAX_CRL_BYTES = 10 * 1024 * 1024
TLS_VERSIONS = (
    ("TLSv1", "TLSv1"),
    ("TLSv1.1", "TLSv1_1"),
    ("TLSv1.2", "TLSv1_2"),
    ("TLSv1.3", "TLSv1_3"),
)


class Handshake(NamedTuple):
    protocol: str | None
    cipher: str | None
    chain: list[x509.Certificate]  # Hoja primero, tal como la envía el servidor


class Revocation(NamedTuple):
    status: str   # good | revoked | unknown
    method: str   # OCSP | CRL | ""
    detail: str


def handshake(hostname: str, port: int, context: ssl.SSLContext | None = None) -> Handshake:
    """Conecta con `context` (por defecto, uno que verifica el certificado).

    Lanza ssl.SSLCertVerificationError si el certificado no es válido y
    ssl.SSLError si no se puede negociar TLS. Un corte de red puntual
    (conexión reiniciada o tiempo agotado) se reintenta una vez.
    """

    try:
        return _handshake_once(hostname, port, context)
    except ssl.SSLError:
        raise
    except (ConnectionError, TimeoutError):
        sleep(1)
        return _handshake_once(hostname, port, context)


def _handshake_once(hostname: str, port: int, context: ssl.SSLContext | None) -> Handshake:
    context = context or ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=HANDSHAKE_TIMEOUT) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls:
            chain = [_load_certificate(item) for item in (tls.get_unverified_chain() or [])]
            return Handshake(tls.version(), (tls.cipher() or (None,))[0], chain)


def _load_certificate(item) -> x509.Certificate:
    der = item if isinstance(item, bytes) else item.public_bytes(ssl.ENCODING_DER)
    return x509.load_der_x509_certificate(der)


def supported_tls_versions(hostname: str, port: int, negotiated: str | None = None) -> list[str]:
    """Devuelve las versiones de TLS que acepta el servidor.

    `negotiated` es la versión de una conexión normal: el servidor elige la
    más alta que admite, así que solo hace falta probar las inferiores. Se
    prueban una tras otra para no saturar al servidor con conexiones.
    """

    names = [name for name, _ in TLS_VERSIONS]
    highest = names.index(negotiated) if negotiated in names else len(names) - 1
    to_probe = TLS_VERSIONS[:highest] if negotiated in names else TLS_VERSIONS
    accepted = [name for name, attribute in to_probe if _accepts_version(hostname, port, name, attribute)]
    if negotiated in names:
        accepted.append(negotiated)
    return accepted


def _accepts_version(hostname: str, port: int, name: str, attribute: str) -> bool:
    """Solo cuenta si la conexión negocia exactamente esa versión."""

    try:
        result = handshake(hostname, port, legacy_tls_context(getattr(ssl.TLSVersion, attribute)))
    except (OSError, ValueError):
        return False
    return result.protocol == name


# --- Revocación -------------------------------------------------------------------

def check_revocation(chain: list[x509.Certificate]) -> Revocation:
    """Consulta OCSP si el certificado lo anuncia; si no, su lista CRL."""

    if not chain:
        return Revocation("unknown", "", "")
    leaf = chain[0]
    issuer = chain[1] if len(chain) > 1 else _download_issuer(leaf)

    ocsp_urls = _access_locations(leaf, AuthorityInformationAccessOID.OCSP)
    if ocsp_urls and issuer is not None:
        result = _check_ocsp(leaf, issuer, ocsp_urls[0])
        if result.status != "unknown":
            return result

    for url in _crl_urls(leaf):
        result = _check_crl(leaf, issuer, url)
        if result.status != "unknown":
            return result

    if not ocsp_urls and not _crl_urls(leaf):
        return Revocation("unknown", "", "El certificado no indica dónde consultar su revocación.")
    return Revocation("unknown", "", "No se pudo consultar el estado de revocación.")


def _access_locations(cert: x509.Certificate, method) -> list[str]:
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    except x509.ExtensionNotFound:
        return []
    return [item.access_location.value for item in aia if item.access_method == method]


def _crl_urls(cert: x509.Certificate) -> list[str]:
    try:
        points = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
    except x509.ExtensionNotFound:
        return []
    return [
        name.value
        for point in points
        for name in (point.full_name or [])
        if isinstance(name, x509.UniformResourceIdentifier)
    ]


def _download(url: str, **kwargs) -> bytes | None:
    """Descarga limitada en tamaño. Las URL vienen del certificado (no son de
    fiar), así que pasan la misma validación que el destino del análisis."""

    try:
        validate_target(url)
        method = "POST" if "data" in kwargs else "GET"
        headers = {"User-Agent": USER_AGENT, **kwargs.pop("headers", {})}
        with requests.request(
            method, url, headers=headers, timeout=REVOCATION_TIMEOUT,
            allow_redirects=False, stream=True, **kwargs,
        ) as response:
            if response.status_code != 200:
                return None
            content = b""
            for chunk in response.iter_content(chunk_size=65536):
                content += chunk
                if len(content) > MAX_CRL_BYTES:
                    return None
            return content
    except (ValueError, requests.RequestException):
        return None


def _download_issuer(leaf: x509.Certificate) -> x509.Certificate | None:
    for url in _access_locations(leaf, AuthorityInformationAccessOID.CA_ISSUERS):
        content = _download(url)
        if not content:
            continue
        try:
            return x509.load_der_x509_certificate(content)
        except ValueError:
            try:
                return x509.load_pem_x509_certificate(content)
            except ValueError:
                continue
    return None


def _check_ocsp(leaf: x509.Certificate, issuer: x509.Certificate, url: str) -> Revocation:
    request = ocsp.OCSPRequestBuilder().add_certificate(leaf, issuer, hashes.SHA1()).build()
    content = _download(
        url,
        data=request.public_bytes(serialization.Encoding.DER),
        headers={"Content-Type": "application/ocsp-request"},
    )
    if not content:
        return Revocation("unknown", "OCSP", "")
    try:
        response = ocsp.load_der_ocsp_response(content)
        if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            return Revocation("unknown", "OCSP", "")
        status = response.certificate_status
    except ValueError:
        return Revocation("unknown", "OCSP", "")

    if status == ocsp.OCSPCertStatus.REVOKED:
        date = response.revocation_time_utc
        return Revocation("revoked", "OCSP", date.date().isoformat() if date else "")
    if status == ocsp.OCSPCertStatus.GOOD:
        return Revocation("good", "OCSP", url)
    return Revocation("unknown", "OCSP", "")


@lru_cache(maxsize=32)
def _download_crl(url: str, hour: int) -> bytes | None:
    """Muchos certificados comparten CRL: se reutiliza durante la misma hora."""

    return _download(url)


def _check_crl(leaf: x509.Certificate, issuer: x509.Certificate | None, url: str) -> Revocation:
    content = _download_crl(url, int(time() // 3600))
    if not content:
        return Revocation("unknown", "CRL", "")
    try:
        crl = x509.load_der_x509_crl(content)
    except ValueError:
        try:
            crl = x509.load_pem_x509_crl(content)
        except ValueError:
            return Revocation("unknown", "CRL", "")

    # Una CRL que no está firmada por el emisor del certificado no sirve de prueba.
    if issuer is not None:
        try:
            if not crl.is_signature_valid(issuer.public_key()):
                return Revocation("unknown", "CRL", "")
        except (TypeError, ValueError):
            return Revocation("unknown", "CRL", "")

    entry = crl.get_revoked_certificate_by_serial_number(leaf.serial_number)
    if entry is not None:
        return Revocation("revoked", "CRL", entry.revocation_date_utc.date().isoformat())
    return Revocation("good", "CRL", url)
