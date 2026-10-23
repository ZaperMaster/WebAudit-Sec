"""Validación de destinos y acceso a red (HTTP y TLS)."""

import ipaddress
import socket
import ssl
import warnings
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from urllib3.exceptions import InsecureRequestWarning

from .config import PUBLIC_SUFFIX_EXTRACTOR, USER_AGENT


def default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def validate_target(url: str) -> str:
    """Permite únicamente destinos HTTP(S) que resuelvan a IP públicas."""

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
    if hostname == "localhost" or hostname.endswith((".localhost", ".local")):
        raise ValueError("No se permiten destinos locales.")

    addresses = _resolve_addresses(hostname, parsed.port or default_port(parsed.scheme))
    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError("El destino debe resolver únicamente a IP públicas.")

    return url


def _resolve_addresses(hostname: str, port: int) -> set:
    try:
        return {ipaddress.ip_address(hostname.strip("[]"))}
    except ValueError:
        pass

    try:
        return {
            ipaddress.ip_address(item[4][0])
            for item in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        }
    except socket.gaierror as exc:
        raise ValueError("No se pudo resolver el dominio.") from exc


def registrable_domain(hostname: str) -> str:
    """Devuelve el dominio registrable (ej. shop.example.co.uk -> example.co.uk)."""

    hostname = hostname.lower().rstrip(".")
    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        extracted = PUBLIC_SUFFIX_EXTRACTOR(hostname)
        return extracted.top_domain_under_public_suffix or hostname


def fetch(url: str, method: str = "GET", timeout: int = 8):
    """Petición sin seguir redirecciones.

    Si el certificado HTTPS no es de confianza, se reintenta sin verificarlo
    para poder auditar igualmente las cabeceras (el problema TLS se reporta aparte).
    """

    options = {
        "timeout": timeout,
        "allow_redirects": False,
        "headers": {"User-Agent": USER_AGENT},
        "stream": True,
    }
    try:
        return requests.request(method, url, verify=True, **options)
    except requests.exceptions.SSLError:
        if urlparse(url).scheme != "https":
            raise
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", InsecureRequestWarning)
            return requests.request(method, url, verify=False, **options)


def header_map(response) -> dict[str, str]:
    return {key.lower(): value for key, value in response.headers.items()}


def set_cookie_headers(response) -> list[str]:
    """Devuelve cada Set-Cookie por separado (requests los fusiona en uno)."""

    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    getlist = getattr(raw_headers, "getlist", None)
    if getlist:
        return getlist("Set-Cookie")

    cookie = response.headers.get("Set-Cookie")
    return [cookie] if cookie else []


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
        expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        days_left = (expires_at - datetime.now(timezone.utc)).days

    return {
        "protocol": protocol,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "days_left": days_left,
    }
