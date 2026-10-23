"""Constantes y reglas de configuración del escáner."""

import re

import tldextract


USER_AGENT = "WebAudit-Sec/1.0"

# Límites del rastreo
MAX_CRAWL_PAGES = 150
MAX_CRAWL_SECONDS = 300
MAX_HTML_BYTES = 256 * 1024
MAX_LINKS_PER_PAGE = 300
MAX_URL_LENGTH = 2048

# Usa la lista de sufijos públicos incluida en el paquete (sin red).
PUBLIC_SUFFIX_EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=(),
    fallback_to_snapshot=True,
)

SEVERITIES = ("high", "medium", "low", "info")
SEVERITY_ORDER = {severity: index for index, severity in enumerate(SEVERITIES, start=1)}

# Cabecera -> (severidad si falta, recomendación)
SECURITY_HEADERS = {
    "content-security-policy": (
        "high",
        "Configura una Content-Security-Policy que limite scripts, estilos y orígenes.",
    ),
    "x-content-type-options": (
        "low",
        "Configura X-Content-Type-Options: nosniff.",
    ),
    "referrer-policy": (
        "low",
        "Define una política Referrer-Policy.",
    ),
    "permissions-policy": (
        "low",
        "Define una Permissions-Policy adecuada.",
    ),
    "x-frame-options": (
        "medium",
        "Configura X-Frame-Options o frame-ancestors en CSP.",
    ),
    "cross-origin-opener-policy": (
        "medium",
        "Configura Cross-Origin-Opener-Policy, por ejemplo same-origin.",
    ),
    "cross-origin-resource-policy": (
        "low",
        "Configura Cross-Origin-Resource-Policy según el uso del recurso.",
    ),
    "x-permitted-cross-domain-policies": (
        "low",
        "Configura X-Permitted-Cross-Domain-Policies: none si no usas Flash/PDF cross-domain.",
    ),
}

DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version")

# Versiones por debajo de las cuales el software ya no recibe parches de
# seguridad (revisado en octubre de 2026; actualízalo con el tiempo).
UNSUPPORTED_BELOW = {
    "apache": (2, 4),
    "nginx": (1, 20),
    "php": (8, 2),
    "microsoft-iis": (10, 0),
    "openssl": (3, 0),
}

# Archivos que no deberían ser públicos (comprobación opcional):
# (ruta, patrón que debe aparecer al principio del contenido, severidad, título)
EXPOSED_FILES = [
    ("/.git/HEAD", rb"^ref: refs/", "high", "Repositorio Git expuesto (/.git/)"),
    ("/.git/config", rb"^\[core\]", "high", "Repositorio Git expuesto (/.git/)"),
    ("/.env", rb"^[A-Z][A-Z0-9_]*=", "high", "Archivo de configuración .env expuesto"),
    ("/backup.sql", rb"CREATE TABLE|INSERT INTO", "high", "Copia de la base de datos accesible"),
    ("/backup.zip", rb"^PK\x03\x04", "high", "Copia de seguridad (.zip) accesible"),
    ("/wp-config.php.bak", rb"DB_PASSWORD", "high", "Copia de wp-config.php accesible"),
    ("/server-status", rb"Apache Server Status", "medium", "Página server-status de Apache accesible"),
    ("/phpinfo.php", rb"phpinfo\(\)|PHP Version", "medium", "Página phpinfo() accesible"),
    ("/.DS_Store", rb"^\x00\x00\x00\x01Bud1", "low", "Archivo .DS_Store expuesto"),
]

# Cookies
SESSION_COOKIE_NAME = re.compile(r"sess|sid|auth|token|jwt|login", re.IGNORECASE)
MAX_SESSION_COOKIE_DAYS = 30
COOKIE_PREFIX_RULES = {
    "__Secure-": "El prefijo __Secure- exige el atributo Secure.",
    "__Host-": "El prefijo __Host- exige Secure, Path=/ y que no haya Domain.",
}
RISKY_HTTP_METHODS = ("TRACE", "TRACK", "DEBUG")
OBSOLETE_TLS_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv3"}
TLS_EXPIRY_WARNING_DAYS = 21
HSTS_MIN_MAX_AGE = 15552000  # 180 días

VALID_REFERRER_POLICIES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
}

OWASP_TOP10_CATEGORIES = {
    "configuration": "A02:2025 - Security Misconfiguration",
    "cryptography": "A04:2025 - Cryptographic Failures",
    "session": "A07:2025 - Authentication Failures",
    "integrity": "A08:2025 - Software or Data Integrity Failures",
}

OWASP_CHEAT_SHEETS = {
    "headers": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
    "csp": "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
    "tls": "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    "session": "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
    "disclosure": "https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html",
    "third_party_js": "https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html",
}
