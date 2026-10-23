"""Escáner de seguridad web de WebAudit Sec.

Estructura:
    config.py       constantes, límites y reglas
    network.py      validación de destinos, peticiones HTTP y TLS
    results.py      formato de checks, findings y resultado final
    links.py        extracción de enlaces para el rastreo
    analyzers.py    análisis de valores (CSP, HSTS, cookies...)
    page_checks.py  comprobaciones de cada página
    site_checks.py  comprobaciones de sitio (TLS, redirección, métodos, security.txt)
    crawler.py      scan_security_headers (una página) y scan_website (rastreo)
"""

from .crawler import scan_security_headers, scan_website

__all__ = ["scan_security_headers", "scan_website"]
