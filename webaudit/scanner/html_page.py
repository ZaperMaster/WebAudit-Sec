"""Lectura del HTML de una página: enlaces, recursos que carga y formularios.

Se lee una sola vez por página y lo usan el rastreo (enlaces) y las
comprobaciones de contenido mixto y SRI.
"""

from html.parser import HTMLParser
from typing import NamedTuple

from . import config


class Resource(NamedTuple):
    tag: str          # script, link, img, iframe...
    url: str          # Tal como aparece en el HTML
    active: bool      # Puede ejecutar código o cambiar la página (script, CSS, iframe...)
    integrity: bool   # Tiene atributo integrity (SRI)


class ParsedPage(NamedTuple):
    anchors: list[str]
    resources: list[Resource]
    form_actions: list[str]
    truncated: bool  # Se alcanzó el límite de bytes o de enlaces

    @property
    def declares_icon(self) -> bool:
        """Si tiene <link rel=icon>; si no, el navegador pide /favicon.ico."""
        return any(resource.tag == "link" and not resource.active for resource in self.resources)


# etiqueta -> (atributo con la URL, ¿contenido activo?)
RESOURCE_ATTRIBUTES = {
    "script": ("src", True),
    "iframe": ("src", True),
    "frame": ("src", True),
    "object": ("data", True),
    "embed": ("src", True),
    "img": ("src", False),
    "audio": ("src", False),
    "video": ("src", False),
    "source": ("src", False),
    "track": ("src", False),
}
STYLESHEET_RELS = {"stylesheet"}
ICON_RELS = {"icon", "apple-touch-icon"}


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.anchors: list[str] = []
        self.resources: list[Resource] = []
        self.form_actions: list[str] = []
        self.truncated = False

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        values = {name.lower(): value for name, value in attrs if value is not None}

        if tag == "a" and values.get("href"):
            if len(self.anchors) >= config.MAX_LINKS_PER_PAGE:
                self.truncated = True
            else:
                self.anchors.append(values["href"])
        elif tag == "link" and values.get("href"):
            rels = set(values.get("rel", "").lower().split())
            if rels & STYLESHEET_RELS:
                self._add_resource(tag, values["href"], True, values)
            elif rels & ICON_RELS:
                self._add_resource(tag, values["href"], False, values)
        elif tag == "form" and values.get("action"):
            self.form_actions.append(values["action"])
        elif tag in RESOURCE_ATTRIBUTES:
            attribute, active = RESOURCE_ATTRIBUTES[tag]
            if values.get(attribute):
                self._add_resource(tag, values[attribute], active, values)

    def _add_resource(self, tag, url, active, values):
        if len(self.resources) < config.MAX_LINKS_PER_PAGE:
            self.resources.append(Resource(tag, url.strip(), active, bool(values.get("integrity"))))


def read_page(response) -> ParsedPage | None:
    """Analiza el HTML de una respuesta 200 text/html (hasta MAX_HTML_BYTES)."""

    if response.status_code != 200:
        return None
    if "text/html" not in response.headers.get("Content-Type", "").lower():
        return None

    parser = PageParser()
    encoding = response.encoding or "utf-8"
    read_bytes = 0
    for chunk in response.iter_content(chunk_size=8192):
        chunk = chunk[: config.MAX_HTML_BYTES - read_bytes]
        parser.feed(chunk.decode(encoding, errors="replace"))
        read_bytes += len(chunk)
        if read_bytes >= config.MAX_HTML_BYTES:
            break

    return ParsedPage(
        parser.anchors,
        parser.resources,
        parser.form_actions,
        parser.truncated or read_bytes >= config.MAX_HTML_BYTES,
    )
