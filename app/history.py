"""Historial de análisis guardado en disco (un JSON por análisis).

Se guarda en %LOCALAPPDATA%\\WebAuditSec\\history (o en la carpeta del usuario
fuera de Windows) y se conservan los MAX_ENTRIES más recientes.
"""

import json
import os
import re
from datetime import datetime
from pathlib import Path
from uuid import uuid4


MAX_ENTRIES = 50
ENTRY_ID = re.compile(r"^[0-9]{8}-[0-9]{12}-[0-9a-f]{6}$")
SUMMARY_FIELDS = ("target", "crawl", "state", "finished_at", "pages_scanned", "findings_count", "summary")


def history_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home())
    return Path(base) / "WebAuditSec" / "history"


def save(target: str, crawl: bool, state: str, result: dict) -> dict:
    """Guarda un análisis terminado y devuelve su resumen (con `id`)."""

    now = datetime.now().astimezone()
    entry = {
        # Fecha con microsegundos al principio: ordenar por id es ordenar por fecha.
        "id": f"{now:%Y%m%d-%H%M%S%f}-{uuid4().hex[:6]}",
        "target": target,
        "crawl": crawl,
        "state": state,
        "finished_at": now.isoformat(timespec="seconds"),
        "pages_scanned": result.get("pages_scanned", 1),
        "findings_count": result.get("findings_count", 0),
        "summary": result.get("summary", {}),
        "result": result,
    }
    folder = history_dir()
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{entry['id']}.json").write_text(json.dumps(entry, ensure_ascii=False), encoding="utf-8")
    _prune(folder)
    return _summary(entry)


def list_entries() -> list[dict]:
    """Resúmenes del historial, del más reciente al más antiguo."""

    entries = []
    for path in _entry_files(history_dir()):
        try:
            entries.append(_summary(json.loads(path.read_text(encoding="utf-8"))))
        except (OSError, ValueError, KeyError):
            continue  # Un archivo dañado no debe romper el historial
    return entries


def load(entry_id: str) -> dict | None:
    path = _entry_path(entry_id)
    if path is None or not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def delete(entry_id: str) -> bool:
    path = _entry_path(entry_id)
    if path is None or not path.exists():
        return False
    path.unlink()
    return True


def _entry_path(entry_id: str) -> Path | None:
    """Ruta del análisis, o None si el id no tiene el formato esperado
    (así un id malicioso no puede salir de la carpeta del historial)."""

    if not ENTRY_ID.match(entry_id):
        return None
    return history_dir() / f"{entry_id}.json"


def _entry_files(folder: Path) -> list[Path]:
    if not folder.exists():
        return []
    files = [path for path in folder.glob("*.json") if ENTRY_ID.match(path.stem)]
    return sorted(files, key=lambda path: path.stem, reverse=True)


def _prune(folder: Path) -> None:
    for path in _entry_files(folder)[MAX_ENTRIES:]:
        path.unlink(missing_ok=True)


def _summary(entry: dict) -> dict:
    return {"id": entry["id"], **{field: entry.get(field) for field in SUMMARY_FIELDS}}
