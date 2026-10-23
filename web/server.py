"""API local de WebAudit Sec (FastAPI)."""

from pathlib import Path

import requests
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, HttpUrl

from webaudit import history, jobs
from webaudit.scanner import scan_security_headers, scan_website


STATIC_DIR = Path(__file__).parent / "static"
INDEX_FILE = STATIC_DIR / "index.html"

app = FastAPI(
    title="WebAudit Sec",
    description="Auditor de seguridad web",
    version="0.3.0",
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class ScanRequest(BaseModel):
    target: HttpUrl
    crawl: bool = False
    max_pages: int | None = Field(None, ge=1, le=500)
    max_minutes: int | None = Field(None, ge=1, le=15)

    def scan_options(self) -> dict:
        return {
            "max_pages": self.max_pages,
            "max_seconds": self.max_minutes * 60 if self.max_minutes else None,
        }


def run_scan(scan, *args, **kwargs) -> dict:
    """Ejecuta un análisis traduciendo los errores a respuestas HTTP."""

    try:
        return scan(*args, **kwargs)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail="No se pudo conectar con el sitio web.",
        ) from exc


@app.get("/")
def home():
    return FileResponse(INDEX_FILE)


@app.post("/scan/headers")
def scan_headers_endpoint(request: ScanRequest):
    return run_scan(scan_security_headers, str(request.target))


@app.post("/scan/website")
def scan_website_endpoint(request: ScanRequest):
    return run_scan(scan_website, str(request.target), crawl=request.crawl, **request.scan_options())


# --- Análisis en segundo plano (progreso en vivo y cancelación) ---------------

@app.post("/scan/jobs")
def start_scan_job(request: ScanRequest):
    return {"id": jobs.start_job(str(request.target), request.crawl, request.scan_options()).id}


@app.get("/scan/jobs/{job_id}")
def scan_job_status(job_id: str):
    return _existing_job(job_id).snapshot()


@app.delete("/scan/jobs/{job_id}")
def cancel_scan_job(job_id: str):
    job = _existing_job(job_id)
    job.cancel()
    return job.snapshot()


# --- Historial -------------------------------------------------------------------

@app.get("/history")
def list_history():
    return history.list_entries()


@app.get("/history/{entry_id}")
def get_history_entry(entry_id: str):
    entry = history.load(entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="El análisis no existe.")
    return entry


@app.get("/history/{entry_id}/previous")
def get_previous_history_entry(entry_id: str):
    """El análisis anterior del mismo sitio y alcance, para comparar."""

    entry = history.previous(entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="No hay un análisis anterior de este sitio.")
    return entry


@app.delete("/history/{entry_id}")
def delete_history_entry(entry_id: str):
    if not history.delete(entry_id):
        raise HTTPException(status_code=404, detail="El análisis no existe.")
    return {"deleted": entry_id}


def _existing_job(job_id: str) -> jobs.ScanJob:
    job = jobs.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="El análisis no existe.")
    return job
