"""API local de WebAudit Sec (FastAPI)."""

from pathlib import Path

import requests
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl

from app.scanner import scan_security_headers, scan_website


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
    return run_scan(scan_website, str(request.target), crawl=request.crawl)
