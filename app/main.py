
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, HttpUrl
import requests

from app.scanner import scan_security_headers, scan_website

app = FastAPI(
    title="VulnLab",
    description="Auditor de seguridad web",
    version="0.3.0",
)

INDEX_FILE = Path(__file__).parent / "static" / "index.html"


class ScanRequest(BaseModel):
    target: HttpUrl
    crawl: bool = False


@app.get("/")
def home():
    return FileResponse(INDEX_FILE)


@app.post("/scan/headers")
def scan_headers(request: ScanRequest):
    try:
        return scan_security_headers(str(request.target))
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail="No se pudo conectar con el sitio web.",
        ) from exc


@app.post("/scan/website")
def scan_website_endpoint(request: ScanRequest):
    try:
        return scan_website(
            str(request.target),
            crawl=request.crawl,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail="No se pudo conectar con el sitio web.",
        ) from exc
