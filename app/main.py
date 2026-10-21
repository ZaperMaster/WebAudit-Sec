
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl
import requests

from app.scanner import scan_security_headers, scan_website

app = FastAPI(
    title="WebAudit Sec",
    description="Auditor de seguridad web",
    version="0.3.0",
)

STATIC_DIR = Path(__file__).parent / "static"
BRAND_DIR = Path(__file__).parent.parent / "logo"
INDEX_FILE = STATIC_DIR / "index.html"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.mount("/brand", StaticFiles(directory=BRAND_DIR), name="brand")


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
