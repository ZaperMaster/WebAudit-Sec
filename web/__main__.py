"""Arranca la versión web en http://127.0.0.1:8000. Ejecuta: python -m web"""

import uvicorn


if __name__ == "__main__":
    uvicorn.run("web.server:app", host="127.0.0.1", port=8000)
