from ctypes import windll
from pathlib import Path
from threading import Thread
from time import monotonic, sleep
import sys

import uvicorn
import webview

from app.main import app


def resource_path(relative_path: str) -> Path:
    bundle_dir = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return bundle_dir / relative_path


def show_startup_error(message: str) -> None:
    windll.user32.MessageBoxW(None, message, "WebAudit Sec", 0x10)


def main() -> None:
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=0,
            log_level="warning",
            access_log=False,
        )
    )
    server_thread = Thread(target=server.run, daemon=True)
    server_thread.start()

    deadline = monotonic() + 15
    while not server.started:
        if not server_thread.is_alive():
            raise RuntimeError("No se pudo iniciar el servidor local de WebAudit Sec.")
        if monotonic() >= deadline:
            server.should_exit = True
            raise TimeoutError("El servidor local de WebAudit Sec tardó demasiado.")
        sleep(0.05)

    try:
        port = server.servers[0].sockets[0].getsockname()[1]
        webview.create_window(
            "WebAudit Sec",
            f"http://127.0.0.1:{port}/",
            width=1180,
            height=820,
            min_size=(780, 600),
        )
        webview.start(
            gui="edgechromium",
            debug=False,
            icon=str(resource_path("app/static/webaudit-sec-window.ico")),
        )
        if not webview.windows or not webview.windows[0].events.shown.is_set():
            raise RuntimeError(
                "No se pudo abrir la ventana. Instala Microsoft Edge WebView2 Runtime."
            )
    except Exception as exc:
        show_startup_error(
            f"WebAudit Sec no pudo iniciar la ventana de escritorio.\n\n{exc}"
        )
    finally:
        server.should_exit = True
        server_thread.join(timeout=5)


if __name__ == "__main__":
    main()