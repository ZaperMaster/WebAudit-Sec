"""Ventana de escritorio (Windows) de WebAudit Sec.

Arranca la API local en un hilo y la muestra en una ventana WebView2 con:
- el icono de la app (logo-dentro) en la ventana y en la barra de tareas;
- la barra de título del mismo color que el fondo de la app.
"""

import ctypes
import sys
from ctypes import wintypes
from pathlib import Path
from threading import Thread
from time import monotonic, sleep

import uvicorn
import webview

from app.main import app


APP_NAME = "WebAudit Sec"
APP_USER_MODEL_ID = "WebAuditSec.Desktop"
BACKGROUND_COLOR = "#090d18"  # Igual que --bg en static/css/styles.css
TITLE_TEXT_COLOR = "#edf4ff"
WINDOW_SIZE = (1180, 820)
MIN_WINDOW_SIZE = (780, 600)
SERVER_START_TIMEOUT = 15


def resource_path(relative_path: str) -> Path:
    """Ruta a un recurso, tanto en desarrollo como dentro del .exe de PyInstaller."""

    base_dir = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return base_dir / relative_path


ICON_PATH = resource_path("app/static/icons/app.ico")


# --- Integración con Windows -------------------------------------------------

def _colorref(hex_color: str) -> int:
    """'#RRGGBB' -> COLORREF (0x00BBGGRR) que espera la API de Windows."""

    red, green, blue = (int(hex_color[i:i + 2], 16) for i in (1, 3, 5))
    return red | (green << 8) | (blue << 16)


def set_app_user_model_id() -> None:
    """Hace que la barra de tareas use el icono de la app y no el de python.exe."""

    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_USER_MODEL_ID)
    except (AttributeError, OSError):
        pass


def style_title_bar(hwnd: int) -> None:
    """Barra de título oscura y del color del fondo de la app.

    El color exacto solo lo admite Windows 11; en Windows 10 queda en modo oscuro.
    """

    dwm_set_attribute = ctypes.windll.dwmapi.DwmSetWindowAttribute
    dwm_set_attribute.argtypes = [wintypes.HWND, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]

    def set_attribute(attribute: int, value: int) -> None:
        data = ctypes.c_int(value)
        dwm_set_attribute(hwnd, attribute, ctypes.byref(data), ctypes.sizeof(data))

    DWMWA_USE_IMMERSIVE_DARK_MODE_OLD = 19  # Windows 10 anteriores a 20H1
    DWMWA_USE_IMMERSIVE_DARK_MODE = 20
    DWMWA_BORDER_COLOR = 34
    DWMWA_CAPTION_COLOR = 35
    DWMWA_TEXT_COLOR = 36

    set_attribute(DWMWA_USE_IMMERSIVE_DARK_MODE_OLD, 1)
    set_attribute(DWMWA_USE_IMMERSIVE_DARK_MODE, 1)
    set_attribute(DWMWA_CAPTION_COLOR, _colorref(BACKGROUND_COLOR))
    set_attribute(DWMWA_BORDER_COLOR, _colorref(BACKGROUND_COLOR))
    set_attribute(DWMWA_TEXT_COLOR, _colorref(TITLE_TEXT_COLOR))


def set_window_icon(hwnd: int, icon_path: Path) -> None:
    """Asigna el .ico a la ventana (icono pequeño y grande de la barra de tareas)."""

    if not icon_path.exists():
        return

    user32 = ctypes.windll.user32
    user32.LoadImageW.restype = wintypes.HANDLE
    user32.LoadImageW.argtypes = [
        wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT,
        ctypes.c_int, ctypes.c_int, wintypes.UINT,
    ]
    user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]

    IMAGE_ICON, LR_LOADFROMFILE = 1, 0x10
    WM_SETICON, ICON_SMALL, ICON_BIG = 0x80, 0, 1
    SM_CXICON, SM_CXSMICON = 11, 49

    for icon_type, metric in ((ICON_BIG, SM_CXICON), (ICON_SMALL, SM_CXSMICON)):
        size = user32.GetSystemMetrics(metric)
        handle = user32.LoadImageW(None, str(icon_path), IMAGE_ICON, size, size, LR_LOADFROMFILE)
        if handle:
            user32.SendMessageW(hwnd, WM_SETICON, icon_type, handle)


def find_window_handle(window) -> int | None:
    try:
        return int(window.native.Handle.ToInt64())
    except Exception:  # p. ej. si .NET no permite leer Handle desde este hilo
        return ctypes.windll.user32.FindWindowW(None, APP_NAME) or None


def on_window_shown(window) -> None:
    hwnd = find_window_handle(window)
    if not hwnd:
        return
    for customize in (style_title_bar, lambda h: set_window_icon(h, ICON_PATH)):
        try:
            customize(hwnd)
        except Exception:
            pass  # Detalle estético: nunca debe impedir abrir la app


def show_error(message: str) -> None:
    ctypes.windll.user32.MessageBoxW(None, message, APP_NAME, 0x10)


# --- Servidor local -----------------------------------------------------------

def start_server() -> tuple[uvicorn.Server, Thread]:
    """Inicia la API en 127.0.0.1 con un puerto libre y espera a que esté lista."""

    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning", access_log=False)
    )
    thread = Thread(target=server.run, daemon=True)
    thread.start()

    deadline = monotonic() + SERVER_START_TIMEOUT
    while not server.started:
        if not thread.is_alive():
            raise RuntimeError(f"No se pudo iniciar el servidor local de {APP_NAME}.")
        if monotonic() >= deadline:
            server.should_exit = True
            raise TimeoutError(f"El servidor local de {APP_NAME} tardó demasiado.")
        sleep(0.05)
    return server, thread


def server_port(server: uvicorn.Server) -> int:
    return server.servers[0].sockets[0].getsockname()[1]


# --- Punto de entrada -----------------------------------------------------------

def main() -> None:
    set_app_user_model_id()
    server, thread = start_server()

    try:
        window = webview.create_window(
            APP_NAME,
            f"http://127.0.0.1:{server_port(server)}/",
            width=WINDOW_SIZE[0],
            height=WINDOW_SIZE[1],
            min_size=MIN_WINDOW_SIZE,
            background_color=BACKGROUND_COLOR,
        )
        window.events.shown += lambda: on_window_shown(window)
        webview.start(gui="edgechromium", debug=False, icon=str(ICON_PATH))

        if not window.events.shown.is_set():
            raise RuntimeError("No se pudo abrir la ventana. Instala Microsoft Edge WebView2 Runtime.")
    except Exception as exc:
        show_error(f"{APP_NAME} no pudo iniciar la ventana de escritorio.\n\n{exc}")
    finally:
        server.should_exit = True
        thread.join(timeout=5)
