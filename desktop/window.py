"""Ventana de escritorio (Windows) de WebAudit Sec.

Arranca la API local en un hilo y la muestra en una ventana WebView2 sin marco:
la barra de título la dibuja la propia interfaz (static/index.html) y llama a
DesktopApi para mover, redimensionar, minimizar, maximizar y cerrar, y para
guardar los informes exportados (HTML y PDF).
El icono de la app (logo-dentro) se usa en la barra de tareas.
"""

import ctypes
import sys
from ctypes import wintypes
from pathlib import Path
from threading import Thread
from time import monotonic, sleep

import uvicorn
import webview

from web.server import app


APP_NAME = "WebAudit Sec"
APP_USER_MODEL_ID = "WebAuditSec.Desktop"
BACKGROUND_COLOR = "#090d18"  # Igual que --bg en static/css/styles.css
BORDER_COLOR = "#26344b"  # Igual que --border
WINDOW_SIZE = (1180, 820)
MIN_WINDOW_SIZE = (780, 600)
SERVER_START_TIMEOUT = 15
PDF_TIMEOUT = 60


def resource_path(relative_path: str) -> Path:
    """Ruta a un recurso, tanto en desarrollo como dentro del .exe de PyInstaller."""

    base_dir = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return base_dir / relative_path


ICON_PATH = resource_path("desktop/assets/app.ico")


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


def style_frame(hwnd: int) -> None:
    """Esquinas redondeadas y borde fino (Windows 11) en la ventana sin marco.

    También permite minimizarla desde la barra de tareas, que en una ventana
    sin marco solo funciona si tiene el estilo WS_MINIMIZEBOX.
    """

    dwm_set_attribute = ctypes.windll.dwmapi.DwmSetWindowAttribute
    dwm_set_attribute.argtypes = [wintypes.HWND, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]

    def set_attribute(attribute: int, value: int) -> None:
        data = ctypes.c_int(value)
        dwm_set_attribute(hwnd, attribute, ctypes.byref(data), ctypes.sizeof(data))

    DWMWA_USE_IMMERSIVE_DARK_MODE = 20
    DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND = 33, 2
    DWMWA_BORDER_COLOR = 34

    set_attribute(DWMWA_USE_IMMERSIVE_DARK_MODE, 1)
    set_attribute(DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND)
    set_attribute(DWMWA_BORDER_COLOR, _colorref(BORDER_COLOR))

    GWL_STYLE, WS_MINIMIZEBOX, WS_SYSMENU = -16, 0x00020000, 0x00080000
    user32 = ctypes.windll.user32
    style = user32.GetWindowLongW(hwnd, GWL_STYLE)
    user32.SetWindowLongW(hwnd, GWL_STYLE, style | WS_MINIMIZEBOX | WS_SYSMENU)


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
    for customize in (style_frame, lambda h: set_window_icon(h, ICON_PATH)):
        try:
            customize(hwnd)
        except Exception:
            pass  # Detalle estético: nunca debe impedir abrir la app


class DesktopApi:
    """API que la interfaz llama vía window.pywebview.api: controles de la
    ventana (barra de título propia) y guardado de informes exportados.

    Mover y redimensionar siguen al cursor mientras el botón esté pulsado.
    Lo que toca la ventana se ejecuta en su hilo.
    """

    VK_LBUTTON = 0x01
    RESIZE_EDGES = {
        "left", "right", "top", "bottom",
        "top-left", "top-right", "bottom-left", "bottom-right",
    }

    def __init__(self):
        self._window = None
        self._restore_bounds = None  # Tamaño antes de maximizar

    def attach(self, window) -> None:
        self._window = window

    def _on_ui_thread(self, func) -> None:
        from System import Action  # pythonnet, ya cargado por pywebview

        self._window.native.Invoke(Action(func))

    def is_maximized(self) -> bool:
        return self._restore_bounds is not None

    def minimize(self) -> None:
        self._window.minimize()

    def toggle_maximize(self) -> bool:
        """Maximiza al área de trabajo (sin tapar la barra de tareas) o restaura."""

        def toggle():
            from System.Windows.Forms import Screen

            form = self._window.native
            if self._restore_bounds is None:
                self._restore_bounds = form.Bounds
                form.Bounds = Screen.FromHandle(form.Handle).WorkingArea
            else:
                form.Bounds, self._restore_bounds = self._restore_bounds, None

        self._on_ui_thread(toggle)
        return self.is_maximized()

    def close(self) -> None:
        self._window.destroy()

    # --- Exportar informes ---

    def _ask_save_path(self, filename: str, file_type: str) -> str | None:
        selection = self._window.create_file_dialog(
            webview.FileDialog.SAVE, save_filename=filename, file_types=(file_type,),
        )
        if not selection:
            return None
        return selection if isinstance(selection, str) else selection[0]

    def save_text(self, filename: str, content: str, file_type: str) -> str | None:
        """Pide dónde guardar y escribe un informe de texto (HTML, JSON o CSV).

        `file_type` es el filtro del diálogo, p. ej. "HTML (*.html)".
        Devuelve la ruta o None si se cancela.
        """

        path = self._ask_save_path(filename, file_type)
        if path:
            Path(path).write_text(content, encoding="utf-8-sig" if path.lower().endswith(".csv") else "utf-8")
        return path

    def save_pdf(self, filename: str) -> str | None:
        """Pide dónde guardar e imprime a PDF la página con los estilos de
        impresión (que solo muestran el informe preparado por la interfaz)."""

        path = self._ask_save_path(filename, "PDF (*.pdf)")
        if not path:
            return None

        tasks = []

        def start_printing():
            # WebView2 solo se puede usar desde el hilo de la ventana.
            core = self._window.native.browser.webview.CoreWebView2
            settings = core.Environment.CreatePrintSettings()
            settings.ShouldPrintBackgrounds = True        # Colores de las etiquetas
            settings.ShouldPrintHeaderAndFooter = False   # Sin URL ni fecha del navegador
            tasks.append(core.PrintToPdfAsync(path, settings))

        self._on_ui_thread(start_printing)

        # La tarea termina en el hilo de la ventana: aquí solo se espera.
        deadline = monotonic() + PDF_TIMEOUT
        while not tasks[0].IsCompleted:
            if monotonic() > deadline:
                raise TimeoutError("No se pudo generar el PDF a tiempo.")
            sleep(0.1)
        if tasks[0].IsFaulted or not tasks[0].Result:
            raise RuntimeError("No se pudo generar el PDF.")
        return path

    def start_drag(self, edge: str = "move") -> bool:
        """Empieza a mover (o a redimensionar por `edge`) con el ratón pulsado.

        Devuelve si la ventana sigue maximizada.
        """

        if edge == "move":
            if self._restore_bounds is not None:
                self._on_ui_thread(self._restore_under_cursor)
            self._follow_cursor(edge)
        elif edge in self.RESIZE_EDGES and self._restore_bounds is None:
            self._follow_cursor(edge)
        return self.is_maximized()

    def _restore_under_cursor(self) -> None:
        """Como en Windows: al arrastrar una ventana maximizada, se restaura
        bajo el cursor manteniendo la proporción horizontal."""

        from System.Windows.Forms import Cursor

        form = self._window.native
        bounds, self._restore_bounds = self._restore_bounds, None
        cursor = Cursor.Position
        ratio = (cursor.X - form.Left) / max(form.Width, 1)
        form.SetBounds(
            int(cursor.X - bounds.Width * ratio), form.Top,
            bounds.Width, bounds.Height,
        )

    def _follow_cursor(self, edge: str) -> None:
        """Mueve o redimensiona mientras el botón izquierdo siga pulsado.

        Se hace siguiendo el cursor (y no con el arrastre nativo de Windows)
        para que WebView2 conserve el ratón y reciba el clic al soltar.
        """

        from System.Windows.Forms import Cursor

        user32 = ctypes.windll.user32
        form = self._window.native
        start = Cursor.Position
        left, top, width, height = form.Left, form.Top, form.Width, form.Height
        min_width, min_height = form.MinimumSize.Width, form.MinimumSize.Height

        def new_bounds():
            cursor = Cursor.Position
            dx, dy = cursor.X - start.X, cursor.Y - start.Y
            if edge == "move":
                return left + dx, top + dy, width, height
            x, y, w, h = left, top, width, height
            if "right" in edge:
                w = max(min_width, width + dx)
            if "bottom" in edge:
                h = max(min_height, height + dy)
            if "left" in edge:
                w = max(min_width, width - dx)
                x = left + width - w
            if "top" in edge:
                h = max(min_height, height - dy)
                y = top + height - h
            return x, y, w, h

        while user32.GetAsyncKeyState(self.VK_LBUTTON) & 0x8000:
            bounds = new_bounds()
            self._on_ui_thread(lambda: form.SetBounds(*bounds))
            sleep(0.016)


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
        controls = DesktopApi()
        window = webview.create_window(
            APP_NAME,
            f"http://127.0.0.1:{server_port(server)}/",
            js_api=controls,
            width=WINDOW_SIZE[0],
            height=WINDOW_SIZE[1],
            min_size=MIN_WINDOW_SIZE,
            background_color=BACKGROUND_COLOR,
            frameless=True,
            easy_drag=False,
            shadow=True,
        )
        controls.attach(window)
        window.events.shown += lambda: on_window_shown(window)
        webview.start(gui="edgechromium", debug=False, icon=str(ICON_PATH))

        if not window.events.shown.is_set():
            raise RuntimeError("No se pudo abrir la ventana. Instala Microsoft Edge WebView2 Runtime.")
    except Exception as exc:
        show_error(f"{APP_NAME} no pudo iniciar la ventana de escritorio.\n\n{exc}")
    finally:
        server.should_exit = True
        thread.join(timeout=5)
