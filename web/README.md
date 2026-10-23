# WebAudit Sec — versión web

Servidor FastAPI que sirve la interfaz y la API de análisis. Se usa desde cualquier
navegador.

## Arrancar

Desde la raíz del proyecto:

```
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m web
```

Abre http://127.0.0.1:8000. Para escuchar en otra dirección o puerto, usa uvicorn
directamente, por ejemplo:

```
.venv\Scripts\python.exe -m uvicorn web.server:app --host 0.0.0.0 --port 8080
```

## Diferencias con la app de escritorio

- Exportar **HTML, JSON y CSV** descarga el archivo; **PDF** abre el diálogo de imprimir
  del navegador (elige «Guardar como PDF»).
- No hay botones de ventana: los pone el navegador.
- El **historial** se guarda en el equipo donde corre el servidor, en
  `%LOCALAPPDATA%\WebAuditSec\history` (o en la carpeta del usuario fuera de Windows).
  Si varias personas usan el mismo servidor, todas ven el mismo historial.

> Si publicas el servidor en internet, cualquiera podrá lanzar análisis desde él contra
> sitios públicos. El motor bloquea direcciones privadas y locales, pero conviene
> protegerlo con autenticación.

## API

| Método | Ruta | Para qué |
|---|---|---|
| `POST` | `/scan/jobs` | Empieza un análisis: `{"target", "crawl", "deep", "max_pages", "max_minutes"}` |
| `GET` | `/scan/jobs/{id}` | Progreso y, al terminar, el resultado |
| `DELETE` | `/scan/jobs/{id}` | Cancela (devuelve lo analizado hasta entonces) |
| `POST` | `/scan/website` | Análisis completo en una sola petición |
| `GET` | `/history` | Lista del historial |
| `GET` | `/history/{id}` | Un análisis guardado |
| `GET` | `/history/{id}/previous` | El análisis anterior del mismo sitio |
| `DELETE` | `/history/{id}` | Borra un análisis del historial |

La documentación interactiva está en http://127.0.0.1:8000/docs.
