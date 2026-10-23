# WebAudit Sec — app de escritorio (Windows)

La misma interfaz que la [versión web](../web/), dentro de una ventana propia de
Windows (WebView2) con barra de título integrada. Arranca su servidor solo en
`127.0.0.1` y en un puerto libre, así que no queda accesible desde otros equipos.

## Descargar

El `.exe` compilado está en la sección **Releases** del repositorio. Necesita Windows 10
u 11 con Microsoft Edge WebView2 Runtime (viene incluido en Windows 11).

## Ejecutar desde el código

Desde la raíz del proyecto:

```
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -r desktop\requirements.txt
.venv\Scripts\python.exe -m desktop
```

## Crear el .exe

Ejecuta `desktop\build_windows.bat`. Crea el entorno si no existe, instala las
dependencias y genera `dist\WebAudit-Sec.exe`.

## Particularidades

- Los informes (PDF, HTML, JSON y CSV) se guardan con el diálogo de Windows. El PDF lo
  genera WebView2 directamente, sin pasar por la impresora.
- El historial se guarda en `%LOCALAPPDATA%\WebAuditSec\history` (los 50 análisis más
  recientes). Para vaciarlo basta con borrar esa carpeta.
- Windows SmartScreen puede avisar de «editor desconocido» al abrir el `.exe`, porque no
  está firmado. Para evitarlo hace falta un certificado de firma de código.

## Icono

`assets/logo-dentro.png` es el original del icono. Si lo cambias, regenera
`assets/app.ico` con:

```
.venv\Scripts\python.exe -m pip install pillow
.venv\Scripts\python.exe desktop\make_icon.py
```
