# WebAudit Sec

Auditor de seguridad web de escritorio para Windows. Abre una ventana propia y solo
inicia su servidor local en `127.0.0.1`.

## Estructura

```
desktop.py               Lanzador (python desktop.py)
build_windows.bat        Crea dist\WebAudit-Sec.exe
app/
  main.py                API local (FastAPI)
  desktop.py             Ventana, icono y barra de título
  scanner/               Motor de análisis
    config.py            Constantes, límites y reglas
    network.py           Validación de destinos, HTTP y TLS
    results.py           Formato de checks, hallazgos y resultado
    links.py             Enlaces del mismo sitio para el rastreo
    analyzers.py         Análisis de valores (CSP, HSTS, cookies...)
    page_checks.py       Comprobaciones de cada página
    site_checks.py       Comprobaciones de sitio (TLS, redirección, métodos, security.txt)
    crawler.py           scan_security_headers y scan_website
  static/
    index.html           Interfaz
    css/styles.css
    js/i18n.js           Textos ES / EN
    js/app.js            Lógica de la interfaz
    brand/               logo-fuera.png (cabecera) y logo-dentro.png
    icons/app.ico        Icono del .exe y de la barra de tareas (de logo-dentro)
tools/make_icon.py       Regenera app.ico a partir de logo-dentro.png
tests/
```

## Ejecutar en desarrollo

```
.venv\Scripts\python.exe desktop.py
.venv\Scripts\python.exe -m pytest
```

## Crear el ejecutable

En Windows 10 u 11, instala Python 3.10 o superior y Microsoft Edge WebView2 Runtime.
Después, ejecuta `build_windows.bat`. El ejecutable se genera en `dist\WebAudit-Sec.exe`.

Si cambias `logo-dentro.png`, regenera el icono con `python tools/make_icon.py`
(requiere `pip install pillow`).
