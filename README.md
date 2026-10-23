# WebAudit Sec

Auditor de seguridad web de escritorio para Windows. Abre una ventana propia y solo
inicia su servidor local en `127.0.0.1`.

## Estructura

```
desktop.py               Lanzador (python desktop.py)
build_windows.bat        Crea dist\WebAudit-Sec.exe
app/
  main.py                API local (FastAPI)
  jobs.py                Análisis en segundo plano: progreso y cancelación
  desktop.py             Ventana, icono y barra de título
  scanner/               Motor de análisis
    config.py            Constantes, límites y reglas
    network.py           Validación de destinos y peticiones HTTP
    results.py           Formato de checks y hallazgos (y plantillas para traducirlos)
    html_page.py         Lectura del HTML: enlaces, recursos y formularios
    links.py             Enlaces del mismo sitio para el rastreo
    analyzers.py         Análisis de valores (CSP, HSTS, cookies...)
    page_checks.py       Comprobaciones de cada página (cabeceras, cookies, contenido mixto, SRI)
    tls.py               Handshake, cadena, versiones TLS y revocación (OCSP/CRL)
    tls_checks.py        Comprobaciones TLS a partir de esos datos
    site_checks.py       Comprobaciones de sitio (redirección, métodos, security.txt)
    crawler.py           scan_security_headers y scan_website
  static/
    index.html           Interfaz
    css/styles.css
    js/i18n.js           Textos ES / EN de la interfaz
    js/i18n-scanner.js   Traducción al inglés de los textos del escáner
    js/window.js         Barra de título propia y controles de ventana
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
