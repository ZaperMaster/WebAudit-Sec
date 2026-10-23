@echo off
rem Crea dist\WebAudit-Sec.exe (app de escritorio) con PyInstaller.
rem Se ejecuta desde cualquier sitio: trabaja en la raíz del proyecto.
setlocal
cd /d "%~dp0.."

if not exist ".venv\Scripts\python.exe" (
    py -3 -m venv .venv
    if errorlevel 1 goto :error
)

".venv\Scripts\python.exe" -m pip install -r desktop\requirements.txt
if errorlevel 1 goto :error

rem --paths: raíz del proyecto, para importar webaudit, web y desktop.
rem --icon: icono del .exe.  web\static: interfaz.  desktop\assets: icono de la ventana.
".venv\Scripts\python.exe" -m PyInstaller ^
    --noconfirm ^
    --clean ^
    --windowed ^
    --onefile ^
    --name WebAudit-Sec ^
    --paths . ^
    --collect-all webview ^
    --collect-all tldextract ^
    --icon desktop\assets\app.ico ^
    --add-data "web\static;web\static" ^
    --add-data "desktop\assets\app.ico;desktop\assets" ^
    desktop\__main__.py
if errorlevel 1 goto :error

del /q WebAudit-Sec.spec 2>nul
echo.
echo Ejecutable creado en: %CD%\dist\WebAudit-Sec.exe
pause
exit /b 0

:error
echo.
echo No se pudo crear el ejecutable. Revisa el error anterior.
pause
exit /b 1
