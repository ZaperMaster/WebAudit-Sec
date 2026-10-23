@echo off
rem Crea dist\WebAudit-Sec.exe con PyInstaller.
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    py -3 -m venv .venv
    if errorlevel 1 goto :error
)

".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto :error

rem --icon: icono del .exe (escritorio).  app\static: interfaz, logos e iconos.
".venv\Scripts\python.exe" -m PyInstaller ^
    --noconfirm ^
    --clean ^
    --windowed ^
    --onefile ^
    --name WebAudit-Sec ^
    --collect-all webview ^
    --collect-all tldextract ^
    --icon "%~dp0app\static\icons\app.ico" ^
    --add-data "%~dp0app\static;app\static" ^
    "%~dp0desktop.py"
if errorlevel 1 goto :error

echo.
echo Ejecutable creado en: %~dp0dist\WebAudit-Sec.exe
pause
exit /b 0

:error
echo.
echo No se pudo crear el ejecutable. Revisa el error anterior.
pause
exit /b 1
