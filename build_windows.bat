@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    py -3 -m venv .venv
    if errorlevel 1 goto :error
)

".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto :error

".venv\Scripts\python.exe" -m PyInstaller ^
    --noconfirm ^
    --clean ^
    --windowed ^
    --onefile ^
    --name WebAudit-Sec ^
    --collect-all webview ^
    --collect-all tldextract ^
    --icon "%~dp0app\static\webaudit-sec.ico" ^
    --add-data "%~dp0app\static\index.html;app\static" ^
    --add-data "%~dp0app\static\webaudit-sec.ico;app\static" ^
    --add-data "%~dp0app\static\webaudit-sec-window.ico;app\static" ^
    --add-data "%~dp0logo;logo" ^
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