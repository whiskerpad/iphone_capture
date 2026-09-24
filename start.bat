@echo off
rem ASCII only + CRLF: cmd.exe reads .bat in the console code page (CP932)
cd /d "%~dp0"
rem Python lookup order: IPHONE_CAPTURE_PYTHON, py launcher, LOCALAPPDATA Python3x, python.exe on PATH
set "PY=%IPHONE_CAPTURE_PYTHON%"
if not defined PY where py.exe >nul 2>&1 && set "PY=py.exe"
if not defined PY for /d %%d in ("%LOCALAPPDATA%\Programs\Python\Python3*") do if exist "%%d\python.exe" set "PY=%%d\python.exe"
if not defined PY where python.exe >nul 2>&1 && set "PY=python.exe"
if not defined PY (
  echo [ERROR] Python 3.8+ not found. Install it from https://www.python.org/
  pause
  exit /b 1
)
del /q "%~dp0page.url" 2>nul
rem Stop a leftover capture server (python) still holding port 8765/8443
for /f "tokens=5" %%p in ('netstat -ano ^| findstr /r /c:"TCP  *[0-9.]*:8765  *[0-9.]*:0  *LISTENING" /c:"TCP  *[0-9.]*:8443  *[0-9.]*:0  *LISTENING"') do (
  tasklist /fi "pid eq %%p" /nh | find /i "python" >nul && (
    echo Stopping old capture server PID %%p
    taskkill /f /pid %%p >nul 2>&1
  )
)
ping -n 2 127.0.0.1 >nul
start "iphone-capture-open" /MIN "%~dp0open_page.bat"
"%PY%" -m pip install --disable-pip-version-check "cryptography>=42,<46"
if errorlevel 1 (
  echo [ERROR] pip install cryptography failed.
  pause
  exit /b 1
)
set IPHONE_CAPTURE_BAT=1
"%PY%" "%~dp0capture_server.py"
echo.
echo Server stopped. Closing this window also stops receiving.
pause
