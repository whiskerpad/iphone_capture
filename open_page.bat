@echo off
rem Waits for page.url written by capture_server.py, then opens it in the default browser.
cd /d "%~dp0"
set "URLFILE=%~dp0page.url"
set /a N=0
:wait
if exist "%URLFILE%" goto open
set /a N+=1
if %N% GEQ 180 goto fail
ping -n 2 127.0.0.1 >nul
goto wait
:open
set /p URL=<"%URLFILE%"
start "" "%URL%"
exit /b 0
:fail
echo [ERROR] page.url was not created. Open the URL shown in the server window manually.
pause
exit /b 1
