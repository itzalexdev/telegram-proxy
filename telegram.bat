@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "PROXY_EXE=%~dp0src\telegram-proxy.exe"
set "PROXY_PORT=15444"
set "PROXY_SECRET=ddb277d051fec605df7f3a57badd188a1d"

if not exist "%PROXY_EXE%" (
    echo [telegram-proxy] telegram-proxy.exe is missing.
    pause
    exit /b 1
)

netstat -ano -p tcp | findstr /R /C:"127.0.0.1:%PROXY_PORT% .*LISTENING" >nul
if errorlevel 1 goto start_proxy
tasklist /FI "IMAGENAME eq telegram-proxy.exe" /NH | findstr /I /C:"telegram-proxy.exe" >nul
if not errorlevel 1 goto proxy_ready
echo [telegram-proxy] Port %PROXY_PORT% is used by another application.
pause
exit /b 2

:start_proxy
start "Telegram Proxy" /min "%PROXY_EXE%" --port %PROXY_PORT%
timeout /t 2 /nobreak >nul
netstat -ano -p tcp | findstr /R /C:"127.0.0.1:%PROXY_PORT% .*LISTENING" >nul
if errorlevel 1 (
    echo [telegram-proxy] The proxy did not start correctly.
    pause
    exit /b 3
)

:proxy_ready
echo [telegram-proxy] Ready on 127.0.0.1:%PROXY_PORT%.
start "" "tg://proxy?server=127.0.0.1&port=%PROXY_PORT%&secret=%PROXY_SECRET%"

endlocal
exit /b 0
