@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "PROXY_EXE=%~dp0src\telegram-proxy.exe"

powershell.exe -NoProfile -Command "$p=Get-Process -Name 'telegram-proxy' -ErrorAction SilentlyContinue | Where-Object Path -EQ $env:PROXY_EXE; if(-not $p){exit 1}; $p | Stop-Process -Force"
if errorlevel 1 (
    echo [telegram-proxy] The proxy is not running.
    exit /b 0
)

echo [telegram-proxy] Stopped.
endlocal
exit /b 0
