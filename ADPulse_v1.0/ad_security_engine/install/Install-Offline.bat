@echo off
setlocal

echo.
echo =======================================================
echo   ADPulse - Offline Installer
echo =======================================================
echo.

set "SCRIPTDIR=%~dp0"
powershell -ExecutionPolicy Bypass -File "%SCRIPTDIR%install_offline.ps1" %*

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Something went wrong. Check the errors above.
    echo.
)
pause
