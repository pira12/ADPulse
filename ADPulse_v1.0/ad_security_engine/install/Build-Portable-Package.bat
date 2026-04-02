@echo off
setlocal

echo.
echo =======================================================
echo   ADPulse - Build Portable Package
echo   (Run this on a machine WITH internet access)
echo =======================================================
echo.

set "SCRIPTDIR=%~dp0"
powershell -ExecutionPolicy Bypass -File "%SCRIPTDIR%prepare_offline_package.ps1" %*

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Something went wrong. Check the errors above.
    echo.
)
pause
