@echo off
setlocal
set BASEDIR=%~dp0
echo.
echo Installing ADPulse as a Windows Scheduled Task...
echo (Runs every 6 hours automatically, no login needed)
echo.
powershell -ExecutionPolicy Bypass -File "%BASEDIR%install_offline.ps1"
pause
