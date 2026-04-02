@echo off
setlocal
set BASEDIR=%~dp0
set PYTHON=%BASEDIR%python\python.exe
set ENGINE=%BASEDIR%ad_security_engine\main.py
set CONFIG=%BASEDIR%ad_security_engine\config.ini

echo ============================================
echo   ADPulse - Test LDAP Connection
echo ============================================
echo.

if not exist "%CONFIG%" (
    echo ERROR: config.ini not found.
    echo Run Run-ADPulse.bat first to create it, then fill in your DC settings.
    pause
    exit /b 1
)

"%PYTHON%" "%ENGINE%" --config "%CONFIG%" --test-connection
pause
