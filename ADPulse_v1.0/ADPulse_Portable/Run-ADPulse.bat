@echo off
setlocal
set BASEDIR=%~dp0
set PYTHON=%BASEDIR%python\python.exe
set ENGINE=%BASEDIR%ad_security_engine\main.py
set CONFIG=%BASEDIR%ad_security_engine\config.ini

echo ============================================
echo   ADPulse - AD Security Assessment Engine
echo ============================================
echo.

if not exist "%PYTHON%" (
    echo ERROR: Portable Python not found at %PYTHON%
    echo The package may be incomplete - re-transfer the full ADPulse_Portable folder.
    pause
    exit /b 1
)

if not exist "%CONFIG%" (
    echo First run detected - creating config.ini from template...
    copy "%BASEDIR%ad_security_engine\config.ini.example" "%CONFIG%" >nul
    echo.
    echo IMPORTANT: Edit config.ini with your domain controller settings,
    echo then run this script again to start scanning.
    echo.
    notepad "%CONFIG%"
    pause
    exit /b
)

if "%~1"=="" (
    "%PYTHON%" "%ENGINE%" --config "%CONFIG%"
) else (
    "%PYTHON%" "%ENGINE%" --config "%CONFIG%" %*
)
pause
