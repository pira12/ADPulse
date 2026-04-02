<#
.SYNOPSIS
    Builds a fully self-contained ADPulse package — includes portable Python.

.DESCRIPTION
    Downloads Python embeddable (portable, no installer), pip, and all dependency
    wheels, then bundles everything with the ADPulse source into a single folder.

    The resulting package can run on ANY Windows machine — no Python installation,
    no internet, and no admin rights required.

    Transfer the folder to the air-gapped VM via:
    - RDP drive redirection (\\tsclient\C\...)
    - Network file share (\\fileserver\share\...)
    - Any other file transfer method

    Run this on any internet-connected Windows machine.

.PARAMETER OutputDir
    Directory where the offline package will be created (default: .\ADPulse_Portable)

.PARAMETER PythonVersion
    Python version to bundle (default: 3.12.7)

.EXAMPLE
    .\prepare_offline_package.ps1

.EXAMPLE
    .\prepare_offline_package.ps1 -OutputDir "\\fileserver\transfer\ADPulse_Portable"
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputDir = ".\ADPulse_Portable",

    [Parameter(Mandatory=$false)]
    [string]$PythonVersion = "3.12.7"
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "   ADPulse - Portable Package Builder                   " -ForegroundColor Cyan
Write-Host "   (Bundles Python + dependencies — zero install needed) " -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""

# -- Clean output directory ----------------------------------------------------
if (Test-Path $OutputDir) {
    Write-Host "Cleaning existing output directory..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $OutputDir
}

$PythonDir = Join-Path $OutputDir "python"
$WheelDir  = Join-Path $OutputDir "wheels"
$PkgDir    = Join-Path $OutputDir "ad_security_engine"

New-Item -ItemType Directory -Force -Path $PythonDir | Out-Null
New-Item -ItemType Directory -Force -Path $WheelDir  | Out-Null
New-Item -ItemType Directory -Force -Path $PkgDir    | Out-Null

# -- Download Python embeddable package ----------------------------------------
Write-Host ""
Write-Host "[1/4] Downloading Python $PythonVersion embeddable package..." -ForegroundColor Yellow

$pyZipName = "python-$PythonVersion-embed-amd64.zip"
$pyZipUrl  = "https://www.python.org/ftp/python/$PythonVersion/$pyZipName"
$pyZipPath = Join-Path $OutputDir $pyZipName

try {
    Invoke-WebRequest -Uri $pyZipUrl -OutFile $pyZipPath -UseBasicParsing
} catch {
    Write-Host "ERROR: Failed to download Python from $pyZipUrl" -ForegroundColor Red
    Write-Host "  Check the version number or your internet connection." -ForegroundColor Yellow
    Write-Host "  Error: $_" -ForegroundColor Red
    exit 1
}

Write-Host "  Extracting..." -ForegroundColor Yellow
Expand-Archive -Path $pyZipPath -DestinationPath $PythonDir -Force
Remove-Item $pyZipPath

# -- Enable pip in the embeddable distribution ---------------------------------
# The embeddable Python ships with imports disabled. We need to uncomment the
# "import site" line in the python3XX._pth file to enable pip/site-packages.
$pthFile = Get-ChildItem $PythonDir -Filter "python*._pth" | Select-Object -First 1
if ($pthFile) {
    $pthContent = Get-Content $pthFile.FullName
    $pthContent = $pthContent -replace "^#\s*import site", "import site"
    # Also add Lib\site-packages so pip-installed packages are found
    $pthContent += "Lib\site-packages"
    Set-Content -Path $pthFile.FullName -Value $pthContent
    Write-Host "  Enabled site-packages in $($pthFile.Name)" -ForegroundColor Green
}

Write-Host "[OK] Python $PythonVersion extracted to: $PythonDir" -ForegroundColor Green

# -- Download and install pip --------------------------------------------------
Write-Host ""
Write-Host "[2/4] Installing pip into portable Python..." -ForegroundColor Yellow

$getPipUrl  = "https://bootstrap.pypa.io/get-pip.py"
$getPipPath = Join-Path $OutputDir "get-pip.py"
$portablePython = Join-Path $PythonDir "python.exe"

Invoke-WebRequest -Uri $getPipUrl -OutFile $getPipPath -UseBasicParsing
& $portablePython $getPipPath --no-warn-script-location 2>&1 | Out-Null
Remove-Item $getPipPath

if (-not (& $portablePython -m pip --version 2>&1)) {
    Write-Host "ERROR: pip installation failed." -ForegroundColor Red
    exit 1
}
Write-Host "[OK] pip installed." -ForegroundColor Green

# -- Download dependency wheels ------------------------------------------------
Write-Host ""
Write-Host "[3/4] Downloading dependency wheels..." -ForegroundColor Yellow

$ScriptDir        = Split-Path -Parent $MyInvocation.MyCommand.Path
$EngineDir        = Split-Path -Parent $ScriptDir
$RequirementsFile = Join-Path $EngineDir "requirements.txt"

if (-not (Test-Path $RequirementsFile)) {
    Write-Host "ERROR: requirements.txt not found at $RequirementsFile" -ForegroundColor Red
    exit 1
}

& $portablePython -m pip download -r $RequirementsFile -d $WheelDir --only-binary=:all:
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Retrying with source fallback..." -ForegroundColor Yellow
    & $portablePython -m pip download -r $RequirementsFile -d $WheelDir
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to download dependencies." -ForegroundColor Red
        exit 1
    }
}

# Pre-install wheels into the portable Python so it's ready to run immediately
Write-Host "  Pre-installing dependencies into portable Python..." -ForegroundColor Yellow
& $portablePython -m pip install --no-index --find-links $WheelDir ldap3 reportlab --no-warn-script-location
if ($LASTEXITCODE -ne 0) {
    Write-Host "WARNING: Pre-install failed, wheels are still bundled for manual install." -ForegroundColor Yellow
}

Write-Host "[OK] Dependencies ready." -ForegroundColor Green

# -- Copy ADPulse source -------------------------------------------------------
Write-Host ""
Write-Host "[4/4] Copying ADPulse source files..." -ForegroundColor Yellow

$filesToCopy = @("main.py", "requirements.txt", "config.ini.example",
                 "DETECTIONS.md", "ARCHITECTURE.md", "README.md")
foreach ($f in $filesToCopy) {
    $src = Join-Path $EngineDir $f
    if (Test-Path $src) { Copy-Item $src -Destination $PkgDir }
}

$moduleSrc = Join-Path $EngineDir "modules"
if (Test-Path $moduleSrc) {
    Copy-Item -Recurse $moduleSrc -Destination (Join-Path $PkgDir "modules")
}

$installSrc = Join-Path $EngineDir "install"
if (Test-Path $installSrc) {
    Copy-Item -Recurse $installSrc -Destination (Join-Path $PkgDir "install")
}

New-Item -ItemType Directory -Force -Path (Join-Path $PkgDir "output") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $PkgDir "logs")   | Out-Null

Write-Host "[OK] Source files copied." -ForegroundColor Green

# -- Copy the offline installer into the package root --------------------------
Copy-Item (Join-Path $ScriptDir "install_offline.ps1") -Destination $OutputDir -ErrorAction SilentlyContinue

# -- Create a quick-launch batch file -----------------------------------------
$batchContent = @"
@echo off
setlocal
set BASEDIR=%~dp0
set PYTHON=%BASEDIR%python\python.exe
set ENGINE=%BASEDIR%ad_security_engine\main.py

echo ============================================
echo   ADPulse - AD Security Assessment Engine
echo ============================================
echo.

if not exist "%BASEDIR%ad_security_engine\config.ini" (
    echo First run detected - creating config.ini from template...
    copy "%BASEDIR%ad_security_engine\config.ini.example" "%BASEDIR%ad_security_engine\config.ini"
    echo.
    echo IMPORTANT: Edit ad_security_engine\config.ini with your domain controller settings.
    echo Then run this script again.
    echo.
    notepad "%BASEDIR%ad_security_engine\config.ini"
    pause
    exit /b
)

if "%~1"=="" (
    "%PYTHON%" "%ENGINE%" --config "%BASEDIR%ad_security_engine\config.ini"
) else (
    "%PYTHON%" "%ENGINE%" --config "%BASEDIR%ad_security_engine\config.ini" %*
)
pause
"@
Set-Content -Path (Join-Path $OutputDir "Run-ADPulse.bat") -Value $batchContent

# -- Create a scheduled task installer batch -----------------------------------
$taskBatchContent = @"
@echo off
setlocal
set BASEDIR=%~dp0
set PYTHON=%BASEDIR%python\python.exe

echo Installing ADPulse as a scheduled task...
powershell -ExecutionPolicy Bypass -File "%BASEDIR%install_offline.ps1"
pause
"@
Set-Content -Path (Join-Path $OutputDir "Install-ScheduledTask.bat") -Value $taskBatchContent

# -- Summary -------------------------------------------------------------------
$totalSize = (Get-ChildItem $OutputDir -Recurse | Measure-Object -Property Length -Sum).Sum
$sizeMB = [math]::Round($totalSize / 1MB, 1)

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Green
Write-Host "   Portable Package Ready!                              " -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Location     : $((Resolve-Path $OutputDir).Path)"
Write-Host "  Total size   : $sizeMB MB"
Write-Host "  Python       : $PythonVersion (embedded)"
Write-Host ""
Write-Host "  Package contents:" -ForegroundColor Cyan
Write-Host "    python\              Portable Python (no install needed)"
Write-Host "    wheels\              Pre-downloaded dependency wheels"
Write-Host "    ad_security_engine\  ADPulse source code"
Write-Host "    Run-ADPulse.bat      Double-click to run a scan"
Write-Host "    Install-ScheduledTask.bat  Set up recurring scans"
Write-Host ""
Write-Host "  Transfer methods:" -ForegroundColor Yellow
Write-Host "    - RDP: copy via \\tsclient\C\ (enable drive redirection)"
Write-Host "    - Network share: copy to \\server\share\"
Write-Host "    - Any file transfer your org allows"
Write-Host ""
Write-Host "  On the air-gapped VM, just double-click Run-ADPulse.bat" -ForegroundColor Yellow
Write-Host ""
