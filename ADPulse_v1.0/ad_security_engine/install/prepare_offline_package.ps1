<#
.SYNOPSIS
    Prepares an offline deployment package for ADPulse on a machine WITH internet.

.DESCRIPTION
    Downloads all Python wheel dependencies and bundles them with the ADPulse
    source into a self-contained folder that can be copied to an air-gapped VM
    via USB, file share, or any other transfer method.

    Run this on any internet-connected machine with Python 3.10+.
    Then copy the resulting folder to your offline AD VM.

.PARAMETER OutputDir
    Directory where the offline package will be created (default: .\ADPulse_Offline)

.PARAMETER PythonPath
    Path to python.exe (default: auto-detect)

.EXAMPLE
    # On your internet-connected workstation:
    .\prepare_offline_package.ps1

.EXAMPLE
    .\prepare_offline_package.ps1 -OutputDir "D:\Transfer\ADPulse_Offline"
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputDir = ".\ADPulse_Offline",

    [Parameter(Mandatory=$false)]
    [string]$PythonPath = ""
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "   ADPulse - Offline Package Builder                    " -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Run this on a machine WITH internet access." -ForegroundColor Yellow
Write-Host "Then copy the output folder to your air-gapped AD VM." -ForegroundColor Yellow
Write-Host ""

# -- Find Python ---------------------------------------------------------------
if (-not $PythonPath) {
    $candidates = @("python", "python3",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe")
    foreach ($candidate in $candidates) {
        try {
            $ver = & $candidate --version 2>&1
            if ($LASTEXITCODE -eq 0) {
                $PythonPath = (Get-Command $candidate -ErrorAction SilentlyContinue)?.Source
                if (-not $PythonPath) { $PythonPath = $candidate }
                Write-Host "[OK] Found Python: $PythonPath ($ver)" -ForegroundColor Green
                break
            }
        } catch {}
    }
    if (-not $PythonPath) {
        Write-Host "ERROR: Python not found. Install Python 3.10+ first." -ForegroundColor Red
        exit 1
    }
}

# -- Locate source directory (relative to this script) -------------------------
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$EngineDir   = Split-Path -Parent $ScriptDir          # ad_security_engine/
$RequirementsFile = Join-Path $EngineDir "requirements.txt"

if (-not (Test-Path $RequirementsFile)) {
    Write-Host "ERROR: requirements.txt not found at $RequirementsFile" -ForegroundColor Red
    exit 1
}

# -- Create output structure ---------------------------------------------------
$PkgDir   = Join-Path $OutputDir "ad_security_engine"
$WheelDir = Join-Path $OutputDir "wheels"

if (Test-Path $OutputDir) {
    Write-Host "Cleaning existing output directory..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $OutputDir
}

New-Item -ItemType Directory -Force -Path $PkgDir   | Out-Null
New-Item -ItemType Directory -Force -Path $WheelDir  | Out-Null

# -- Download wheels for offline install ---------------------------------------
Write-Host ""
Write-Host "Downloading dependency wheels..." -ForegroundColor Yellow
& $PythonPath -m pip download -r $RequirementsFile -d $WheelDir --only-binary=:all:
if ($LASTEXITCODE -ne 0) {
    Write-Host "Binary-only download had issues, retrying with source fallback..." -ForegroundColor Yellow
    & $PythonPath -m pip download -r $RequirementsFile -d $WheelDir
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to download dependencies." -ForegroundColor Red
        exit 1
    }
}
Write-Host "Wheels downloaded to: $WheelDir" -ForegroundColor Green

# -- Copy ADPulse source -------------------------------------------------------
Write-Host "Copying ADPulse source files..." -ForegroundColor Yellow
$filesToCopy = @("main.py", "requirements.txt", "config.ini.example", "DETECTIONS.md",
                 "ARCHITECTURE.md", "README.md")
foreach ($f in $filesToCopy) {
    $src = Join-Path $EngineDir $f
    if (Test-Path $src) {
        Copy-Item $src -Destination $PkgDir
    }
}

# Copy modules
$moduleSrc = Join-Path $EngineDir "modules"
if (Test-Path $moduleSrc) {
    Copy-Item -Recurse $moduleSrc -Destination (Join-Path $PkgDir "modules")
}

# Copy install scripts
$installSrc = Join-Path $EngineDir "install"
if (Test-Path $installSrc) {
    Copy-Item -Recurse $installSrc -Destination (Join-Path $PkgDir "install")
}

# -- Create the offline install script -----------------------------------------
Copy-Item (Join-Path $ScriptDir "install_offline.ps1") -Destination $OutputDir -ErrorAction SilentlyContinue

# -- Summary -------------------------------------------------------------------
$wheelCount = (Get-ChildItem $WheelDir -Filter "*.whl" -ErrorAction SilentlyContinue).Count
$wheelCount += (Get-ChildItem $WheelDir -Filter "*.tar.gz" -ErrorAction SilentlyContinue).Count

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Green
Write-Host "   Offline Package Ready!                               " -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Package location : $((Resolve-Path $OutputDir).Path)"
Write-Host "  Wheels bundled   : $wheelCount"
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor Yellow
Write-Host "  1. Copy the '$OutputDir' folder to your offline AD VM"
Write-Host "     (USB drive, file share, etc.)"
Write-Host "  2. On the VM, run:" -ForegroundColor Yellow
Write-Host "     .\install_offline.ps1" -ForegroundColor White
Write-Host ""
