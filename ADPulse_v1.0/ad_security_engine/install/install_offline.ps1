<#
.SYNOPSIS
    Installs ADPulse on an air-gapped VM with no internet access.

.DESCRIPTION
    Installs Python dependencies from pre-downloaded wheels (bundled by
    prepare_offline_package.ps1), sets up ADPulse, and optionally creates
    a scheduled task for continuous scanning.

    Prerequisites:
    - Python 3.10+ must already be installed on the VM
    - Run prepare_offline_package.ps1 on an internet-connected machine first

.PARAMETER InstallDir
    Where to install ADPulse (default: C:\ADSecurityEngine)

.PARAMETER PythonPath
    Path to python.exe (default: auto-detect)

.PARAMETER SkipScheduledTask
    Skip scheduled task creation (just install files and dependencies)

.PARAMETER IntervalHours
    Scan interval for scheduled task (default: 6)

.EXAMPLE
    # On the air-gapped AD VM:
    .\install_offline.ps1

.EXAMPLE
    .\install_offline.ps1 -InstallDir "D:\ADPulse" -IntervalHours 12
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$InstallDir = "C:\ADSecurityEngine",

    [Parameter(Mandatory=$false)]
    [string]$PythonPath = "",

    [Parameter(Mandatory=$false)]
    [switch]$SkipScheduledTask,

    [Parameter(Mandatory=$false)]
    [int]$IntervalHours = 6,

    [Parameter(Mandatory=$false)]
    [string]$TaskName = "ADSecurityAssessmentEngine"
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "   ADPulse - Offline Installer                          " -ForegroundColor Cyan
Write-Host "   (No internet required)                               " -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""

# -- Locate package contents ---------------------------------------------------
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$WheelDir  = Join-Path $ScriptDir "wheels"
$SourceDir = Join-Path $ScriptDir "ad_security_engine"

if (-not (Test-Path $WheelDir)) {
    Write-Host "ERROR: 'wheels' folder not found at $WheelDir" -ForegroundColor Red
    Write-Host "   Did you run prepare_offline_package.ps1 first?" -ForegroundColor Yellow
    exit 1
}
if (-not (Test-Path $SourceDir)) {
    Write-Host "ERROR: 'ad_security_engine' folder not found at $SourceDir" -ForegroundColor Red
    exit 1
}

# -- Find Python ---------------------------------------------------------------
if (-not $PythonPath) {
    $candidates = @("python", "python3",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe",
        "C:\Python312\python.exe",
        "C:\Python311\python.exe")
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
        Write-Host "ERROR: Python not found on this machine." -ForegroundColor Red
        Write-Host ""
        Write-Host "Python must be pre-installed on the offline VM." -ForegroundColor Yellow
        Write-Host "Options:" -ForegroundColor Yellow
        Write-Host "  1. Install from the Python embeddable package (no internet needed)"
        Write-Host "     Download python-3.12.x-embed-amd64.zip from python.org on another machine"
        Write-Host "     and extract it to C:\Python312\ on this VM."
        Write-Host "  2. Use your organization's software deployment tool to install Python."
        Write-Host ""
        exit 1
    }
}

# Verify Python version
$pyVer = & $PythonPath -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>&1
$pyMajor, $pyMinor = $pyVer -split '\.'
if ([int]$pyMajor -lt 3 -or ([int]$pyMajor -eq 3 -and [int]$pyMinor -lt 10)) {
    Write-Host "ERROR: Python 3.10+ required, found $pyVer" -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Python version: $pyVer" -ForegroundColor Green

# -- Copy source to install directory ------------------------------------------
Write-Host ""
Write-Host "Copying ADPulse to $InstallDir ..." -ForegroundColor Yellow

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

Copy-Item -Path "$SourceDir\*" -Destination $InstallDir -Recurse -Force
New-Item -ItemType Directory -Force -Path (Join-Path $InstallDir "output") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $InstallDir "logs")   | Out-Null

Write-Host "[OK] Source files copied." -ForegroundColor Green

# -- Install dependencies from local wheels ------------------------------------
Write-Host ""
Write-Host "Installing Python dependencies from offline wheels..." -ForegroundColor Yellow
& $PythonPath -m pip install --no-index --find-links $WheelDir ldap3 reportlab
if ($LASTEXITCODE -ne 0) {
    Write-Host "WARNING: pip install from wheels returned an error." -ForegroundColor Yellow
    Write-Host "Trying alternative: installing all wheel files directly..." -ForegroundColor Yellow
    $wheelFiles = Get-ChildItem $WheelDir -Filter "*.whl" | ForEach-Object { $_.FullName }
    if ($wheelFiles) {
        & $PythonPath -m pip install @wheelFiles
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to install dependencies." -ForegroundColor Red
        Write-Host "Ensure the wheels were downloaded for the same Python version and platform." -ForegroundColor Yellow
        exit 1
    }
}
Write-Host "[OK] Dependencies installed (offline)." -ForegroundColor Green

# -- Verify installation -------------------------------------------------------
Write-Host ""
Write-Host "Verifying installation..." -ForegroundColor Yellow
$verifyResult = & $PythonPath -c "import ldap3; import reportlab; print('OK')" 2>&1
if ($verifyResult -ne "OK") {
    Write-Host "ERROR: Import verification failed: $verifyResult" -ForegroundColor Red
    exit 1
}
Write-Host "[OK] All dependencies verified." -ForegroundColor Green

# -- Config file setup ---------------------------------------------------------
$ConfigFile = Join-Path $InstallDir "config.ini"
if (-not (Test-Path $ConfigFile)) {
    $ExampleConfig = Join-Path $InstallDir "config.ini.example"
    if (Test-Path $ExampleConfig) {
        Copy-Item $ExampleConfig $ConfigFile
        Write-Host ""
        Write-Host "IMPORTANT: config.ini created from template." -ForegroundColor Yellow
        Write-Host "Edit $ConfigFile with your domain controller settings before running." -ForegroundColor Yellow
    }
}

# -- Scheduled task (optional) -------------------------------------------------
if (-not $SkipScheduledTask) {
    Write-Host ""
    Write-Host "Setting up scheduled task..." -ForegroundColor Yellow

    $MainScript = Join-Path $InstallDir "main.py"

    $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Write-Host "Removing existing task '$TaskName'..." -ForegroundColor Yellow
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }

    $Action = New-ScheduledTaskAction `
        -Execute $PythonPath `
        -Argument "`"$MainScript`" --config `"$ConfigFile`"" `
        -WorkingDirectory $InstallDir

    $TriggerBoot = New-ScheduledTaskTrigger -AtStartup
    $TriggerRepeat = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Hours $IntervalHours) -Once -At (Get-Date)

    $Settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 15) `
        -StartWhenAvailable `
        -MultipleInstances IgnoreNew

    $Principal = New-ScheduledTaskPrincipal `
        -UserId "$env:USERDOMAIN\$env:USERNAME" `
        -LogonType S4U `
        -RunLevel Limited

    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $Action `
        -Trigger $TriggerBoot `
        -Settings $Settings `
        -Principal $Principal `
        -Description "ADPulse - AD Security Continuous Assessment (offline install)" `
        -Force | Out-Null

    Write-Host "[OK] Scheduled task '$TaskName' created (every $IntervalHours hours)." -ForegroundColor Green
}

# -- Test connectivity ---------------------------------------------------------
Write-Host ""
Write-Host "Running connection test..." -ForegroundColor Yellow
$testResult = & $PythonPath (Join-Path $InstallDir "main.py") --test-connection 2>&1
Write-Host $testResult

# -- Done ----------------------------------------------------------------------
Write-Host ""
Write-Host "=======================================================" -ForegroundColor Green
Write-Host "   Offline Installation Complete!                       " -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Install Dir  : $InstallDir"
Write-Host "  Config       : $ConfigFile"
Write-Host "  Python       : $PythonPath"
if (-not $SkipScheduledTask) {
    Write-Host "  Task Name    : $TaskName"
    Write-Host "  Interval     : Every $IntervalHours hours"
}
Write-Host ""
Write-Host "  Quick start:" -ForegroundColor Yellow
Write-Host "    1. Edit $ConfigFile with your DC settings"
Write-Host "    2. python $InstallDir\main.py --test-connection"
Write-Host "    3. python $InstallDir\main.py"
Write-Host ""
