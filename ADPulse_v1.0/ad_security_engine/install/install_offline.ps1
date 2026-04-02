<#
.SYNOPSIS
    Installs ADPulse as a scheduled task on an air-gapped VM using bundled portable Python.

.DESCRIPTION
    Uses the portable Python and pre-installed dependencies bundled by
    prepare_offline_package.ps1. No internet or Python installation required.

    Can also be used standalone if Python is already installed on the VM.

.PARAMETER InstallDir
    Where to install ADPulse (default: runs from current location)

.PARAMETER IntervalHours
    Scan interval for scheduled task (default: 6)

.PARAMETER SkipScheduledTask
    Skip scheduled task creation

.EXAMPLE
    .\install_offline.ps1

.EXAMPLE
    .\install_offline.ps1 -IntervalHours 12
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$InstallDir = "",

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
Write-Host "   (No internet or Python installation required)        " -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""

# -- Locate package contents ---------------------------------------------------
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$PortablePy = Join-Path $ScriptDir "python\python.exe"
$SourceDir  = Join-Path $ScriptDir "ad_security_engine"
$WheelDir   = Join-Path $ScriptDir "wheels"

# -- Find Python: prefer bundled portable, fall back to system -----------------
$PythonPath = ""

if (Test-Path $PortablePy) {
    $PythonPath = $PortablePy
    $pyVer = & $PythonPath --version 2>&1
    Write-Host "[OK] Using bundled portable Python: $pyVer" -ForegroundColor Green
} else {
    # Fall back to system Python
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
                Write-Host "[OK] Found system Python: $PythonPath ($ver)" -ForegroundColor Green
                break
            }
        } catch {}
    }
    if (-not $PythonPath) {
        Write-Host "ERROR: No Python found." -ForegroundColor Red
        Write-Host "  The bundled portable Python was not found at: $PortablePy" -ForegroundColor Yellow
        Write-Host "  Did you use prepare_offline_package.ps1 to build this package?" -ForegroundColor Yellow
        exit 1
    }
}

# -- Determine install location ------------------------------------------------
if (-not $InstallDir) {
    # Default: run from current package location (no copy needed)
    $InstallDir = $ScriptDir
    Write-Host "Running from package directory: $InstallDir" -ForegroundColor Cyan
} else {
    # Copy everything to the specified install directory
    Write-Host "Copying package to $InstallDir ..." -ForegroundColor Yellow
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    }
    Copy-Item -Path "$ScriptDir\*" -Destination $InstallDir -Recurse -Force
    # Update paths to the new location
    $PythonPath = Join-Path $InstallDir "python\python.exe"
    $SourceDir  = Join-Path $InstallDir "ad_security_engine"
    $WheelDir   = Join-Path $InstallDir "wheels"
    Write-Host "[OK] Copied." -ForegroundColor Green
}

# -- Ensure source dir exists --------------------------------------------------
if (-not (Test-Path $SourceDir)) {
    Write-Host "ERROR: ad_security_engine folder not found at $SourceDir" -ForegroundColor Red
    exit 1
}

# -- Install dependencies from wheels if not already installed -----------------
Write-Host ""
Write-Host "Checking dependencies..." -ForegroundColor Yellow

$depsOk = & $PythonPath -c "import ldap3; import reportlab; print('OK')" 2>&1
if ($depsOk -eq "OK") {
    Write-Host "[OK] Dependencies already installed in portable Python." -ForegroundColor Green
} elseif (Test-Path $WheelDir) {
    Write-Host "Installing from bundled wheels..." -ForegroundColor Yellow
    & $PythonPath -m pip install --no-index --find-links $WheelDir ldap3 reportlab --no-warn-script-location 2>&1
    if ($LASTEXITCODE -ne 0) {
        # Try installing wheel files directly
        $wheelFiles = Get-ChildItem $WheelDir -Filter "*.whl" | ForEach-Object { $_.FullName }
        if ($wheelFiles) {
            & $PythonPath -m pip install @wheelFiles --no-warn-script-location
        }
    }
    # Verify
    $depsOk = & $PythonPath -c "import ldap3; import reportlab; print('OK')" 2>&1
    if ($depsOk -ne "OK") {
        Write-Host "ERROR: Dependency installation failed: $depsOk" -ForegroundColor Red
        exit 1
    }
    Write-Host "[OK] Dependencies installed." -ForegroundColor Green
} else {
    Write-Host "ERROR: Dependencies not installed and no wheels directory found." -ForegroundColor Red
    exit 1
}

# -- Config file setup ---------------------------------------------------------
$ConfigFile = Join-Path $SourceDir "config.ini"
if (-not (Test-Path $ConfigFile)) {
    $ExampleConfig = Join-Path $SourceDir "config.ini.example"
    if (Test-Path $ExampleConfig) {
        Copy-Item $ExampleConfig $ConfigFile
        Write-Host ""
        Write-Host "IMPORTANT: config.ini created from template." -ForegroundColor Yellow
        Write-Host "  Edit $ConfigFile with your domain controller settings." -ForegroundColor Yellow
    }
}

# -- Create output/logs dirs ---------------------------------------------------
New-Item -ItemType Directory -Force -Path (Join-Path $SourceDir "output") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $SourceDir "logs")   | Out-Null

# -- Scheduled task (optional) -------------------------------------------------
if (-not $SkipScheduledTask) {
    Write-Host ""
    Write-Host "Setting up scheduled task..." -ForegroundColor Yellow

    $MainScript = Join-Path $SourceDir "main.py"

    $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Write-Host "Removing existing task '$TaskName'..." -ForegroundColor Yellow
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }

    $Action = New-ScheduledTaskAction `
        -Execute "`"$PythonPath`"" `
        -Argument "`"$MainScript`" --config `"$ConfigFile`"" `
        -WorkingDirectory $SourceDir

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
        -Description "ADPulse - AD Security Assessment (portable, offline)" `
        -Force | Out-Null

    Write-Host "[OK] Scheduled task '$TaskName' created (every $IntervalHours hours)." -ForegroundColor Green
}

# -- Test connectivity ---------------------------------------------------------
Write-Host ""
Write-Host "Running LDAP connection test..." -ForegroundColor Yellow
$MainScript = Join-Path $SourceDir "main.py"
& $PythonPath $MainScript --test-connection 2>&1

# -- Done ----------------------------------------------------------------------
Write-Host ""
Write-Host "=======================================================" -ForegroundColor Green
Write-Host "   Installation Complete!                               " -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Install Dir  : $SourceDir"
Write-Host "  Python       : $PythonPath (portable, bundled)"
Write-Host "  Config       : $ConfigFile"
if (-not $SkipScheduledTask) {
    Write-Host "  Task Name    : $TaskName"
    Write-Host "  Interval     : Every $IntervalHours hours"
}
Write-Host ""
Write-Host "  Quick start:" -ForegroundColor Yellow
Write-Host "    1. Edit config.ini with your DC settings"
Write-Host "    2. Double-click Run-ADPulse.bat (or run manually below)"
Write-Host "    3. $PythonPath $MainScript --test-connection"
Write-Host "    4. $PythonPath $MainScript"
Write-Host ""
