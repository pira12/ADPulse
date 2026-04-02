<#
.SYNOPSIS
    Installs the AD Security Continuous Assessment Engine as a Windows Scheduled Task.

.DESCRIPTION
    Creates a scheduled task that runs the scanner every N hours as the specified
    service account. The service account requires NO admin rights — just be a
    member of Domain Users.

.PARAMETER ServiceAccount
    The domain account to run the task as (e.g. DOMAIN\svc-secmonitor)

.PARAMETER ServicePassword
    The password for the service account

.PARAMETER PythonPath
    Full path to python.exe (default: tries to find it automatically)

.PARAMETER InstallDir
    Directory where the engine is installed

.PARAMETER IntervalHours
    How often to run the scan (default: 6 hours)

.EXAMPLE
    .\install_scheduled_task.ps1 -ServiceAccount "CORP\svc-secmonitor" -ServicePassword "P@ssw0rd!" -InstallDir "C:\ADSecurityEngine"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$ServiceAccount,

    [Parameter(Mandatory=$true)]
    [string]$ServicePassword,

    [Parameter(Mandatory=$false)]
    [string]$PythonPath = "",

    [Parameter(Mandatory=$false)]
    [string]$InstallDir = "C:\ADSecurityEngine",

    [Parameter(Mandatory=$false)]
    [int]$IntervalHours = 6,

    [Parameter(Mandatory=$false)]
    [string]$TaskName = "ADSecurityAssessmentEngine"
)

$ErrorActionPreference = "Stop"

Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   AD Security Engine - Scheduled Task Installer              ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── Find Python ──────────────────────────────────────────────────────────────
if (-not $PythonPath) {
    $candidates = @(
        "python",
        "python3",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe",
        "C:\Python312\python.exe",
        "C:\Python311\python.exe",
    )
    foreach ($candidate in $candidates) {
        try {
            $ver = & $candidate --version 2>&1
            if ($LASTEXITCODE -eq 0) {
                $PythonPath = (Get-Command $candidate -ErrorAction SilentlyContinue)?.Source
                if (-not $PythonPath) { $PythonPath = $candidate }
                Write-Host "✅ Found Python: $PythonPath ($ver)" -ForegroundColor Green
                break
            }
        } catch {}
    }
    if (-not $PythonPath) {
        Write-Host "❌ Python not found. Install Python 3.10+ and try again." -ForegroundColor Red
        exit 1
    }
}

# ── Verify install directory ──────────────────────────────────────────────────
if (-not (Test-Path $InstallDir)) {
    Write-Host "❌ Install directory not found: $InstallDir" -ForegroundColor Red
    Write-Host "   Copy the ad_security_engine folder to $InstallDir and try again."
    exit 1
}

$MainScript  = Join-Path $InstallDir "main.py"
$ConfigFile  = Join-Path $InstallDir "config.ini"

if (-not (Test-Path $MainScript)) {
    Write-Host "❌ main.py not found in $InstallDir" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $ConfigFile)) {
    Write-Host "❌ config.ini not found in $InstallDir" -ForegroundColor Red
    Write-Host "   Copy config.ini.example to config.ini and configure your settings."
    exit 1
}

# ── Install dependencies ──────────────────────────────────────────────────────
Write-Host "📦 Installing Python dependencies..." -ForegroundColor Yellow
$reqFile = Join-Path $InstallDir "requirements.txt"
& $PythonPath -m pip install -r $reqFile --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ pip install failed. Check your internet connection." -ForegroundColor Red
    exit 1
}
Write-Host "✅ Dependencies installed." -ForegroundColor Green

# ── Create output and logs directories ───────────────────────────────────────
New-Item -ItemType Directory -Force -Path (Join-Path $InstallDir "output") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $InstallDir "logs")   | Out-Null

# ── Remove existing task if present ──────────────────────────────────────────
$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Write-Host "⚠️  Removing existing task '$TaskName'..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

# ── Build task components ─────────────────────────────────────────────────────
$Action = New-ScheduledTaskAction `
    -Execute $PythonPath `
    -Argument "`"$MainScript`" --config `"$ConfigFile`"" `
    -WorkingDirectory $InstallDir

# Run at system startup, then every N hours
$TriggerBoot = New-ScheduledTaskTrigger -AtStartup
$TriggerRepeat = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Hours $IntervalHours) -Once -At (Get-Date)

$Settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 15) `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable `
    -MultipleInstances IgnoreNew

$Principal = New-ScheduledTaskPrincipal `
    -UserId $ServiceAccount `
    -LogonType Password `
    -RunLevel Limited   # Explicitly NOT elevated

# ── Register the task ─────────────────────────────────────────────────────────
Write-Host "📅 Registering scheduled task '$TaskName'..." -ForegroundColor Yellow

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $TriggerBoot `
    -Settings $Settings `
    -Principal $Principal `
    -Password $ServicePassword `
    -Description "AD Security Continuous Assessment Engine - runs every $IntervalHours hours using low-privilege domain account" `
    -Force | Out-Null

Write-Host "✅ Scheduled task registered successfully." -ForegroundColor Green

# ── Run a test scan immediately ───────────────────────────────────────────────
Write-Host ""
Write-Host "🔍 Running initial test scan..." -ForegroundColor Yellow
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 5

$taskInfo = Get-ScheduledTask -TaskName $TaskName
$taskInfo | Get-ScheduledTaskInfo | Select-Object LastRunTime, LastTaskResult, NextRunTime | Format-List

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  ✅ Installation Complete!                                    ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Task Name    : $TaskName"
Write-Host "  Runs As      : $ServiceAccount (standard domain user, no admin rights)"
Write-Host "  Interval     : Every $IntervalHours hours"
Write-Host "  Install Dir  : $InstallDir"
Write-Host "  Reports      : $InstallDir\output\"
Write-Host "  Logs         : $InstallDir\logs\"
Write-Host ""
Write-Host "  To view in Task Scheduler: taskschd.msc"
Write-Host "  To run manually          : Start-ScheduledTask -TaskName '$TaskName'"
Write-Host "  To view history          : python main.py --history"
Write-Host ""
