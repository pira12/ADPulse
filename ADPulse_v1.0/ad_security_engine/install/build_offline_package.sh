#!/usr/bin/env bash
# build_offline_package.sh
# ─────────────────────────────────────────────────────────────────────────────
# Builds a fully self-contained ADPulse package for offline Windows deployment.
# Run this on your Linux machine — it downloads the Windows Python embeddable
# and Windows-compatible dependency wheels, pre-installs everything, and
# assembles a folder you can copy directly to the air-gapped VM via RDP.
#
# Usage:
#   ./build_offline_package.sh                         # defaults
#   ./build_offline_package.sh 3.12.7 ./MyOutput      # custom version + dir
#
# Requirements: python3, pip3, curl, unzip
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

PYTHON_VERSION="${1:-3.12.7}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE_DIR="$(dirname "$SCRIPT_DIR")"               # ad_security_engine/
DEFAULT_OUT="$(dirname "$ENGINE_DIR")/ADPulse_Portable"
OUTPUT_DIR="$(realpath -m "${2:-$DEFAULT_OUT}")"

# ── ANSI colours ──────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

echo ""
echo -e "${CYAN}${BOLD}=======================================================${NC}"
echo -e "${CYAN}${BOLD}   ADPulse - Offline Package Builder (Linux → Windows) ${NC}"
echo -e "${CYAN}${BOLD}   Bundles portable Python + all dependencies          ${NC}"
echo -e "${CYAN}${BOLD}=======================================================${NC}"
echo ""

# ── Prerequisite check ────────────────────────────────────────────────────────
MISSING=()
for cmd in python3 curl unzip; do
    command -v "$cmd" &>/dev/null || MISSING+=("$cmd")
done
if [ ${#MISSING[@]} -gt 0 ]; then
    echo -e "${RED}ERROR: Missing required tools: ${MISSING[*]}${NC}"
    echo "  Install them (e.g. sudo apt install python3-pip curl unzip) and retry."
    exit 1
fi

# Verify pip is available
python3 -m pip --version &>/dev/null || {
    echo -e "${RED}ERROR: pip not available. Install with: sudo apt install python3-pip${NC}"
    exit 1
}

# Derive short version string: 3.12.7 → 312
PY_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)
PY_SHORT="${PY_MAJOR}${PY_MINOR}"

# ── Clean output directory ────────────────────────────────────────────────────
if [ -d "$OUTPUT_DIR" ]; then
    echo -e "${YELLOW}Cleaning existing output directory...${NC}"
    rm -rf "$OUTPUT_DIR"
fi

PYTHON_DIR="$OUTPUT_DIR/python"
WHEEL_DIR="$OUTPUT_DIR/wheels"
PKG_DIR="$OUTPUT_DIR/ad_security_engine"
SITE_PKG="$PYTHON_DIR/Lib/site-packages"

mkdir -p "$PYTHON_DIR" "$WHEEL_DIR" "$PKG_DIR" "$SITE_PKG"

# ── Step 1: Download Windows Python embeddable ────────────────────────────────
echo ""
echo -e "${YELLOW}[1/4] Downloading Python $PYTHON_VERSION Windows embeddable...${NC}"

PY_ZIP="python-${PYTHON_VERSION}-embed-amd64.zip"
PY_URL="https://www.python.org/ftp/python/${PYTHON_VERSION}/${PY_ZIP}"
PY_ZIP_PATH="$OUTPUT_DIR/$PY_ZIP"

curl -L --progress-bar -o "$PY_ZIP_PATH" "$PY_URL" || {
    echo -e "${RED}ERROR: Failed to download Python from:${NC}"
    echo "  $PY_URL"
    echo "  Check your internet connection or try a different version."
    exit 1
}

echo "  Extracting..."
unzip -q "$PY_ZIP_PATH" -d "$PYTHON_DIR"
rm "$PY_ZIP_PATH"

# Enable site-packages in the embeddable's _pth file.
# By default it has '#import site' commented out and no Lib\site-packages path.
PTH_FILE=$(find "$PYTHON_DIR" -maxdepth 1 -name "python*._pth" | head -1)
if [ -n "$PTH_FILE" ]; then
    # Uncomment 'import site'
    sed -i 's/^#\s*import site/import site/' "$PTH_FILE"
    # Add Lib\site-packages if not already present
    grep -q "Lib.site-packages" "$PTH_FILE" || printf 'Lib\\site-packages\n' >> "$PTH_FILE"
    echo -e "  Patched $(basename "$PTH_FILE") to enable site-packages"
else
    echo -e "${YELLOW}  WARNING: Could not find ._pth file — site-packages may not load${NC}"
fi

echo -e "${GREEN}[OK] Python $PYTHON_VERSION extracted and configured.${NC}"

# ── Step 2: Download Windows-compatible wheels ────────────────────────────────
echo ""
echo -e "${YELLOW}[2/4] Downloading Windows dependency wheels...${NC}"

REQUIREMENTS="$ENGINE_DIR/requirements.txt"
if [ ! -f "$REQUIREMENTS" ]; then
    echo -e "${RED}ERROR: requirements.txt not found at $REQUIREMENTS${NC}"
    exit 1
fi

# pip download with cross-platform flags fetches Windows wheels from Linux.
# Try cp (CPython) wheels for win_amd64 first, fall back to any compatible wheel.
echo "  Fetching CPython $PY_SHORT wheels for win_amd64..."
if ! python3 -m pip download \
        -r "$REQUIREMENTS" \
        -d "$WHEEL_DIR" \
        --platform win_amd64 \
        --python-version "$PY_SHORT" \
        --implementation cp \
        --abi "cp${PY_SHORT}" \
        --only-binary=:all: \
        --quiet 2>/dev/null; then

    echo -e "${YELLOW}  Retrying without strict ABI constraint...${NC}"
    python3 -m pip download \
        -r "$REQUIREMENTS" \
        -d "$WHEEL_DIR" \
        --platform win_amd64 \
        --python-version "$PY_SHORT" \
        --implementation cp \
        --only-binary=:all: \
        --quiet || {
        echo -e "${RED}ERROR: Failed to download Windows wheels.${NC}"
        echo "  Make sure pip is up to date: python3 -m pip install --upgrade pip"
        exit 1
    }
fi

WHL_COUNT=$(find "$WHEEL_DIR" -name "*.whl" | wc -l)
echo -e "${GREEN}[OK] $WHL_COUNT wheel file(s) downloaded.${NC}"

# ── Step 3: Pre-install wheels into portable Python's site-packages ───────────
echo ""
echo -e "${YELLOW}[3/4] Pre-installing dependencies into portable Python...${NC}"
echo "  (Extracts wheels directly into site-packages — no pip needed on the VM)"

for wheel in "$WHEEL_DIR"/*.whl; do
    whl_name=$(basename "$wheel")
    echo "    → $whl_name"
    # Wheels are zip files. Extract everything into site-packages.
    # The dist-info/ and package dirs land correctly at the top level.
    unzip -q -o "$wheel" -d "$SITE_PKG"
done

# Verify the critical packages are present
echo ""
ALL_OK=true
for pkg in ldap3 reportlab; do
    if find "$SITE_PKG" -maxdepth 1 -name "${pkg}" -type d | grep -q .; then
        echo -e "    ${GREEN}[OK]${NC} $pkg"
    else
        echo -e "    ${YELLOW}[WARN]${NC} $pkg directory not found in site-packages"
        ALL_OK=false
    fi
done

if [ "$ALL_OK" = false ]; then
    echo ""
    echo -e "${YELLOW}  Some packages may be missing. The wheels are still bundled${NC}"
    echo -e "${YELLOW}  and install_offline.ps1 will install them on first run.${NC}"
fi

echo -e "${GREEN}[OK] Dependencies pre-installed.${NC}"

# ── Step 4: Copy ADPulse source files ─────────────────────────────────────────
echo ""
echo -e "${YELLOW}[4/4] Copying ADPulse source files...${NC}"

for f in main.py requirements.txt config.ini.example DETECTIONS.md ARCHITECTURE.md README.md; do
    [ -f "$ENGINE_DIR/$f" ] && cp "$ENGINE_DIR/$f" "$PKG_DIR/"
done

[ -d "$ENGINE_DIR/modules"  ] && cp -r "$ENGINE_DIR/modules"  "$PKG_DIR/"
[ -d "$ENGINE_DIR/install"  ] && cp -r "$ENGINE_DIR/install"  "$PKG_DIR/"

mkdir -p "$PKG_DIR/output" "$PKG_DIR/logs"

# Copy install_offline.ps1 to the package root for easy access
[ -f "$SCRIPT_DIR/install_offline.ps1" ] && cp "$SCRIPT_DIR/install_offline.ps1" "$OUTPUT_DIR/"

echo -e "${GREEN}[OK] Source files copied.${NC}"

# ── Batch launchers ───────────────────────────────────────────────────────────

cat > "$OUTPUT_DIR/Run-ADPulse.bat" << 'ENDBATCH'
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
ENDBATCH

cat > "$OUTPUT_DIR/Test-Connection.bat" << 'ENDBATCH'
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
ENDBATCH

cat > "$OUTPUT_DIR/Install-ScheduledTask.bat" << 'ENDBATCH'
@echo off
setlocal
set BASEDIR=%~dp0
echo.
echo Installing ADPulse as a Windows Scheduled Task...
echo (Runs every 6 hours automatically, no login needed)
echo.
powershell -ExecutionPolicy Bypass -File "%BASEDIR%install_offline.ps1"
pause
ENDBATCH

# ── Summary ───────────────────────────────────────────────────────────────────
TOTAL_MB=$(du -sm "$OUTPUT_DIR" | cut -f1)

echo ""
echo -e "${GREEN}${BOLD}=======================================================${NC}"
echo -e "${GREEN}${BOLD}   Package Ready!                                       ${NC}"
echo -e "${GREEN}${BOLD}=======================================================${NC}"
echo ""
echo -e "  ${BOLD}Location${NC} : $OUTPUT_DIR"
echo -e "  ${BOLD}Size${NC}     : ~${TOTAL_MB} MB"
echo -e "  ${BOLD}Python${NC}   : $PYTHON_VERSION (Windows embeddable, pre-configured)"
echo ""
echo -e "${CYAN}  Package layout:${NC}"
echo "    python/                    Portable Python with deps pre-installed"
echo "    wheels/                    Dependency wheels (fallback)"
echo "    ad_security_engine/        ADPulse source code + modules"
echo "    Run-ADPulse.bat            Double-click to run a scan"
echo "    Test-Connection.bat        Verify LDAP connectivity"
echo "    Install-ScheduledTask.bat  Set up recurring automated scans"
echo ""
echo -e "${YELLOW}  Transfer to the air-gapped VM via RDP:${NC}"
echo "    1. In your RDP client, go to:"
echo "       Local Resources → More → Drives → check your local drive"
echo "    2. Connect to the VM"
echo "    3. Inside the RDP session, open File Explorer and navigate to:"
echo "       \\\\tsclient\\  (you'll see your local drives listed)"
echo "    4. Copy the ADPulse_Portable folder to C:\\ on the VM"
echo ""
echo -e "${YELLOW}  On the Windows VM (no install steps needed):${NC}"
echo "    1. Double-click Run-ADPulse.bat"
echo "       → On first run it creates config.ini and opens it in Notepad"
echo "    2. Fill in your domain controller (server = dc01.corp.local, domain = corp.local)"
echo "    3. Double-click Run-ADPulse.bat again — it scans and saves reports to output\\"
echo ""
echo -e "${YELLOW}  Optional - set up automated recurring scans:${NC}"
echo "    Double-click Install-ScheduledTask.bat (runs as your Windows user, no admin needed)"
echo ""
