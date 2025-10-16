#!/usr/bin/env bash
set -euo pipefail

echo "======================================"
echo "  jsrip Installation"
echo "======================================"

# 1) Python version (>=3.9)
echo "[1/4] Checking Python version..."
PYTHON_BIN="${PYTHON_BIN:-python3}"
PY_VER=$($PYTHON_BIN - <<'PY'
import sys
print(f"{sys.version_info.major}.{sys.version_info.minor}")
PY
)
REQUIRED="3.9"
if [ "$(printf '%s\n' "$REQUIRED" "$PY_VER" | sort -V | head -n1)" != "$REQUIRED" ]; then
  echo "Error: Python $REQUIRED+ required, found $PY_VER"
  exit 1
fi
echo "✓ Python $PY_VER"

# 2) venv
echo "[2/4] Creating/activating virtualenv..."
if [ ! -d "venv" ]; then
  $PYTHON_BIN -m venv venv
fi
# shellcheck disable=SC1091
source venv/bin/activate
echo "✓ venv ready"

# 3) deps
echo "[3/4] Installing Python deps..."
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
echo "✓ deps installed"

# 4) playwright browser
echo "[4/4] Installing Playwright Chromium..."
python -m playwright install chromium
echo "✓ Chromium installed"

echo "======================================"
echo "  Done!"
echo "======================================"
echo "Activate venv:"
echo "  source venv/bin/activate"
echo "Run:"
echo "  python jsrip.py -u https://example.com"
