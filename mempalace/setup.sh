#!/usr/bin/env bash
# Talon MemPalace — one-time host setup
#
# Creates a local Python venv and installs mempalace + chromadb.
# Run this on the host machine so the wrapper script can use the venv
# when developing or testing outside a container.
#
# Inside the container, /opt/mempalace (pre-baked into the image) is used instead.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

echo "=== Talon MemPalace Setup ==="
echo ""

# ── Python check ─────────────────────────────────────────────────────────────
PYTHON_BIN=""
for candidate in python3.13 python3.12 python3.11 python3.10 python3.9 python3; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [[ "$major" -eq 3 && "$minor" -ge 9 ]]; then
            PYTHON_BIN="$candidate"
            PYTHON_VERSION="$ver"
            break
        fi
    fi
done

if [[ -z "$PYTHON_BIN" ]]; then
    echo "ERROR: Python 3.9+ is required."
    exit 1
fi

echo "Using $PYTHON_BIN ($PYTHON_VERSION)  ✓"

# ── Virtual environment ───────────────────────────────────────────────────────
if [[ ! -d "$VENV_DIR" ]]; then
    echo "Creating virtual environment..."
    "$PYTHON_BIN" -m venv "$VENV_DIR"
else
    echo "Virtual environment exists  ✓"
fi

# ── Install dependencies ──────────────────────────────────────────────────────
echo "Installing mempalace and chromadb (this may take a minute)..."
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet "chromadb>=0.5.0,<0.7" "pyyaml>=6.0" mempalace
echo "Dependencies installed  ✓"

# ── Palace data directory ─────────────────────────────────────────────────────
PALACE_DATA_DIR="$SCRIPT_DIR/../mempalace-data/palace"
mkdir -p "$PALACE_DATA_DIR"
echo "Palace data directory: $PALACE_DATA_DIR  ✓"

# ── .env ─────────────────────────────────────────────────────────────────────
ENV_FILE="$SCRIPT_DIR/.env"
if [[ ! -f "$ENV_FILE" ]]; then
    cp "$SCRIPT_DIR/.env.example" "$ENV_FILE"
    echo ""
    echo "  Created .env from template."
    echo "  ➜ Edit $ENV_FILE if you need to change the palace data path."
    echo ""
else
    echo ".env exists  ✓"
fi

echo ""
echo "=== Setup complete! ==="
echo ""
echo "MemPalace will initialize its palace structure automatically on first use."
echo "Palace data is stored at: $(realpath "$PALACE_DATA_DIR")"
echo ""
