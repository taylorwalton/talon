#!/usr/bin/env bash
# NanoClaw Shuffle MCP — one-time setup
#
# What this does:
#   1. Creates a Python virtual environment (.venv/) to avoid host Python conflicts
#   2. Installs shuffle-mcp-server from GitHub into it
#   3. Creates .env from .env.example if not already present
#
# After running this, edit .env with your Shuffle API key, then restart NanoClaw.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
ENV_FILE="$SCRIPT_DIR/.env"
MCP_WRAPPER="$SCRIPT_DIR/shuffle-mcp.sh"

echo "=== NanoClaw Shuffle MCP Setup ==="
echo ""

# ── Python check ─────────────────────────────────────────────────────────────
PYTHON_BIN=""
for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [[ "$major" -eq 3 && "$minor" -ge 10 && "$minor" -le 13 ]]; then
            PYTHON_BIN="$candidate"
            PYTHON_VERSION="$ver"
            break
        fi
    fi
done

if [[ -z "$PYTHON_BIN" ]]; then
    echo "ERROR: Python 3.10–3.13 is required."
    echo "       Install Python 3.13 via Homebrew: brew install python@3.13"
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

# ── Install shuffle-mcp-server ────────────────────────────────────────────────
echo "Installing shuffle-mcp-server from GitHub..."
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet \
    "git+https://github.com/socfortress/shuffle-mcp-server.git"
echo "shuffle-mcp-server installed  ✓"

# ── .env ─────────────────────────────────────────────────────────────────────
if [[ ! -f "$ENV_FILE" ]]; then
    cp "$SCRIPT_DIR/.env.example" "$ENV_FILE"
    echo ""
    echo "  Created .env from template."
    echo "  ➜ Edit $ENV_FILE with your Shuffle API key."
    echo ""
else
    echo ".env exists  ✓"
fi

chmod +x "$MCP_WRAPPER"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "=== Setup complete! ==="
echo ""
if grep -q "your-shuffle-api-key" "$ENV_FILE" 2>/dev/null; then
    echo "Next steps:"
    echo "  1. Edit shuffle-mcp/.env with your Shuffle API key"
    echo "     (the same key configured in CoPilot's Shuffle connector)"
    echo "  2. Optionally set SHUFFLE_ORG_ID to scope to one customer's org"
    echo "  3. Restart NanoClaw"
else
    echo "Restart NanoClaw to pick up the Shuffle MCP server."
fi
echo ""
