#!/usr/bin/env bash
# MySQL MCP Server wrapper for NanoClaw
#
# - Loads credentials from .env in the same directory
# - Runs @benborla29/mcp-server-mysql (pre-installed globally in the container image)
#
# This script is called by Claude Code as the MCP server command.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load credentials from .env
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/.env"
    set +a
else
    echo "[mysql-mcp] ERROR: .env not found at $SCRIPT_DIR/.env" >&2
    echo "[mysql-mcp] Run setup.sh first and fill in your MySQL credentials." >&2
    exit 1
fi

# Prefer globally installed binary; fall back to npx (slower but always works)
if command -v mcp-server-mysql &>/dev/null; then
    exec mcp-server-mysql
else
    exec npx --yes @benborla29/mcp-server-mysql
fi
