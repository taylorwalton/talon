#!/usr/bin/env bash
# MySQL MCP Server wrapper for NanoClaw.
#
# Two execution paths:
#
#   1. Inside the NanoClaw agent container with per-MCP isolation enabled.
#      The wrapper detects an isolated secret at /etc/mcp-secrets/mysql.env
#      and uses sudo to drop privs to mcp-mysql before sourcing it.
#      The agent (running as node uid) cannot read /etc/mcp-secrets/mysql.env.
#
#   2. Legacy / host fallback. Sources mysql/.env directly.
#
# Unlike most other wrappers, mcp-server-mysql is a globally-installed npm
# binary (not under /opt/), so we resolve it via PATH lookup.
#
# This script is called by Claude Code as the MCP server command.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ISOLATED_ENV="/etc/mcp-secrets/mysql.env"

# === Container path: isolated mcp-mysql uid ===
if [[ -f "$ISOLATED_ENV" ]] && command -v sudo >/dev/null 2>&1; then
    # Resolve the binary path before privilege drop so the sudo'd shell
    # doesn't need to redo PATH lookup with a different environment.
    SYSTEM_BIN=$(command -v mcp-server-mysql 2>/dev/null || true)
    if [[ -n "$SYSTEM_BIN" ]]; then
        exec sudo -n -u mcp-mysql /bin/bash -c "
            set -a
            source '$ISOLATED_ENV'
            set +a
            exec '$SYSTEM_BIN'
        "
    fi
fi

# === Fallback: legacy path ===
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
