#!/usr/bin/env bash
# Shuffle MCP Server wrapper for NanoClaw.
#
# Two execution paths:
#
#   1. Inside the NanoClaw agent container with per-MCP isolation enabled.
#      The wrapper detects an isolated secret at /etc/mcp-secrets/shuffle.env
#      and uses sudo to drop privs to mcp-shuffle before sourcing it.
#
#   2. Legacy / host fallback. Sources shuffle-mcp/.env directly.
#
# This script is called by Claude Code as the MCP server command.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

LOCAL_MCP="$SCRIPT_DIR/.venv/bin/shuffle-mcp-server"
SYSTEM_MCP="/opt/shuffle-mcp/bin/shuffle-mcp-server"
ISOLATED_ENV="/etc/mcp-secrets/shuffle.env"

_is_native_exec() {
    local bin="$1"
    [[ -x "$bin" ]] || return 1
    if [[ "$(uname -s)" == "Linux" ]]; then
        local magic
        magic=$(head -c 4 "$bin" 2>/dev/null | od -An -tx1 | tr -d ' \n')
        [[ "$magic" == "7f454c46" ]] || return 1
    fi
    return 0
}

# === Container path: isolated mcp-shuffle uid ===
if [[ -f "$ISOLATED_ENV" ]] && [[ -x "$SYSTEM_MCP" ]] && command -v sudo >/dev/null 2>&1; then
    exec sudo -n -u mcp-shuffle /bin/bash -c "
        set -a
        source '$ISOLATED_ENV'
        set +a
        exec '$SYSTEM_MCP'
    "
fi

# === Fallback: legacy path ===
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/.env"
    set +a
else
    echo "[shuffle-mcp] ERROR: .env not found at $SCRIPT_DIR/.env" >&2
    echo "[shuffle-mcp] Run setup.sh first and fill in your Shuffle credentials." >&2
    exit 1
fi

if _is_native_exec "$LOCAL_MCP"; then
    exec "$LOCAL_MCP"
elif [[ -x "$SYSTEM_MCP" ]]; then
    exec "$SYSTEM_MCP"
else
    echo "[shuffle-mcp] ERROR: shuffle-mcp-server not found." >&2
    echo "[shuffle-mcp]   In a container: rebuild the image (container/build.sh)" >&2
    echo "[shuffle-mcp]   On the host: run shuffle-mcp/setup.sh" >&2
    exit 1
fi
