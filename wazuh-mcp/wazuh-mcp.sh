#!/usr/bin/env bash
# Wazuh MCP Server wrapper for NanoClaw.
#
# Two execution paths:
#
#   1. Inside the NanoClaw agent container with per-MCP isolation enabled.
#      The wrapper detects an isolated secret at /etc/mcp-secrets/wazuh.env
#      and uses sudo to drop privs to mcp-wazuh before sourcing it. The
#      agent (running as node uid) cannot read /etc/mcp-secrets/wazuh.env.
#
#   2. Legacy / host fallback. When the isolated secret isn't present
#      (host install or older container), the wrapper falls back to
#      sourcing wazuh-mcp/.env directly.
#
# This script is called by Claude Code as the MCP server command.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

LOCAL_MCP="$SCRIPT_DIR/.venv/bin/wazuh-mcp-server"
SYSTEM_MCP="/opt/wazuh-mcp/bin/wazuh-mcp-server"
ISOLATED_ENV="/etc/mcp-secrets/wazuh.env"

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

# === Container path: isolated mcp-wazuh uid ===
if [[ -f "$ISOLATED_ENV" ]] && [[ -x "$SYSTEM_MCP" ]] && command -v sudo >/dev/null 2>&1; then
    exec sudo -n -u mcp-wazuh /bin/bash -c "
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
    echo "[wazuh-mcp] ERROR: .env not found at $SCRIPT_DIR/.env" >&2
    echo "[wazuh-mcp] Run setup.sh first and fill in your Wazuh credentials." >&2
    exit 1
fi

if _is_native_exec "$LOCAL_MCP"; then
    exec "$LOCAL_MCP"
elif [[ -x "$SYSTEM_MCP" ]]; then
    exec "$SYSTEM_MCP"
else
    echo "[wazuh-mcp] ERROR: wazuh-mcp-server not found." >&2
    echo "[wazuh-mcp]   In a container: rebuild the image (container/build.sh)" >&2
    echo "[wazuh-mcp]   On the host: run wazuh-mcp/setup.sh" >&2
    exit 1
fi
