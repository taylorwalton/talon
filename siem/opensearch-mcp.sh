#!/usr/bin/env bash
# OpenSearch MCP Server wrapper for NanoClaw SIEM
#
# - Loads credentials from .env in the same directory
# - Runs the MCP server from the local .venv (no host Python conflicts)
#
# This script is called by Claude Code as the MCP server command.
# Do not run it directly — use `claude` from the siem/ directory instead.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load credentials from .env
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/.env"
    set +a
else
    echo "[opensearch-mcp] ERROR: .env not found at $SCRIPT_DIR/.env" >&2
    echo "[opensearch-mcp] Run setup.sh first and fill in your OpenSearch credentials." >&2
    exit 1
fi

LOCAL_MCP="$SCRIPT_DIR/.venv/bin/opensearch-mcp-server"
SYSTEM_MCP="/opt/opensearch-mcp/bin/opensearch-mcp-server"

# Check if the local .venv binary is native to this OS (handles macOS venv mounted in Linux container)
_is_native_exec() {
    local bin="$1"
    [[ -x "$bin" ]] || return 1
    if [[ "$(uname -s)" == "Linux" ]]; then
        # Verify ELF magic bytes — macOS Mach-O binaries cannot run on Linux
        local magic
        magic=$(head -c 4 "$bin" 2>/dev/null | od -An -tx1 | tr -d ' \n')
        [[ "$magic" == "7f454c46" ]] || return 1
    fi
    return 0
}

if _is_native_exec "$LOCAL_MCP"; then
    exec "$LOCAL_MCP"
elif [[ -x "$SYSTEM_MCP" ]]; then
    # System venv pre-installed in the NanoClaw container image
    exec "$SYSTEM_MCP"
else
    echo "[opensearch-mcp] ERROR: opensearch-mcp-server not found." >&2
    echo "[opensearch-mcp]   In a container: rebuild the image (container/build.sh)" >&2
    echo "[opensearch-mcp]   On the host: run siem/setup.sh" >&2
    exit 1
fi
