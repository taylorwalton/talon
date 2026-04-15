#!/usr/bin/env bash
# Velociraptor MCP Server wrapper for NanoClaw
#
# - Loads credentials from .env in the same directory
# - Resolves VELOCIRAPTOR_API_KEY to an absolute path relative to this script
#   (handles macOS host path vs Linux container path transparently)
# - Runs velociraptor-mcp-server from the local .venv (no host Python conflicts)
#
# This script is called by Claude Code as the MCP server command.
# Do not run it directly — use setup.sh first, then start NanoClaw.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load credentials from .env
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/.env"
    set +a
else
    echo "[velociraptor-mcp] ERROR: .env not found at $SCRIPT_DIR/.env" >&2
    echo "[velociraptor-mcp] Run setup.sh first and fill in your Velociraptor credentials." >&2
    exit 1
fi

# Resolve VELOCIRAPTOR_API_KEY to absolute path if it's relative
# This ensures the same .env works on both the macOS host and inside the Linux container
# (where SCRIPT_DIR will be /workspace/extra/velociraptor-mcp)
if [[ "${VELOCIRAPTOR_API_KEY:-}" != /* ]]; then
    export VELOCIRAPTOR_API_KEY="$SCRIPT_DIR/${VELOCIRAPTOR_API_KEY:-api.config.yaml}"
fi

if [[ ! -f "$VELOCIRAPTOR_API_KEY" ]]; then
    echo "[velociraptor-mcp] ERROR: api.config.yaml not found at $VELOCIRAPTOR_API_KEY" >&2
    echo "[velociraptor-mcp] Copy your Velociraptor api.config.yaml into the velociraptor-mcp/ directory." >&2
    exit 1
fi

LOCAL_MCP="$SCRIPT_DIR/.venv/bin/velociraptor-mcp-server"
SYSTEM_MCP="/opt/velociraptor-mcp/bin/velociraptor-mcp-server"

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
    # System installation pre-installed in the NanoClaw container image
    exec "$SYSTEM_MCP"
else
    echo "[velociraptor-mcp] ERROR: velociraptor-mcp-server not found." >&2
    echo "[velociraptor-mcp]   In a container: rebuild the image (container/build.sh)" >&2
    echo "[velociraptor-mcp]   On the host: run velociraptor-mcp/setup.sh" >&2
    exit 1
fi
