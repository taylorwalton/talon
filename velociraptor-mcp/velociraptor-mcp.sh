#!/usr/bin/env bash
# Velociraptor MCP Server wrapper for NanoClaw.
#
# Velociraptor uses mTLS for gRPC — the api.config.yaml IS the client
# certificate + key. Both .env (which references the cert path) and
# api.config.yaml itself are protected by the per-MCP isolation pattern.
#
# Two execution paths:
#
#   1. Inside the NanoClaw agent container with per-MCP isolation enabled.
#      The wrapper detects:
#        /etc/mcp-secrets/velociraptor.env             (env, mode 600 mcp-velociraptor)
#        /etc/mcp-secrets/velociraptor.api.config.yaml (cert, mode 600 mcp-velociraptor)
#      and uses sudo to drop privs to mcp-velociraptor before sourcing the
#      env. VELOCIRAPTOR_API_KEY is overridden to the isolated cert path
#      regardless of what the .env says (since the original cert location
#      is shadowed and unreadable).
#
#   2. Legacy / host fallback. Resolves the cert path relative to SCRIPT_DIR.
#
# This script is called by Claude Code as the MCP server command.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

LOCAL_MCP="$SCRIPT_DIR/.venv/bin/velociraptor-mcp-server"
SYSTEM_MCP="/opt/velociraptor-mcp/bin/velociraptor-mcp-server"
ISOLATED_ENV="/etc/mcp-secrets/velociraptor.env"
ISOLATED_CERT="/etc/mcp-secrets/velociraptor.api.config.yaml"

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

# === Container path: isolated mcp-velociraptor uid ===
if [[ -f "$ISOLATED_ENV" ]] && [[ -f "$ISOLATED_CERT" ]] && [[ -x "$SYSTEM_MCP" ]] && command -v sudo >/dev/null 2>&1; then
    # Override VELOCIRAPTOR_API_KEY after sourcing so the cert path always
    # points at the isolated copy. The original at /workspace/extra/.../api.config.yaml
    # is shadowed by /dev/null and unreadable to mcp-velociraptor anyway.
    exec sudo -n -u mcp-velociraptor /bin/bash -c "
        set -a
        source '$ISOLATED_ENV'
        export VELOCIRAPTOR_API_KEY='$ISOLATED_CERT'
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
    echo "[velociraptor-mcp] ERROR: .env not found at $SCRIPT_DIR/.env" >&2
    echo "[velociraptor-mcp] Run setup.sh first and fill in your Velociraptor credentials." >&2
    exit 1
fi

# Resolve VELOCIRAPTOR_API_KEY to absolute path if it's relative
# This ensures the same .env works on both the macOS host and inside the Linux container
if [[ "${VELOCIRAPTOR_API_KEY:-}" != /* ]]; then
    export VELOCIRAPTOR_API_KEY="$SCRIPT_DIR/${VELOCIRAPTOR_API_KEY:-api.config.yaml}"
fi

if [[ ! -f "$VELOCIRAPTOR_API_KEY" ]]; then
    echo "[velociraptor-mcp] ERROR: api.config.yaml not found at $VELOCIRAPTOR_API_KEY" >&2
    echo "[velociraptor-mcp] Copy your Velociraptor api.config.yaml into the velociraptor-mcp/ directory." >&2
    exit 1
fi

if _is_native_exec "$LOCAL_MCP"; then
    exec "$LOCAL_MCP"
elif [[ -x "$SYSTEM_MCP" ]]; then
    exec "$SYSTEM_MCP"
else
    echo "[velociraptor-mcp] ERROR: velociraptor-mcp-server not found." >&2
    echo "[velociraptor-mcp]   In a container: rebuild the image (container/build.sh)" >&2
    echo "[velociraptor-mcp]   On the host: run velociraptor-mcp/setup.sh" >&2
    exit 1
fi
