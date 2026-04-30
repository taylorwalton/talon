#!/usr/bin/env bash
# OpenSearch MCP Server wrapper for NanoClaw SIEM.
#
# Two execution paths:
#
#   1. Inside the NanoClaw agent container with per-MCP isolation enabled
#      (the default for non-main groups). The wrapper detects an isolated
#      secret file at /etc/mcp-secrets/siem.env and uses sudo to drop privs
#      to mcp-siem (a dedicated non-privileged uid) before sourcing it.
#      The agent (running as node uid) cannot read /etc/mcp-secrets/siem.env.
#
#   2. Legacy / host fallback. When the isolated secret file isn't present
#      (host install with `claude` from siem/ dir, or older container
#      without the isolation pattern), the wrapper falls back to sourcing
#      siem/.env directly from this script's directory.
#
# This script is called by Claude Code as the MCP server command.
# Do not run it directly — use `claude` from the siem/ directory instead.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

LOCAL_MCP="$SCRIPT_DIR/.venv/bin/opensearch-mcp-server"
SYSTEM_MCP="/opt/opensearch-mcp/bin/opensearch-mcp-server"
ISOLATED_ENV="/etc/mcp-secrets/siem.env"

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

# === Container path: isolated mcp-siem uid ===
# /etc/mcp-secrets/siem.env is owned by mcp-siem:mcp-siem with mode 600.
# `sudo -n -u mcp-siem` drops privs (NOPASSWD configured at build time).
# `-E` would preserve env, but we don't need it — the secret is sourced
# AFTER the priv drop, inside the new shell, so only mcp-siem ever reads it.
if [[ -f "$ISOLATED_ENV" ]] && [[ -x "$SYSTEM_MCP" ]] && command -v sudo >/dev/null 2>&1; then
    exec sudo -n -u mcp-siem /bin/bash -c "
        set -a
        source '$ISOLATED_ENV'
        set +a
        exec '$SYSTEM_MCP'
    "
fi

# === Fallback: legacy path (host install, or container without isolation) ===
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
