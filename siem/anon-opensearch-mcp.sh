#!/usr/bin/env bash
# Anonymizing OpenSearch MCP proxy for NanoClaw
#
# Wraps opensearch-mcp-server and anonymizes tool results before they reach
# the cloud model. Sensitive field values are replaced with consistent tokens
# (USER_1, HOST_1, IP_INT_1, etc.). A built-in `deanonymize` tool reverses
# the substitution for report writing.
#
# Field definitions live in anon_proxy/fields.yaml — git pull to get updates.
# Token map is persisted at /workspace/group/session_tokens.json.
#
# This script is called by Claude Code as the MCP server command.
# Do not run it directly — start NanoClaw normally.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_SCRIPT="$SCRIPT_DIR/anon_proxy/anon_proxy.py"

LOCAL_PYTHON="$SCRIPT_DIR/.venv/bin/python3"
SYSTEM_PYTHON="/opt/opensearch-mcp/bin/python3"

# Check if a binary is native to the current OS (handles macOS venv in Linux container)
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

if _is_native_exec "$LOCAL_PYTHON"; then
    # Host: use the siem venv — install pyyaml if not already present
    "$LOCAL_PYTHON" -c "import yaml" 2>/dev/null || \
        "$SCRIPT_DIR/.venv/bin/pip" install --quiet pyyaml >&2
    exec "$LOCAL_PYTHON" "$PROXY_SCRIPT"
elif [[ -x "$SYSTEM_PYTHON" ]]; then
    # Container: use the system opensearch-mcp venv — install pyyaml if needed
    "$SYSTEM_PYTHON" -c "import yaml" 2>/dev/null || \
        /opt/opensearch-mcp/bin/pip install --quiet pyyaml >&2
    exec "$SYSTEM_PYTHON" "$PROXY_SCRIPT"
else
    echo "[anon-opensearch-mcp] ERROR: python3 not found." >&2
    echo "[anon-opensearch-mcp]   In a container: rebuild the image (container/build.sh)" >&2
    echo "[anon-opensearch-mcp]   On the host: run siem/setup.sh" >&2
    exit 1
fi
