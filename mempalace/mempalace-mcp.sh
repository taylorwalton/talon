#!/usr/bin/env bash
# MemPalace MCP server wrapper for Talon
#
# Provides the SOC agent with persistent semantic memory — past alert
# investigations, asset metadata, false positive records, and IOC history
# are stored in a local ChromaDB + SQLite knowledge graph and retrieved
# via semantic search at the start of each investigation.
#
# Palace data is stored at mempalace-data/palace/ (mounted read-write into
# the container). This directory is gitignored and persists across restarts.
#
# This script is called by Claude Code as the MCP server command.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load optional .env (palace path override, etc.)
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/.env"
    set +a
fi

# Palace data directory — persistent, read-write, outside the config dir
# Inside container: /workspace/extra/mempalace-data/palace
# On host:         mempalace-data/palace (relative to project root)
PALACE_PATH="${MEMPALACE_PALACE_PATH:-/workspace/extra/mempalace-data/palace}"
export MEMPALACE_PALACE_PATH="$PALACE_PATH"

# Ensure the palace directory exists before starting the server
mkdir -p "$PALACE_PATH"

LOCAL_PYTHON="$SCRIPT_DIR/.venv/bin/python3"
SYSTEM_PYTHON="/opt/mempalace/bin/python3"

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
    PYTHON="$LOCAL_PYTHON"
elif [[ -x "$SYSTEM_PYTHON" ]]; then
    PYTHON="$SYSTEM_PYTHON"
else
    echo "[mempalace-mcp] ERROR: python3 not found." >&2
    echo "[mempalace-mcp]   In a container: rebuild the image (container/build.sh)" >&2
    echo "[mempalace-mcp]   On the host: run mempalace/setup.sh" >&2
    exit 1
fi

# Auto-initialize the palace on first run.
# Creates the ChromaDB collection and SQLite knowledge graph tables so the
# MCP server can immediately read and write without a separate init step.
SENTINEL="$PALACE_PATH/.initialized"
if [[ ! -f "$SENTINEL" ]]; then
    echo "[mempalace-mcp] Initializing palace at $PALACE_PATH..." >&2
    "$PYTHON" - <<'PYEOF'
import os, sys
palace_path = os.environ.get("MEMPALACE_PALACE_PATH", "")
try:
    # Import and instantiate Palace — this creates the ChromaDB collection
    # and SQLite tables if they don't already exist.
    from mempalace.palace import Palace
    Palace()
    print(f"[mempalace-mcp] Palace initialized successfully", file=sys.stderr)
except Exception as e:
    # Non-fatal: the MCP server may still start and handle init errors itself
    print(f"[mempalace-mcp] Warning: init returned: {e}", file=sys.stderr)
PYEOF
    touch "$SENTINEL"
fi

exec "$PYTHON" -m mempalace.mcp_server
