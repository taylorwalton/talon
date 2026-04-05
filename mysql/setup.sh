#!/usr/bin/env bash
# NanoClaw MySQL MCP — one-time setup
#
# What this does:
#   1. Installs @benborla29/mcp-server-mysql globally
#   2. Creates .env from .env.example if not already present
#
# After running this, edit .env with your MySQL credentials.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

echo "=== NanoClaw MySQL MCP Setup ==="
echo ""

# ── Node check ───────────────────────────────────────────────────────────────
if ! command -v node &>/dev/null; then
    echo "ERROR: Node.js is required. Install it from https://nodejs.org" >&2
    exit 1
fi
echo "Node.js $(node --version)  ✓"

# ── Install MCP server ────────────────────────────────────────────────────────
echo "Installing @benborla29/mcp-server-mysql..."
npm install -g @benborla29/mcp-server-mysql
echo "MCP server installed  ✓"

# ── .env ─────────────────────────────────────────────────────────────────────
if [[ ! -f "$ENV_FILE" ]]; then
    cp "$SCRIPT_DIR/.env.example" "$ENV_FILE"
    echo ""
    echo "  Created .env from template."
    echo "  ➜ Edit $ENV_FILE with your MySQL credentials before starting NanoClaw."
    echo ""
else
    echo ".env exists  ✓"
fi

chmod +x "$SCRIPT_DIR/mysql-mcp.sh"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "=== Setup complete! ==="
echo ""
if grep -q "your-username" "$ENV_FILE" 2>/dev/null; then
    echo "Next steps:"
    echo "  1. Edit mysql/.env with your MySQL host, user, password, and database"
    echo "  2. Restart NanoClaw"
else
    echo "Restart NanoClaw to pick up the MySQL MCP server."
fi
echo ""
