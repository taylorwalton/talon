# NanoClaw Agent Container
# Runs Claude Agent SDK in isolated Linux VM with browser automation

FROM node:22-slim

# Install system dependencies for Chromium
RUN apt-get update && apt-get install -y \
    chromium \
    fonts-liberation \
    fonts-noto-color-emoji \
    libgbm1 \
    libnss3 \
    libatk-bridge2.0-0 \
    libgtk-3-0 \
    libx11-xcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libasound2 \
    libpangocairo-1.0-0 \
    libcups2 \
    libdrm2 \
    libxshmfence1 \
    curl \
    git \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Pre-install pymysql system-wide so the agent can do multi-query batched
# lookups via Bash without re-running `pip install` on every container boot.
# The agent prefers Bash + pymysql for cross-table customer profiles where a
# single MySQL MCP call would balloon into 5+ round trips. See
# /workspace/extra/mysql/CLAUDE.md for the tool-selection rule.
RUN python3 -m pip install --break-system-packages --quiet pymysql

# Install opensearch-mcp-server into a system venv (used by the SIEM MCP wrapper and anon proxy)
RUN python3 -m venv /opt/opensearch-mcp \
    && /opt/opensearch-mcp/bin/pip install --quiet opensearch-mcp-server pyyaml

# Install copilot-mcp-server into a system venv (used by the CoPilot MCP wrapper)
RUN python3 -m venv /opt/copilot-mcp \
    && /opt/copilot-mcp/bin/pip install --quiet \
       "git+https://github.com/socfortress/copilot-mcp-server.git"

# Install wazuh-mcp-server into a system venv (used by the Wazuh MCP wrapper)
RUN python3 -m venv /opt/wazuh-mcp \
    && /opt/wazuh-mcp/bin/pip install --quiet \
       "git+https://github.com/socfortress/wazuh-mcp-server.git"

# Install velociraptor-mcp-server into a system venv (used by the Velociraptor MCP wrapper)
RUN python3 -m venv /opt/velociraptor-mcp \
    && /opt/velociraptor-mcp/bin/pip install --quiet \
       "git+https://github.com/socfortress/velociraptor-mcp-server.git"

# Install shuffle-mcp-server into a system venv (used by the Shuffle MCP wrapper)
# Gives the agent interactive access to Shuffle's 3,000+ apps catalog —
# RunAppAgentTool / GetExecutionResultTool for natural-language driving of
# any authenticated app, plus AuthenticateTool / GetAppsTool for discovery.
# This is separate from CoPilot's notification-dispatch path: that's a
# fire-and-record server-to-server call; this is for mid-investigation
# tool use (e.g. "look up this user's email via Outlook search").
RUN python3 -m venv /opt/shuffle-mcp \
    && /opt/shuffle-mcp/bin/pip install --quiet \
       "git+https://github.com/socfortress/shuffle-mcp-server.git"

# Install mempalace + chromadb into a system venv (used by the MemPalace MCP wrapper)
# chromadb is large — this layer is cached after the first build
RUN python3 -m venv /opt/mempalace \
    && /opt/mempalace/bin/pip install --quiet \
       "chromadb>=0.5.0,<0.7" "pyyaml>=6.0" mempalace

# Set Chromium path for agent-browser
ENV AGENT_BROWSER_EXECUTABLE_PATH=/usr/bin/chromium
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium

# Install agent-browser, claude-code, and MySQL MCP server globally
RUN npm install -g agent-browser @anthropic-ai/claude-code@2.1.91 @benborla29/mcp-server-mysql

# --- Per-MCP credential isolation ---
# Each backend MCP can run as a dedicated non-privileged user via sudo. The
# entrypoint copies the MCP's .env into /etc/mcp-secrets/<mcp>.env (mode 600,
# owned by the matching mcp-* uid), then shadows the original bind-mount so
# the agent (running as node uid) can't read it. The wrapper in
# /workspace/extra/<mcp>/ uses `sudo -u mcp-<mcp>` to read the secret at
# MCP-launch time.
RUN apt-get update && apt-get install -y --no-install-recommends sudo \
    && rm -rf /var/lib/apt/lists/* \
    # Per-MCP non-privileged users (no shell, no home, no login)
    && useradd -r -u 2001 -s /usr/sbin/nologin mcp-siem \
    # node may sudo to any mcp-* user without password
    && mkdir -p /etc/sudoers.d \
    && echo 'node ALL=(mcp-siem) NOPASSWD: ALL' > /etc/sudoers.d/mcp-isolation \
    && chmod 0440 /etc/sudoers.d/mcp-isolation \
    # Per-MCP secrets directory: traversable but not listable
    && mkdir -p /etc/mcp-secrets \
    && chown root:root /etc/mcp-secrets \
    && chmod 0711 /etc/mcp-secrets \
    # Staging directory for the read-only host bind mount of the original
    # .env (so entrypoint can copy it before chowning to mcp-* uid).
    # Mode 700 means no other user can list or traverse this dir.
    && mkdir -p /etc/mcp-staging \
    && chown root:root /etc/mcp-staging \
    && chmod 0700 /etc/mcp-staging

# Create app directory
WORKDIR /app

# Copy package files first for better caching
COPY agent-runner/package*.json ./

# Install dependencies
RUN npm install

# Copy source code
COPY agent-runner/ ./

# Build TypeScript
RUN npm run build

# Create workspace directories
RUN mkdir -p /workspace/group /workspace/global /workspace/extra /workspace/ipc/messages /workspace/ipc/tasks /workspace/ipc/input

# Entrypoint script: handles secret-shadowing, per-MCP isolation, and
# privilege drop before exec'ing the agent. Source: container/entrypoint.sh
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Set ownership to node user (non-root) for writable directories
RUN chown -R node:node /workspace && chmod 777 /home/node

# Set working directory to group workspace
WORKDIR /workspace/group

# Entry point reads JSON from stdin, outputs JSON to stdout
ENTRYPOINT ["/app/entrypoint.sh"]
