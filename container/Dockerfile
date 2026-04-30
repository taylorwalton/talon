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

# pymysql lives in a venv owned by mcp-mysql (mode 700) so the agent
# (node uid) cannot import it. The /usr/local/bin/mysql-query wrapper
# (installed below) sudos to mcp-mysql, sources /etc/mcp-secrets/mysql.env,
# and runs the python script — agent gets JSON results, never sees creds.
# See /workspace/extra/mysql/CLAUDE.md for the doctrine on when to use this
# vs. the mcp__mysql__* tools.
#
# The mcp-mysql user is created later in the per-MCP isolation block; we
# install pymysql + helper scripts here but defer chown until after the
# user exists.
RUN python3 -m venv /opt/mysql-tools \
    && /opt/mysql-tools/bin/pip install --quiet pymysql \
    && mkdir -p /opt/mysql-tools/lib

COPY mysql-tools/mysql_query.py /opt/mysql-tools/lib/mysql_query.py
COPY mysql-tools/mysql-query /usr/local/bin/mysql-query
RUN chmod 0755 /usr/local/bin/mysql-query

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
    && useradd -r -u 2002 -s /usr/sbin/nologin mcp-mysql \
    && useradd -r -u 2003 -s /usr/sbin/nologin mcp-wazuh \
    && useradd -r -u 2004 -s /usr/sbin/nologin mcp-copilot \
    && useradd -r -u 2005 -s /usr/sbin/nologin mcp-shuffle \
    && useradd -r -u 2006 -s /usr/sbin/nologin mcp-velociraptor \
    # node may sudo to any mcp-* user without password
    && mkdir -p /etc/sudoers.d \
    && echo 'node ALL=(mcp-siem,mcp-mysql,mcp-wazuh,mcp-copilot,mcp-shuffle,mcp-velociraptor) NOPASSWD: ALL' > /etc/sudoers.d/mcp-isolation \
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
    && chmod 0700 /etc/mcp-staging \
    # Lock down /opt/mysql-tools (pymysql venv + mysql_query.py) to
    # mcp-mysql only. Agent (node) cannot list, enter, or import from
    # this dir. The /usr/local/bin/mysql-query wrapper sudos to mcp-mysql
    # to use it. chmod -R go-rwx leaves owner perms intact while removing
    # all access for group + other.
    && chown -R mcp-mysql:mcp-mysql /opt/mysql-tools \
    && chmod -R go-rwx /opt/mysql-tools

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
