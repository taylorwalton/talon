#!/bin/bash
# NanoClaw agent container entrypoint.
#
# Runs initially as root when invoked without an explicit --user flag (which is
# how non-main groups now launch — see src/container-runner.ts). As root, it:
#
#   1. Shadows /workspace/project/.env so the agent can't read host secrets
#      (existing main-group behavior, preserved here).
#   2. Sets up per-MCP credential isolation: copies each /workspace/extra/<mcp>/.env
#      into /etc/mcp-secrets/<mcp>.env, chowns to the matching mcp-<mcp> uid,
#      and shadows the original bind-mount so the agent can't read it directly.
#   3. Drops privileges to RUN_UID via setpriv before exec'ing the agent
#      runner. claude-code refuses to start as root.
#
# When the container is started directly as a non-root user (e.g. on Apple
# Container without RUN_UID), the setup steps are skipped — backward compatible
# with deployments that don't yet use the isolation pattern.

set -e

# --- Shadow project-root .env (existing main-group behavior) ---
if [ "$(id -u)" = "0" ] && [ -f /workspace/project/.env ]; then
  mount --bind /dev/null /workspace/project/.env
fi

# --- Per-MCP credential isolation ---
# Container-runner mounts each MCP's secret file(s) to two paths via docker -v:
#
#   /etc/mcp-staging/<id>.<file>  (root-readable copy, parent dir mode 700)
#   /workspace/extra/<dir>/<file> (shadowed by /dev/null — agent sees empty)
#
# We consume the staging copies here, copy each one to /etc/mcp-secrets/<id>.<file>,
# then chown to the MCP-specific uid and chmod 600. Wrappers in
# /workspace/extra/<dir>/ use `sudo -u mcp-<id>` to read at MCP-launch time.
# Sudoers config in /etc/sudoers.d/mcp-isolation grants node passwordless
# access to those uids.
#
# Each entry below is "id" — the directory and any non-.env extra files
# are configured in src/container-runner.ts (ISOLATED_MCPS) and we just
# pick up whatever the staging dir has. Extra-file naming convention:
# /etc/mcp-staging/<id>.<filename> (e.g. velociraptor.api.config.yaml).
if [ "$(id -u)" = "0" ] && [ -d /etc/mcp-secrets ] && [ -d /etc/mcp-staging ]; then
  for mcp_id in siem mysql wazuh copilot shuffle velociraptor; do
    user_name="mcp-${mcp_id}"
    id -u "$user_name" >/dev/null 2>&1 || continue

    # Process every staging file matching <id>.* — covers .env and any
    # extra credential files (e.g. velociraptor.api.config.yaml).
    # Use [ -e ] to guard against the literal pattern when glob has no match.
    for staging in /etc/mcp-staging/"${mcp_id}".*; do
      [ -e "$staging" ] || continue
      basename=$(basename "$staging")
      dst="/etc/mcp-secrets/${basename}"
      cp "$staging" "$dst"
      chown "${user_name}:${user_name}" "$dst"
      chmod 600 "$dst"
    done
  done
fi

# --- Compile agent-runner ---
cd /app && npx tsc --outDir /tmp/dist 2>&1 >&2
ln -s /app/node_modules /tmp/dist/node_modules
chmod -R a-w /tmp/dist

# --- Capture stdin (input JSON) ---
cat > /tmp/input.json

# --- Drop privileges if running as root ---
if [ "$(id -u)" = "0" ] && [ -n "$RUN_UID" ]; then
  chown "$RUN_UID:$RUN_GID" /tmp/input.json /tmp/dist
  exec setpriv --reuid="$RUN_UID" --regid="$RUN_GID" --clear-groups -- \
    node /tmp/dist/index.js < /tmp/input.json
fi

exec node /tmp/dist/index.js < /tmp/input.json
