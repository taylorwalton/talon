#!/usr/bin/env bash
# Install and configure OneCLI for NanoClaw.
#
# Idempotent: safe to re-run. Detects existing install and skips work.
# Non-destructive: never overwrites existing .env values without warning.
#
# Phases:
#   1. Install OneCLI gateway + CLI binary if missing
#   2. Detect the reachable gateway URL (loopback or Docker bridge)
#   3. Persist ONECLI_URL in .env
#   4. If ONECLI_API_KEY available (env or .env), run `onecli auth login`
#   5. If no API key, print bootstrap instructions and exit cleanly
#
# Exit codes:
#   0 = OneCLI installed; auth complete OR awaiting manual API key step
#   1 = install failed (network, missing curl, etc.)
#   2 = gateway did not become healthy after install
#   3 = required prerequisite missing (curl, write access)

set -euo pipefail

ONECLI_PORT="${ONECLI_PORT:-10254}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-30}"
ENV_FILE="${ENV_FILE:-$(pwd)/.env}"

log()  { printf '[install-onecli] %s\n' "$*"; }
warn() { printf '[install-onecli] WARN: %s\n' "$*" >&2; }
fail() { printf '[install-onecli] FAIL: %s\n' "$*" >&2; exit "${2:-1}"; }

# --- Phase 0: prerequisites ---

command -v curl >/dev/null || fail "curl not in PATH — install curl first" 3
command -v sh   >/dev/null || fail "sh not in PATH"                        3

# Add ~/.local/bin to PATH for the rest of this script (CLI installs there on some systems)
export PATH="$HOME/.local/bin:$PATH"

# --- Phase 1: install gateway + CLI if missing ---

ALREADY_INSTALLED=0
if command -v onecli >/dev/null 2>&1; then
  log "OneCLI binary present: $(command -v onecli)"
  ALREADY_INSTALLED=1
else
  log "installing OneCLI gateway..."
  curl -fsSL onecli.sh/install | sh || fail "gateway install failed" 1

  log "installing OneCLI CLI..."
  curl -fsSL onecli.sh/cli/install | sh || fail "CLI install failed" 1

  # Re-export PATH in case installer just dropped binary in ~/.local/bin
  export PATH="$HOME/.local/bin:$PATH"
  command -v onecli >/dev/null 2>&1 || fail "onecli still not in PATH after install" 1
fi

# --- Phase 2: persist ~/.local/bin in shell rc files (only if CLI lives there) ---

if [ -x "$HOME/.local/bin/onecli" ]; then
  for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    [ -f "$rc" ] || continue
    if ! grep -q '\.local/bin' "$rc" 2>/dev/null; then
      log "adding ~/.local/bin to PATH in $rc"
      printf '\n# Added by nanoclaw install-onecli.sh\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$rc"
    fi
  done
fi

# --- Phase 3: detect reachable gateway URL ---

# Build candidate list. Docker-bridge IP first when present (new containerized
# OneCLI binds to docker0 by default on Linux).
CANDIDATES=()
if [ -d /sys/class/net/docker0 ]; then
  BRIDGE_IP=$(ip -4 addr show docker0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
  [ -n "${BRIDGE_IP:-}" ] && CANDIDATES+=("http://${BRIDGE_IP}:${ONECLI_PORT}")
fi
CANDIDATES+=("http://127.0.0.1:${ONECLI_PORT}")
CANDIDATES+=("http://localhost:${ONECLI_PORT}")

probe_health() {
  # OneCLI 1.5+ uses /api/health; fall back to /health for older versions.
  curl -sf -m 2 "${1}/api/health" >/dev/null 2>&1 || \
    curl -sf -m 2 "${1}/health" >/dev/null 2>&1
}

log "probing gateway candidates: ${CANDIDATES[*]}"
ONECLI_URL=""
for i in $(seq 1 "$HEALTH_TIMEOUT"); do
  for u in "${CANDIDATES[@]}"; do
    if probe_health "$u"; then
      ONECLI_URL="$u"
      break 2
    fi
  done
  sleep 1
done

if [ -z "$ONECLI_URL" ]; then
  warn "no reachable gateway found on any of: ${CANDIDATES[*]}"
  warn "check: docker ps | grep onecli"
  warn "check: ps aux | grep -i onecli | grep -v grep"
  exit 2
fi

log "gateway healthy at $ONECLI_URL"

# --- Phase 4: configure CLI to point at this URL ---

log "configuring CLI: api-host = $ONECLI_URL"
onecli config set api-host "$ONECLI_URL" >/dev/null 2>&1 || \
  warn "onecli config set api-host failed (may not be needed in this CLI version)"

# --- Phase 5: persist ONECLI_URL in .env ---

if [ -f "$ENV_FILE" ]; then
  if grep -qE '^ONECLI_URL=' "$ENV_FILE"; then
    CURRENT=$(grep -E '^ONECLI_URL=' "$ENV_FILE" | head -1 | cut -d= -f2- | tr -d '"' | tr -d "'")
    if [ "$CURRENT" != "$ONECLI_URL" ]; then
      warn "ONECLI_URL in $ENV_FILE is '$CURRENT' (detected '$ONECLI_URL') — leaving as-is"
      warn "to switch, edit $ENV_FILE manually"
    else
      log "ONECLI_URL already set in $ENV_FILE"
    fi
  else
    log "appending ONECLI_URL=$ONECLI_URL to $ENV_FILE"
    printf '\n# OneCLI gateway URL — added by install-onecli.sh\nONECLI_URL=%s\n' "$ONECLI_URL" >> "$ENV_FILE"
  fi
else
  warn "$ENV_FILE not found — skipping .env update (run from your nanoclaw install dir)"
fi

# --- Phase 6: API key bootstrap ---

# Try env var first, then .env
ONECLI_API_KEY="${ONECLI_API_KEY:-}"
if [ -z "$ONECLI_API_KEY" ] && [ -f "$ENV_FILE" ]; then
  ONECLI_API_KEY=$(grep -E '^ONECLI_API_KEY=' "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"' | tr -d "'" || true)
fi

if [ -n "$ONECLI_API_KEY" ]; then
  log "API key present — running auth login"
  if onecli auth login --api-key "$ONECLI_API_KEY" >/dev/null 2>&1; then
    log "auth login succeeded"
  else
    warn "auth login failed — check key or try manually: onecli auth login --api-key <key>"
  fi

  # Persist to .env if not already there
  if [ -f "$ENV_FILE" ] && ! grep -qE '^ONECLI_API_KEY=' "$ENV_FILE"; then
    log "appending ONECLI_API_KEY to $ENV_FILE"
    printf 'ONECLI_API_KEY=%s\n' "$ONECLI_API_KEY" >> "$ENV_FILE"
  fi

  AUTH_STATUS="configured"
else
  AUTH_STATUS="awaiting API key"
fi

# --- Phase 7: report ---

echo
log "DONE."
log "  Gateway:        $ONECLI_URL (healthy)"
log "  CLI version:    $(onecli version 2>/dev/null | grep -oE '"version"[^,]*' | head -1 | tr -d '"' | sed 's/version://;s/[ ]//g' || echo unknown)"
log "  Already done:   $([ "$ALREADY_INSTALLED" -eq 1 ] && echo yes || echo no)"
log "  Auth status:    $AUTH_STATUS"
echo

if [ "$AUTH_STATUS" = "awaiting API key" ]; then
  cat <<EOF
NEXT STEP — get your OneCLI agent access token.

OneCLI default mode is single-user, no signup required. Open the dashboard,
create an agent, and copy its access token.

  1. OPEN THE DASHBOARD:

     a) SSH tunnel from your laptop (recommended for headless servers):
          ssh -L 10254:$(echo "$ONECLI_URL" | sed -E 's#https?://##') root@<this-host>
        then open in your browser: http://localhost:10254

     b) Expose to LAN by rebinding ports to 0.0.0.0:
          sudo sed -i 's/172.17.0.1:/0.0.0.0:/g' /root/.onecli/docker-compose.yml
          docker compose -p onecli -f /root/.onecli/docker-compose.yml up -d
        then open: http://<this-host-ip>:10254

  2. CREATE AN AGENT in the dashboard (or via CLI once authed):
       Name: nanoclaw            (or per-group: 'main', 'copilot', etc.)
       Identifier: nanoclaw      (lowercase, hyphens — must match group folder)

  3. COPY THE AGENT ACCESS TOKEN (starts with 'oc_agent_').

  4. RE-RUN THIS SCRIPT with the token:

       ONECLI_API_KEY=oc_agent_xxxxx bash scripts/install-onecli.sh

     Or add ONECLI_API_KEY to $ENV_FILE manually and re-run.

  REFERENCE: https://www.onecli.sh/docs/guides/nanoclaw

EOF
  exit 0
fi

cat <<EOF
NEXT STEP — register your Anthropic credential:

  Run the next script:
    bash scripts/migrate-anthropic-to-vault.sh

  Or manually:
    onecli secrets create --name Anthropic --type anthropic \\
      --value <your-token> --host-pattern api.anthropic.com

EOF
