#!/usr/bin/env bash
# Install and configure OneCLI for NanoClaw.
#
# Idempotent: safe to re-run. Skips work that's already done.
# Non-destructive: never overwrites existing config without backup.
#
# Exit codes:
#   0 = OneCLI installed, gateway healthy, .env configured
#   1 = install failed (network, missing curl, etc.)
#   2 = gateway did not become healthy after install
#   3 = required prerequisite missing (curl, write access)

set -euo pipefail

ONECLI_PORT="${ONECLI_PORT:-10254}"
ONECLI_URL="http://127.0.0.1:${ONECLI_PORT}"
ENV_FILE="${ENV_FILE:-$(pwd)/.env}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-15}"

log()  { printf '[install-onecli] %s\n' "$*"; }
warn() { printf '[install-onecli] WARN: %s\n' "$*" >&2; }
fail() { printf '[install-onecli] FAIL: %s\n' "$*" >&2; exit "${2:-1}"; }

# --- Phase 0: prerequisites ---

command -v curl >/dev/null || fail "curl not in PATH — install curl first" 3
command -v sh   >/dev/null || fail "sh not in PATH"                        3

# Add ~/.local/bin to PATH for the rest of this script (OneCLI installs there)
export PATH="$HOME/.local/bin:$PATH"

# --- Phase 1: install gateway + CLI if missing ---

if command -v onecli >/dev/null && curl -sf "$ONECLI_URL/health" >/dev/null 2>&1; then
  log "OneCLI already installed and gateway healthy at $ONECLI_URL"
  ALREADY_INSTALLED=1
else
  ALREADY_INSTALLED=0

  if ! command -v onecli >/dev/null; then
    log "installing OneCLI gateway..."
    curl -fsSL onecli.sh/install | sh || fail "gateway install failed" 1

    log "installing OneCLI CLI..."
    curl -fsSL onecli.sh/cli/install | sh || fail "CLI install failed" 1
  else
    log "OneCLI binaries present but gateway not responding — attempting start"
    onecli start >/dev/null 2>&1 || true
  fi

  # Re-export PATH in case installer just dropped binaries into ~/.local/bin
  export PATH="$HOME/.local/bin:$PATH"
  command -v onecli >/dev/null || fail "onecli still not in PATH after install — check installer output" 1
fi

# --- Phase 2: persist ~/.local/bin in shell rc files ---

for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
  [ -f "$rc" ] || continue
  if ! grep -q '\.local/bin' "$rc" 2>/dev/null; then
    log "adding ~/.local/bin to PATH in $rc"
    printf '\n# Added by nanoclaw install-onecli.sh\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$rc"
  fi
done

# --- Phase 3: point CLI at local gateway ---

log "configuring CLI: api-host = $ONECLI_URL"
onecli config set api-host "$ONECLI_URL" >/dev/null

# --- Phase 4: wait for gateway health ---

log "waiting up to ${HEALTH_TIMEOUT}s for gateway health..."
i=0
while [ "$i" -lt "$HEALTH_TIMEOUT" ]; do
  if curl -sf "$ONECLI_URL/health" >/dev/null 2>&1; then
    log "gateway healthy at $ONECLI_URL"
    break
  fi
  i=$((i + 1))
  sleep 1
done

if ! curl -sf "$ONECLI_URL/health" >/dev/null 2>&1; then
  warn "gateway not responding at $ONECLI_URL after ${HEALTH_TIMEOUT}s"
  warn "check: ps aux | grep -i onecli | grep -v grep"
  warn "try:   onecli start"
  exit 2
fi

# --- Phase 5: ensure ONECLI_URL in .env ---

if [ -f "$ENV_FILE" ]; then
  if grep -qE '^ONECLI_URL=' "$ENV_FILE"; then
    CURRENT=$(grep -E '^ONECLI_URL=' "$ENV_FILE" | head -1 | cut -d= -f2- | tr -d '"' | tr -d "'")
    if [ "$CURRENT" != "$ONECLI_URL" ]; then
      warn "ONECLI_URL in $ENV_FILE is '$CURRENT' (expected '$ONECLI_URL') — leaving as-is"
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

# --- Phase 6: report ---

echo
log "DONE."
log "  Version:        $(onecli version 2>/dev/null | head -1 || echo unknown)"
log "  Gateway:        $ONECLI_URL (healthy)"
log "  CLI api-host:   $(onecli config get api-host 2>/dev/null || echo '?')"
log "  Secrets count:  $(onecli secrets list --quiet --fields name 2>/dev/null | wc -l | tr -d ' ')"
log "  Already done:   $([ "$ALREADY_INSTALLED" -eq 1 ] && echo yes || echo no)"
echo
log "NEXT:"
log "  Register the Anthropic credential next:"
log "    bash scripts/migrate-anthropic-to-vault.sh"
log "  Or manually:"
log "    onecli secrets create --name Anthropic --type anthropic \\"
log "      --value <your-token> --host-pattern api.anthropic.com"
echo
