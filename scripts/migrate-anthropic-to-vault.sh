#!/usr/bin/env bash
# Migrate the Anthropic credential from .env to the OneCLI Vault.
#
# Default behavior (safe):
#   - Reads CLAUDE_CODE_OAUTH_TOKEN (preferred) or ANTHROPIC_API_KEY from .env
#   - Registers it in OneCLI Vault as type=anthropic, host=api.anthropic.com
#   - Leaves .env untouched so you can verify before stripping
#
# With --strip-env:
#   - Also backs up .env and replaces the credential line with a comment.
#   - Required to fully remove the raw token from disk.
#
# Idempotent: re-running detects the existing Vault secret and skips create.
#
# Exit codes:
#   0 = secret registered (and optionally stripped from .env)
#   1 = preflight failed (no onecli, no .env, no token, gateway down)
#   2 = secret create call failed
#   3 = python3 missing (required for JSON parsing)

set -euo pipefail

ENV_FILE="${ENV_FILE:-$(pwd)/.env}"
SECRET_NAME="${SECRET_NAME:-Anthropic}"
HOST_PATTERN="${HOST_PATTERN:-api.anthropic.com}"
STRIP_ENV=0

for arg in "$@"; do
  case "$arg" in
    --strip-env) STRIP_ENV=1 ;;
    -h|--help)
      sed -n '2,/^$/p' "$0" | sed 's/^# //;s/^#//'
      exit 0
      ;;
    *) echo "unknown arg: $arg" >&2; exit 1 ;;
  esac
done

log()  { printf '[migrate-anthropic] %s\n' "$*"; }
warn() { printf '[migrate-anthropic] WARN: %s\n' "$*" >&2; }
fail() { printf '[migrate-anthropic] FAIL: %s\n' "$*" >&2; exit "${2:-1}"; }

# --- Phase 0: prerequisites ---

command -v onecli  >/dev/null || fail "onecli not in PATH — run scripts/install-onecli.sh first" 1
command -v curl    >/dev/null || fail "curl not in PATH" 1
command -v python3 >/dev/null || fail "python3 required for JSON parsing — apt install python3" 3
[ -f "$ENV_FILE" ] || fail ".env not found at $ENV_FILE — run from your nanoclaw install dir" 1

# Read ONECLI_URL from .env or env
ONECLI_URL="${ONECLI_URL:-}"
if [ -z "$ONECLI_URL" ]; then
  ONECLI_URL=$(grep -E '^ONECLI_URL=' "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"' | tr -d "'" || true)
fi
[ -n "$ONECLI_URL" ] || fail "ONECLI_URL not set in .env — run install-onecli.sh first" 1

curl -sf -m 5 "${ONECLI_URL}/api/health" >/dev/null \
  || fail "OneCLI gateway not healthy at $ONECLI_URL" 1
log "OneCLI gateway healthy at $ONECLI_URL"

# --- Phase 1: detect the Anthropic credential in .env ---

get_env_value() {
  # Returns the value (or empty) without failing when the var is missing.
  # set -eo pipefail would otherwise kill the script on a non-matching grep.
  local raw
  raw=$( { grep -E "^${1}=" "$ENV_FILE" 2>/dev/null || true; } | head -1 | cut -d= -f2- || true)
  printf '%s' "$raw" | sed -e 's/^["'"'"']//' -e 's/["'"'"']$//'
}

TOKEN_OAUTH=$(get_env_value CLAUDE_CODE_OAUTH_TOKEN)
TOKEN_API=$(get_env_value ANTHROPIC_API_KEY)
TOKEN_AUTH=$(get_env_value ANTHROPIC_AUTH_TOKEN)

if [ -n "$TOKEN_OAUTH" ]; then
  TOKEN="$TOKEN_OAUTH"
  TOKEN_VAR="CLAUDE_CODE_OAUTH_TOKEN"
elif [ -n "$TOKEN_API" ]; then
  TOKEN="$TOKEN_API"
  TOKEN_VAR="ANTHROPIC_API_KEY"
elif [ -n "$TOKEN_AUTH" ]; then
  TOKEN="$TOKEN_AUTH"
  TOKEN_VAR="ANTHROPIC_AUTH_TOKEN"
else
  fail "No Anthropic credential found in $ENV_FILE (looked for CLAUDE_CODE_OAUTH_TOKEN, ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN)" 1
fi

# Mask token for logging — show prefix + length only
TOKEN_MASK="${TOKEN:0:14}…(len=${#TOKEN})"
log "found $TOKEN_VAR in .env: $TOKEN_MASK"

# --- Phase 2: idempotency check — does the secret already exist? ---

EXISTING_ID=$(curl -sf -m 5 "${ONECLI_URL}/api/secrets" 2>/dev/null | python3 -c "
import sys, json
try:
  data = json.load(sys.stdin)
  if isinstance(data, dict): data = data.get('data', [])
  for s in data:
    if s.get('name') == '$SECRET_NAME' and s.get('type') == 'anthropic':
      print(s.get('id', ''))
      break
except Exception:
  pass
" 2>/dev/null || echo "")

if [ -n "$EXISTING_ID" ]; then
  log "Vault secret '$SECRET_NAME' (anthropic) already exists — id=$EXISTING_ID"
  log "skipping create. To replace, delete first: onecli secrets delete --id $EXISTING_ID"
  SECRET_ID="$EXISTING_ID"
else
  log "registering '$SECRET_NAME' in Vault (type=anthropic, host=$HOST_PATTERN)"
  if onecli secrets create \
       --name "$SECRET_NAME" \
       --type anthropic \
       --value "$TOKEN" \
       --host-pattern "$HOST_PATTERN" >/dev/null 2>&1; then
    log "secret registered successfully"
    # Re-fetch to get the new ID
    SECRET_ID=$(curl -sf -m 5 "${ONECLI_URL}/api/secrets" 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
if isinstance(data, dict): data = data.get('data', [])
for s in data:
  if s.get('name') == '$SECRET_NAME' and s.get('type') == 'anthropic':
    print(s.get('id', ''))
    break
" 2>/dev/null || echo "")
  else
    fail "onecli secrets create failed — try manually with -v output to debug" 2
  fi
fi

# --- Phase 2.5: assign secret to all detected agents ---
#
# OneCLI's "all" secretMode does NOT auto-include secrets on injection
# (verified empirically against v1.18.6). Each secret must be explicitly
# assigned to each agent that should be able to use it. Doing so flips
# the agent into "selective" mode automatically.
#
# Uses `onecli agents set-secrets` which REPLACES the list, so we
# fetch current assignments first and append the new secret if missing.

assign_secret_to_agent() {
  local agent_id=$1 agent_label=$2 secret_id=$3
  # Fetch current secret IDs assigned to this agent
  local current
  current=$(onecli agents secrets --id "$agent_id" 2>/dev/null | python3 -c "
import sys, json
try:
  d = json.load(sys.stdin)
  if isinstance(d, dict): d = d.get('data', [])
  print(','.join(d))
except Exception:
  print('')
" 2>/dev/null || echo "")

  # Already assigned?
  case ",$current," in
    *",$secret_id,"*) log "  agent '$agent_label': already assigned"; return 0 ;;
  esac

  # Build new list (append)
  local new_list
  if [ -z "$current" ]; then
    new_list="$secret_id"
  else
    new_list="${current},${secret_id}"
  fi

  if onecli agents set-secrets --id "$agent_id" --secret-ids "$new_list" >/dev/null 2>&1; then
    log "  agent '$agent_label': assigned"
  else
    warn "  agent '$agent_label': set-secrets failed"
  fi
}

if [ -n "$SECRET_ID" ]; then
  log "assigning secret to all agents..."
  AGENTS_JSON=$(curl -sf -m 5 "${ONECLI_URL}/api/agents" 2>/dev/null || echo '[]')
  printf '%s' "$AGENTS_JSON" | python3 -c "
import sys, json
d = json.load(sys.stdin)
if isinstance(d, dict): d = d.get('data', [])
for a in d:
  print(a.get('id', '') + '\t' + a.get('identifier', '?'))
" 2>/dev/null | while IFS=$'\t' read -r aid aname; do
    [ -n "$aid" ] && assign_secret_to_agent "$aid" "$aname" "$SECRET_ID"
  done
else
  warn "could not determine secret ID — skipping agent assignment"
fi

# --- Phase 3: optionally strip the cred from .env ---

if [ "$STRIP_ENV" -eq 1 ]; then
  BACKUP_FILE="$ENV_FILE.pre-vault.$(date +%Y%m%d-%H%M%S)"
  cp -p "$ENV_FILE" "$BACKUP_FILE"
  log "backed up .env -> $BACKUP_FILE"

  STAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  # Use a sed-safe delimiter (|) since tokens may contain /
  sed -i -E "s|^${TOKEN_VAR}=.*|# ${TOKEN_VAR} migrated to OneCLI Vault on ${STAMP}|" "$ENV_FILE"
  log "removed $TOKEN_VAR line from $ENV_FILE"
else
  warn "$TOKEN_VAR is still in $ENV_FILE — re-run with --strip-env to remove it"
  warn "(safe to leave for now; OneCLI takes precedence when reachable)"
fi

# --- Phase 4: report + verify instructions ---

echo
log "DONE."
log "  Vault secret:   $SECRET_NAME (anthropic, host=$HOST_PATTERN)"
log "  .env action:    $([ "$STRIP_ENV" -eq 1 ] && echo "$TOKEN_VAR removed (backup at $(basename "${BACKUP_FILE:-?}"))" || echo "left in place")"
echo
log "NEXT — restart Talon and verify the Vault path is being used:"
echo
log "  Linux:    sudo systemctl restart talon"
log "  macOS:    launchctl kickstart -k gui/\$(id -u)/com.nanoclaw"
echo
log "After restart, check the logs:"
log "  grep -E 'OneCLI gateway|Injecting' \$(pwd)/logs/talon.log | tail -10"
echo
log "  EXPECT:    'OneCLI gateway config applied'"
log "  NOT:       'Injecting CLAUDE_CODE_OAUTH_TOKEN into container'"
echo

if [ "$STRIP_ENV" -eq 0 ]; then
cat <<EOF
Once verified, strip the raw token from .env:
  bash scripts/migrate-anthropic-to-vault.sh --strip-env

ROLLBACK (if anything breaks):
  onecli secrets delete --id <id from: onecli secrets list>
  sudo systemctl restart talon

EOF
else
cat <<EOF
ROLLBACK (if anything breaks):
  cp '$BACKUP_FILE' '$ENV_FILE'
  onecli secrets delete --id <id from: onecli secrets list>
  sudo systemctl restart talon

EOF
fi
