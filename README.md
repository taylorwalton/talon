<h1 align="center">

<a href="https://www.socfortress.co"><img src="assets/talon-logo.jpg" alt="Talon" width="400"></a>

Talon

[![Medium](https://img.shields.io/badge/Medium-12100E?style=for-the-badge&logo=medium&logoColor=white)](https://socfortress.medium.com/)
[![YouTube Channel Subscribers](https://img.shields.io/youtube/channel/subscribers/UC4EUQtTxeC8wGrKRafI6pZg)](https://www.youtube.com/@taylorwalton_socfortress/videos)
[![Discord Shield](https://discordapp.com/api/guilds/871419379999469568/widget.png?style=shield)](https://discord.gg/UN3pNBzaEQ)
[![GitHub Sponsors](https://img.shields.io/badge/sponsor-30363D?style=for-the-badge&logo=GitHub-Sponsors&logoColor=#EA4AAA)](https://github.com/sponsors/taylorwalton)

[![Get in Touch](https://img.shields.io/badge/📧%20Get%20in%20Touch-Friendly%20Support%20Awaits!-blue?style=for-the-badge)](https://www.socfortress.co/contact_form.html)

</h1>

<h4 align="center">

Talon is an automated AI SOC analyst built by <a href="https://www.socfortress.co">SOCfortress</a> for the <a href="https://github.com/socfortress/CoPilot">CoPilot</a> stack. It runs as a background service alongside CoPilot — pulling raw events from your Wazuh/OpenSearch SIEM, enriching them with threat intelligence, correlating across your environment, and writing structured investigation reports with severity assessments and recommended actions directly back into CoPilot.

📚 <strong>Docs:</strong> <a href="https://docs.socfortress.co">docs.socfortress.co</a>

</h4>

---

---

## What It Does

- **Automated Tier 2 investigations** — every OPEN alert is investigated end-to-end: SIEM raw event → IOC extraction → VirusTotal / Shodan / AbuseIPDB → MITRE ATT&CK correlation → structured report
- **Two trigger paths** — real-time via `POST /investigate` (CoPilot calls this when an alert is created) and a 15-minute scheduled sweep as a safety net
- **Writes back to CoPilot** — job status, full report, and enriched IOCs are persisted in CoPilot's database via its REST API; no direct database writes
- **Privacy-aware by default** — an anonymizing MCP proxy intercepts raw SIEM events and replaces PII (usernames, hostnames, internal IPs) with session tokens before they reach the cloud model; a built-in `deanonymize` tool restores real values in the final report
- **Optional local LLM analysis** — if [Ollama](https://ollama.com) is running, the agent routes raw event interpretation through a local model instead of the cloud; no config needed if Ollama is on the same host
- **Alert-type prompt templates** — per-alert-type investigation guides (Sysmon Event 1, 3, 7, 11, 22) are loaded automatically based on the alert's `rule.groups` field; add new templates without touching code

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                 CoPilot (FastAPI)                    │
│                                                      │
│  Alert created → POST /investigate ──────────────┐   │
│  GET /status, GET /jobs/:alertId ← Talon HTTP API │   │
│                                                   │   │
│  Write-back API (MCP tools):                      │   │
│    POST /api/ai_analyst/jobs          ←───────────┘   │
│    POST /api/ai_analyst/reports                       │
│    POST /api/ai_analyst/iocs                          │
│  MySQL: ai_analyst_job / report / ioc                 │
└───────────────────────┬───────────────────────────────┘
                        │ read-only MCP        ▲ REST write-back
                        ▼                      │
┌─────────────────────────────────────────────────────┐
│                   Talon (Node.js)                    │
│                                                      │
│  HTTP channel (port 3100)                            │
│    POST /investigate  ← CoPilot triggers this        │
│    POST /message      ← ad-hoc analyst prompts       │
│    GET  /status       ← queue + job overview         │
│    GET  /jobs/:id     ← per-alert report status      │
│    GET  /health                                      │
│                                                      │
│  Scheduled task (every 15 min)                       │
│    Queries MySQL for OPEN alerts with no job row     │
│    Runs full investigation per alert                 │
│                                                      │
│  SOC agent container                                 │
│    groups/copilot/CLAUDE.md  ← investigation flow    │
│    groups/copilot/prompts/   ← per-alert templates   │
└─────────────────────────────────────────────────────┘
         │ MCP tools (read-only)
         ▼
┌────────────────────────────────────────────────────────────┐
│  opensearch-mcp     — raw SIEM queries                     │
│  opensearch_anon    — anonymizing proxy (PII → tokens)     │
│  mysql-mcp          — CoPilot DB (alerts, assets, agents)  │
│  copilot-mcp        — CoPilot REST API write-back          │
│  ollama (optional)  — local LLM for sensitive event data   │
└────────────────────────────────────────────────────────────┘
```

For the full architecture and design decisions, see:
- [docs/COPILOT_INTEGRATION.md](docs/COPILOT_INTEGRATION.md) — trigger paths, MySQL schema, MCP tool reference, implementation roadmap
- [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) — design philosophy and architecture decisions

---

## Privacy & Anonymization

Raw SIEM events contain sensitive data — usernames, internal hostnames, RFC1918 IPs. Talon's anonymizing MCP proxy intercepts all document and search results before they reach the Claude cloud API and replaces known PII fields with consistent session tokens:

| Token | Replaces |
|---|---|
| `USER_1`, `USER_2`, … | Usernames, account names (`data_win_eventdata_user`, etc.) |
| `HOST_1`, `HOST_2`, … | Hostnames, computer names (`agent_name`, etc.) |
| `IP_INT_1`, … | Internal / RFC1918 IP addresses |
| `EMAIL_1`, … | Email addresses |

Security-critical values — file hashes, external IPs, domains, process paths, rule metadata — pass through unchanged so threat intel lookups work normally. Before the final report is written, the agent calls a built-in `deanonymize` tool to restore real names and IPs so the analyst sees accurate output.

Field definitions live in [`siem/anon_proxy/fields.yaml`](siem/anon_proxy/fields.yaml) — add new fields and `git pull` to distribute to all deployments.

See [docs/ANON_PROXY.md](docs/ANON_PROXY.md) for a full walkthrough of the proxy flow.

---

## Local LLM Support (Ollama)

If [Ollama](https://ollama.com) is running on the same host, Talon automatically routes raw event interpretation through a local model rather than the cloud. This keeps the most sensitive step — reading the full raw event and extracting IOCs — entirely on-premises.

The agent checks for Ollama at startup. If it's not running, the investigation continues without it — no errors, no configuration required. See step 8 of the deployment guide below for setup.

---

## Deployment Guide

### Prerequisites

- Docker
- Node.js 20+
- A running OpenSearch / Wazuh SIEM
- A running CoPilot instance (MySQL/MariaDB + FastAPI)
- A [Claude Code](https://claude.ai/download) OAuth token

### 1. Clone and install

```bash
git clone https://github.com/taylorwalton/talon.git talon
cd talon
npm install && npm run build
```

### 2. Get a Claude OAuth token

```bash
claude setup-token
# Copy the sk-ant-oat01-... token that is printed
```

### 3. Create `.env`

```bash
cat > .env <<EOF
CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-...

# Optional: webhook endpoint for the 15-minute SOC alert digest
# WEBHOOK_URL=https://your-endpoint.example.com/talon-digest
# WEBHOOK_SECRET=optional-bearer-token
EOF
```

### 4. Create the mount allowlist

Controls which host directories can be mounted into agent containers. Lives outside the project root so agents cannot modify it:

```bash
mkdir -p ~/.config/nanoclaw
cat > ~/.config/nanoclaw/mount-allowlist.json <<EOF
{
  "allowedRoots": [
    {
      "path": "$(pwd)",
      "allowReadWrite": false,
      "description": "Talon project root"
    }
  ],
  "blockedPatterns": [],
  "nonMainReadOnly": true
}
EOF
```

### 5. Configure SIEM credentials

```bash
cp siem/.env.example siem/.env
# Edit siem/.env — set OPENSEARCH_HOSTS, OPENSEARCH_USERNAME, OPENSEARCH_PASSWORD
```

### 6. Configure MySQL credentials

```bash
bash mysql/setup.sh
# Edit mysql/.env — set MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASS, MYSQL_DB
```

### 7. Configure CoPilot MCP credentials

```bash
bash copilot-mcp/setup.sh
# Edit copilot-mcp/.env — set COPILOT_URL, COPILOT_USERNAME, COPILOT_PASSWORD
```

> **Note:** If CoPilot is on the same host as Talon, use `host.docker.internal` instead of `127.0.0.1`:
> ```
> COPILOT_URL=http://host.docker.internal:5000
> ```

### 8. Configure local LLM analysis (optional)

Talon can route raw SIEM event analysis through an open-source LLM instead of the Claude cloud model. Combined with the anonymizing proxy — which replaces PII with session tokens before any LLM call — this keeps sensitive data interpretation off Anthropic's API entirely.

If no LLM is configured, the agent skips local analysis silently and continues the investigation without it.

There are two ways to run the LLM:

---

#### Option A — Local Ollama (on-premises, best privacy)

Install [Ollama](https://ollama.com) on the same machine as Talon and pull a model:

```bash
ollama pull qwen2.5:7b    # recommended — strong analytical capability
# or: ollama pull mistral:7b
# or: ollama pull llama3.2:3b  (lighter, faster)
```

No `.env` needed — the agent container reaches Ollama automatically via `host.docker.internal:11434`.

**Best for:** clients with an existing GPU server or workstation.

---

#### Option B — RunPod cloud GPU (no hardware required)

[RunPod](https://www.runpod.io) lets you run open-source models on cloud GPUs and pay only for what you use. Because Talon's anonymizing proxy has already replaced PII with tokens before the LLM call, what RunPod sees is desensitised data — not real usernames, hostnames, or internal IPs.

**Recommended: RunPod Serverless** — scales to zero between investigations, so you pay only during active analysis (typically seconds per alert).

1. Create a RunPod account at [runpod.io](https://www.runpod.io)
2. Deploy an Ollama serverless worker using RunPod's template library, or spin up a persistent pod:
   - In the pod config, expose port `11434` via HTTP proxy
   - Your endpoint will be: `https://<pod-id>-11434.proxy.runpod.net`
3. Pull your chosen model inside the pod:
   ```bash
   ollama pull qwen2.5:7b
   ```
4. Point Talon at the RunPod endpoint:
   ```bash
   cp ollama/.env.example ollama/.env
   # Edit ollama/.env:
   OLLAMA_HOST=https://<pod-id>-11434.proxy.runpod.net
   ```

**Best for:** clients without GPU hardware who still want open-source model analysis.

| | Local Ollama | RunPod Serverless | RunPod Persistent Pod |
|---|---|---|---|
| Hardware required | Yes (GPU) | No | No |
| Running cost | $0 (sunk) | Pay per investigation | ~$0.20–0.44/hr |
| Cold start | None | ~30–60s | None |
| Privacy | Best (fully on-prem) | Good (PII already tokenized) | Good (PII already tokenized) |
| Best for | Existing GPU infra | Most clients | High-volume SOCs |

---

### 9. Build the container

```bash
CONTAINER_RUNTIME=docker ./container/build.sh
```

### 10. Start the service

**macOS:**
```bash
sed -e "s|{{NODE_PATH}}|$(which node)|g" \
    -e "s|{{PROJECT_ROOT}}|$(pwd)|g" \
    -e "s|{{HOME}}|$HOME|g" \
    launchd/com.nanoclaw.plist > ~/Library/LaunchAgents/com.nanoclaw.plist
launchctl load ~/Library/LaunchAgents/com.nanoclaw.plist
```

**Linux (system service):**
```bash
mkdir -p logs
cat > /etc/systemd/system/talon.service <<EOF
[Unit]
Description=Talon SOC Analyst
After=network.target

[Service]
Type=simple
ExecStart=$(which node) $(pwd)/dist/index.js
WorkingDirectory=$(pwd)
Restart=always
RestartSec=5
KillMode=process
Environment=HOME=$HOME
Environment=PATH=/usr/local/bin:/usr/bin:/bin:$HOME/.local/bin
StandardOutput=append:$(pwd)/logs/talon.log
StandardError=append:$(pwd)/logs/talon.error.log

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now talon
```

**Linux (user service):**
```bash
mkdir -p ~/.config/systemd/user logs
cat > ~/.config/systemd/user/talon.service <<EOF
[Unit]
Description=Talon SOC Analyst
After=network.target

[Service]
Type=simple
ExecStart=$(which node) $(pwd)/dist/index.js
WorkingDirectory=$(pwd)
Restart=always
RestartSec=5
KillMode=process
Environment=HOME=$HOME
Environment=PATH=/usr/local/bin:/usr/bin:/bin:$HOME/.local/bin
StandardOutput=append:$(pwd)/logs/talon.log
StandardError=append:$(pwd)/logs/talon.error.log

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable --now talon
loginctl enable-linger
```

### 11. Verify

```bash
curl http://localhost:3100/health

# Test SIEM connectivity
curl -s -N -X POST http://localhost:3100/message \
  -H "Content-Type: application/json" \
  -d '{"message": "Check cluster health", "sender": "test"}'

# Test CoPilot MCP connectivity
curl -s -N -X POST http://localhost:3100/message \
  -H "Content-Type: application/json" \
  -d '{"message": "Use the copilot MCP tool to list all customers.", "sender": "test"}'

# Test Ollama (optional — only if installed)
curl -s -N -X POST http://localhost:3100/message \
  -H "Content-Type: application/json" \
  -d '{"message": "List available Ollama models.", "sender": "test"}'
```

---

## Per-Deployment Configuration

| File | Purpose |
|------|---------|
| `siem/.env` | OpenSearch credentials — gitignored |
| `mysql/.env` | CoPilot MySQL credentials — gitignored |
| `copilot-mcp/.env` | CoPilot REST API credentials — gitignored |
| `ollama/.env` | Optional Ollama host override — gitignored, omit if using defaults |
| `.env` | `CLAUDE_CODE_OAUTH_TOKEN`, `WEBHOOK_URL`, `WEBHOOK_SECRET` — gitignored |
| `groups/copilot/CLAUDE.md` | SOC agent identity, known assets, ongoing investigations |
| `groups/copilot/prompts/` | Per-alert-type investigation templates (e.g. `sysmon_event_1.txt`) |
| `siem/anon_proxy/fields.yaml` | PII field definitions for the anonymizing proxy |
| `~/.config/nanoclaw/mount-allowlist.json` | Mount security policy — outside repo, tamper-proof |

Append client-specific context (asset inventory, known-good IP ranges, crown jewel assets, business hours) to the bottom of `groups/copilot/CLAUDE.md`.

---

## Adding Alert-Type Templates

Investigation templates live in `groups/copilot/prompts/`. Each file is a plain-text guide with template variables that the agent fills in at runtime.

| File | Alert type |
|------|-----------|
| `sysmon_event_1.txt` | Process Creation (Sysmon Event 1) |
| `sysmon_event_3.txt` | Network Connection (Event 3) |
| `sysmon_event_7.txt` | Image Load / DLL (Event 7) |
| `sysmon_event_11.txt` | File Create (Event 11) |
| `sysmon_event_22.txt` | DNS Query (Event 22) |

To add a new alert type, create the corresponding `.txt` file — no code changes required. The agent detects the type from `rule.groups` in the raw event and loads the matching template automatically.

---

## Key Source Files

| File | Purpose |
|------|---------|
| `src/index.ts` | Orchestrator: message loop, agent invocation |
| `src/channels/http.ts` | HTTP channel: `/investigate`, `/status`, `/jobs/:id`, `/message` |
| `src/task-scheduler.ts` | 15-minute scheduled alert sweep |
| `src/container-runner.ts` | Spawns agent containers with mounts |
| `groups/copilot/CLAUDE.md` | SOC agent investigation workflow |
| `groups/copilot/.mcp.json` | MCP server registry (opensearch, mysql, copilot, ollama) |
| `siem/anon_proxy/anon_proxy.py` | Anonymizing MCP proxy |
| `siem/anon_proxy/fields.yaml` | PII field definitions (git-pullable) |
| `container/Dockerfile` | Agent container image |

---

## Documentation

| Doc | Contents |
|-----|---------|
| [docs/COPILOT_INTEGRATION.md](docs/COPILOT_INTEGRATION.md) | Full CoPilot integration architecture, MySQL schema, MCP tool reference, implementation roadmap |
| [docs/ANON_PROXY.md](docs/ANON_PROXY.md) | Anonymizing proxy deep-dive: flow, token types, preserved fields, de-anonymization, extending `fields.yaml` |
| [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) | Design philosophy and architecture decisions |
| [docs/SECURITY.md](docs/SECURITY.md) | Container isolation model and security boundaries |

---

## Help

You can reach us on [Discord](https://discord.gg/UN3pNBzaEQ) or by [📧](mailto:info@socfortress.co) if you have any question, issue, or idea!

Check out the full SOCfortress video tutorial series on [![YouTube](https://img.shields.io/badge/YouTube-%23FF0000.svg?style=for-the-badge&logo=YouTube&logoColor=white)](https://www.youtube.com/@taylorwalton_socfortress/videos)

## Sponsoring

If you find this project useful and want to support continued development, consider becoming a sponsor:

[![GitHub Sponsors](https://img.shields.io/badge/sponsor-30363D?style=for-the-badge&logo=GitHub-Sponsors&logoColor=#EA4AAA)](https://github.com/sponsors/taylorwalton)

---

## Based On

Talon is a fork of [NanoClaw](https://github.com/qwibitai/nanoclaw), a minimal Claude Agent SDK harness where agents run in isolated Linux containers. The core orchestration engine, container runner, channel system, and IPC layer are NanoClaw. Everything in `groups/copilot/`, `siem/`, `mysql/`, `copilot-mcp/`, `ollama/`, and `src/channels/http.ts` is purpose-built for the SOCfortress stack.

---

## License

The contents of this repository are available under the [MIT license](LICENSE).
