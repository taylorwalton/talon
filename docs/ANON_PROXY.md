# Anonymizing MCP Proxy

This document explains the anonymizing OpenSearch MCP proxy — what problem it solves, how it works step by step, and how to extend it.

---

## The Problem

When the SOC agent investigates an alert, it calls OpenSearch to retrieve the raw SIEM event. That event contains sensitive data:

- Usernames and account names (`john.doe`, `CORP\jsmith`)
- Internal hostnames (`WORKSTATION-01`, `DC-PROD-02`)
- Internal IP addresses (`192.168.1.100`)
- Email addresses (`john.doe@company.com`)

In the standard MCP flow, tool results are returned directly into the Claude model's context window — meaning this raw sensitive data is sent to Anthropic's cloud API as part of every investigation.

The anonymizing proxy intercepts those results before they reach the model and replaces PII values with opaque tokens. The model reasons about `USER_1`, `HOST_1`, and `IP_INT_1` instead of real names and addresses.

---

## How It Works — Step by Step

```
┌──────────────────────────────────────────────────────────────────┐
│                    Claude (cloud model)                          │
│                                                                  │
│  "Fetch the raw event for alert 1234"                            │
│                        │                                        │
│                        ▼                                        │
│  mcp__opensearch_anon__get_document(index, id)                   │
│                        │                                        │
└────────────────────────┼────────────────────────────────────────┘
                         │ JSON-RPC request (stdin)
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│               anon_proxy.py  (runs in container)                 │
│                                                                  │
│  1. Receives the get_document request                            │
│  2. Forwards it unchanged to opensearch-mcp.sh (child process)   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
                         │ JSON-RPC request (child stdin)
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│           opensearch-mcp-server  (child process)                 │
│                                                                  │
│  Fetches raw event from OpenSearch                               │
│  Returns the full document JSON                                  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
                         │ raw document (child stdout)
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│               anon_proxy.py  (intercepts response)               │
│                                                                  │
│  3. Walks every field in the returned JSON                       │
│  4. For each field, checks fields.yaml:                          │
│     • Known PII field?  → replace value with TOKEN_N             │
│     • Preserved field?  → pass through unchanged                 │
│     • Other string?     → scan for inline patterns               │
│  5. Updates session_tokens.json with any new mappings            │
│  6. Returns the anonymized document upstream                     │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
                         │ anonymized document (stdout)
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Claude (cloud model)                          │
│                                                                  │
│  Receives:                                                       │
│    data_win_eventdata_user:  USER_1          ← was john.doe      │
│    agent_name:               HOST_1          ← was WORKSTATION-01│
│    data_win_eventdata_destinationIp: 8.8.8.8 ← preserved        │
│    data_win_eventdata_hashes: SHA256=abc123  ← preserved        │
│    rule_description: "Suspicious process..."  ← preserved       │
│                                                                  │
│  Reasons about tokens, runs threat intel on preserved IOCs,      │
│  writes the report draft using tokens                            │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Token Types

| Token format | Replaces | Example |
|---|---|---|
| `USER_1`, `USER_2`, … | Usernames, account names, UPNs | `john.doe` → `USER_1` |
| `HOST_1`, `HOST_2`, … | Hostnames, computer names | `WORKSTATION-01` → `HOST_1` |
| `EMAIL_1`, `EMAIL_2`, … | Email addresses | `j.doe@corp.com` → `EMAIL_1` |
| `IP_INT_1`, `IP_INT_2`, … | Internal / RFC1918 IP addresses | `192.168.1.100` → `IP_INT_1` |

Tokens are **consistent within a session** — the same original value always maps to the same token. `john.doe` seen in ten different events is always `USER_1`, making correlation across events still possible.

---

## What Is Preserved (Never Anonymized)

These values pass through the proxy unchanged because they are needed for threat intelligence and analysis:

| Field | Why preserved |
|---|---|
| `data_win_eventdata_hashes` | VirusTotal / MalwareBazaar hash lookups |
| External IPs (`8.8.8.8`, etc.) | Shodan / AbuseIPDB / VT lookups |
| `data_win_eventdata_destinationHostname` | C2 domain reputation checks |
| `data_win_eventdata_queryName` | DNS query threat intel |
| `data_win_eventdata_image` / `parentImage` | Process path analysis |
| `data_win_eventdata_commandLine` | Command-line analysis |
| `rule_*` fields | MITRE mapping, severity, classification |
| `data_win_system_eventID` | Alert type detection |
| Timestamps | Event sequencing |

---

## Pattern-Based Scanning

In addition to field-aware tokenization, the proxy scans **all string values** for two patterns, even when they appear embedded inside larger strings:

**Windows user paths**
```
C:\Users\john.doe\AppData\Local\Temp\evil.exe
          ↓
C:\Users\USER_1\AppData\Local\Temp\evil.exe
```
The `commandLine` and `image` fields are preserved as a whole (needed for analysis), but any embedded username in a path is still replaced.

**Internal IP addresses**
```
"Process connected to 10.0.1.55 on port 4444"
                       ↓
"Process connected to IP_INT_1 on port 4444"
```
External IPs are detected by checking against RFC1918 / loopback / link-local ranges and left untouched.

---

## De-anonymization Before Report Delivery

After analysis is complete, the agent calls the built-in `deanonymize` tool to restore original values in the report draft before it reaches the analyst:

```
Step 1 — Investigation (tokens in context)
  USER_1 connected to IP_INT_1 and ran a suspicious command.
  USER_1 is a member of the Domain Admins group.

Step 2 — Call deanonymize(text="<full report draft>")

Step 3 — De-anonymized output returned to model
  john.doe connected to 192.168.1.100 and ran a suspicious command.
  john.doe is a member of the Domain Admins group.

Step 4 — Submit to CoPilot and send to analyst
```

The token map (`/workspace/group/session_tokens.json`) holds the forward mapping. The `deanonymize` tool builds the reverse map and does a string substitution pass.

---

## Session Token Map

The token map is persisted at `/workspace/group/session_tokens.json` inside the agent container:

```json
{
  "forward": {
    "john.doe": "USER_1",
    "WORKSTATION-01": "HOST_1",
    "192.168.1.100": "IP_INT_1"
  },
  "counters": {
    "USER": 1,
    "HOST": 1,
    "IP_INT": 1
  }
}
```

The `forward` map is used for anonymization (original → token) and the reverse is computed on demand for de-anonymization (token → original).

---

## File Layout

```
siem/
  opensearch-mcp.sh          ← raw OpenSearch MCP server (used for non-sensitive queries)
  anon-opensearch-mcp.sh     ← anonymizing wrapper (use for all document/search queries)
  anon_proxy/
    anon_proxy.py            ← proxy implementation
    fields.yaml              ← field definitions (git-pullable, see below)
```

The proxy is registered as a second MCP server in `groups/copilot/.mcp.json`:

```json
{
  "mcpServers": {
    "opensearch":      { "command": "/workspace/extra/siem/opensearch-mcp.sh" },
    "opensearch_anon": { "command": "/workspace/extra/siem/anon-opensearch-mcp.sh" },
    "mysql":           { "command": "/workspace/extra/mysql/mysql-mcp.sh" },
    "copilot":         { "command": "/workspace/extra/copilot-mcp/copilot-mcp.sh" }
  }
}
```

The agent uses `mcp__opensearch_anon__*` for all document retrieval and search queries, and falls back to `mcp__opensearch__*` only for non-sensitive operations like `get_index` and `list_indices`.

---

## Adding New Fields to Anonymize

Field definitions live in `siem/anon_proxy/fields.yaml`. To add a new field:

1. Open `siem/anon_proxy/fields.yaml`
2. Find the right category (`user`, `hostname`, `email`) or add a new one
3. Add the field name in **underscore notation** (Wazuh/CoPilot convention)
4. Commit and push — other deployments run `git pull` to receive the update

Example — adding Azure AD fields:

```yaml
categories:
  user:
    token_prefix: "USER"
    fields:
      - data_win_eventdata_user
      - data_win_eventdata_targetUserName
      # new:
      - data_azure_ad_userPrincipalName
      - data_azure_ad_displayName
```

To add a **new category** (e.g., for credit card numbers or national IDs):

```yaml
categories:
  # ... existing categories ...

  national_id:
    token_prefix: "NID"
    description: "National ID / SSN equivalents"
    fields:
      - data_custom_national_id
      - data_custom_ssn
```

Tokens for the new category will be `NID_1`, `NID_2`, etc.

To **preserve** a field that might otherwise be anonymized by pattern matching, add it to `preserve_fields`:

```yaml
preserve_fields:
  - my_custom_external_ip_field
  - data_custom_public_identifier
```

---

## How the Proxy Fits Into a Full Investigation

```
Alert created in CoPilot
        │
        ▼
Step 0  Check for existing job → register new job → update to "running"
        │
        ▼
Step 1  MySQL: pull alert + asset metadata (index_name, index_id)
        │
        ▼
Step 2  opensearch_anon: get_document → raw event returned anonymized
        opensearch:      get_index    → field mappings (not sensitive)
        ollama:          list_models
        │
        ▼
Step 2.5 Detect alert type from rule.groups / eventID
         Load prompt template from /workspace/group/prompts/<type>.txt
        │
        ▼
Step 3  Extract IOCs from anonymized event
        (hashes, external IPs, domains are preserved — usable as-is)
        (usernames/hosts appear as USER_1 / HOST_1)
        │
        ▼
Step 4  Threat intel: VirusTotal, Shodan, AbuseIPDB
        (external IOCs were never anonymized, queries work normally)
        │
        ▼
Step 5  opensearch_anon: search_documents — correlation queries
        (results consistently use same tokens from Step 2)
        │
        ▼
Step 6a opensearch_anon: deanonymize(text=<full report draft>)
        USER_1 → john.doe, HOST_1 → WORKSTATION-01, IP_INT_1 → 192.168.1.100
        │
        ▼
Step 6b UpdateAiAnalystJobTool → SubmitAiAnalystReportTool → SubmitAiAnalystIocsTool
        │
        ▼
Step 6c send_message → analyst receives accurate, fully resolved report
```
