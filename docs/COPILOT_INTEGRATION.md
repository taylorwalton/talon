# NanoClaw × CoPilot Integration

> **Status:** In progress — MCP write-back tools under development in CoPilot.

This document describes the architecture for integrating the NanoClaw AI analyst with the SOCfortress CoPilot application. The goal is a seamless analyst experience: alerts are automatically investigated by the AI, findings are written back into CoPilot, and analysts can interact with the AI directly from within the platform.

---

## Design Principles

- **CoPilot is the database of record.** All investigation results, job status, and extracted IOCs are stored in CoPilot's MySQL database — not in NanoClaw's SQLite store.
- **NanoClaw is the AI brain.** It detects alert types, loads the right analysis template, queries the SIEM, runs threat intel, and produces structured reports.
- **The agent never writes directly to MySQL.** The MySQL MCP tool is read-only. Agent write-back goes through a CoPilot REST API, which validates and persists results. This keeps the database boundary clean and auditable.
- **Both trigger paths produce identical output.** Whether an investigation is started by a real-time `POST /investigate` call or the 15-minute scheduled task, the agent runs the same workflow and writes back through the same API.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                   CoPilot (FastAPI)                  │
│                                                     │
│  Alert created ──► POST /investigate ──────────────┐│
│                                                    ││
│  GET /nanoclaw/status   ◄──── NanoClaw HTTP API    ││
│  GET /nanoclaw/jobs/:id ◄──── NanoClaw HTTP API    ││
│                                                    ││
│  MCP write-back tools:                             ││
│    POST /api/v1/ai-analyst/jobs       ◄────────────┘│
│    POST /api/v1/ai-analyst/reports                  │
│    POST /api/v1/ai-analyst/iocs                     │
│                                                     │
│  MySQL ──────────────────────────────────────────── │
│    ai_analyst_job                                   │
│    ai_analyst_report                                │
│    ai_analyst_ioc                                   │
└─────────────────────────────────────────────────────┘
          │  read-only MCP              ▲ REST write-back
          ▼                             │
┌─────────────────────────────────────────────────────┐
│                  NanoClaw (Node.js)                  │
│                                                     │
│  HTTP channel (port 3100)                           │
│    POST /investigate   ← CoPilot triggers this      │
│    POST /message       ← ad-hoc analyst prompts     │
│    GET  /status        ← queue + job overview       │
│    GET  /jobs/:alertId ← per-alert report status    │
│    GET  /health                                     │
│                                                     │
│  Scheduled task (every 15 min)                      │
│    Queries MySQL for OPEN alerts with no job row    │
│    Runs full investigation per alert                │
│                                                     │
│  Copilot container agent                            │
│    groups/copilot/CLAUDE.md   ← investigation flow  │
│    groups/copilot/prompts/    ← per-alert templates  │
└─────────────────────────────────────────────────────┘
```

---

## Trigger Paths

### Path 1 — Real-time: `POST /investigate`

CoPilot calls this endpoint immediately when an alert is created (or when an analyst clicks "Analyze with AI" on the alert detail page).

**Request:**
```json
POST http://nanoclaw:3100/investigate
{
  "alert_id": 1234,
  "customer_code": "acme",
  "sender": "copilot"
}
```

**NanoClaw behaviour:**
1. Creates a job row in `ai_analyst_job` (status = `pending`) via the CoPilot write-back API
2. Enqueues the investigation into the copilot group container
3. Returns `{ "job_id": "..." }` immediately (investigation runs async)

### Path 2 — Scheduled: 15-minute task

The scheduled task runs every 15 minutes and picks up any OPEN alert that does not yet have a job row — acting as a safety net for anything the real-time path missed.

```sql
SELECT a.id, a.alert_name, a.source, a.alert_creation_time,
       a.customer_code, ast.asset_name, ast.agent_id,
       ast.index_name, ast.index_id
FROM incident_management_alert a
JOIN incident_management_asset ast ON ast.alert_linked = a.id
LEFT JOIN ai_analyst_job j ON j.alert_id = a.id
WHERE a.status = 'OPEN'
  AND ast.index_name != ''
  AND ast.index_id != ''
  AND j.id IS NULL           -- not yet investigated
ORDER BY a.alert_creation_time DESC;
```

Both paths feed the same investigation workflow and write back through the same CoPilot API.

---

## Investigation Workflow (Agent-Side)

The copilot agent follows these steps for every alert, defined in `groups/copilot/CLAUDE.md`:

1. **Pull alert from MySQL** — `incident_management_alert` + `incident_management_asset`
2. **Fetch raw SIEM event + index mapping** — `get_document` and `get_index` in parallel. The mapping confirms exact field names and types before any search query is built.
3. **Detect alert type + load template** — checks `rule.groups` for `sysmon_event_<N>`, falls back to `data.win.system.eventID`. Reads `/workspace/group/prompts/<type>.txt` if a template exists.
4. **Extract IOCs** — IPs, domains, hashes, processes, commands
5. **Threat intel** — VirusTotal (hashes + IPs + domains), Shodan, AbuseIPDB, MITRE ATT&CK
6. **SIEM correlation** — lateral movement, persistence, other affected hosts
7. **Write results back to CoPilot** — via MCP write-back tools (see below)
8. **Send report to analyst** — via `send_message` to the webhook/HTTP channel

---

## Alert-Type Prompt Templates

Templates live in `groups/copilot/prompts/` and are mounted into the agent container at `/workspace/group/prompts/`. Each file is a plain-text investigation guide with template variables.

| File | Alert Type | Sysmon Event |
|------|-----------|--------------|
| `sysmon_event_1.txt` | Process Creation | Event ID 1 |
| `sysmon_event_3.txt` *(planned)* | Network Connection | Event ID 3 |
| `sysmon_event_7.txt` *(planned)* | Image Load / DLL | Event ID 7 |
| `sysmon_event_11.txt` *(planned)* | File Create | Event ID 11 |
| `sysmon_event_22.txt` *(planned)* | DNS Query | Event ID 22 |

**Template variables** the agent substitutes at runtime:

| Variable | Value |
|----------|-------|
| `{{ alert }}` | Full raw OpenSearch event JSON |
| `{{ event_id }}` | Numeric Sysmon event ID (e.g. `1`) |
| `{{ pipeline \| default('wazuh') }}` | Log pipeline name |
| `{{ virustotal_results }}` | VT findings after threat intel step |

To add a new alert type, create the corresponding `.txt` file — no code changes required.

---

## CoPilot MySQL Schema

Three new tables store all AI analyst state:

```sql
-- One row per investigation job
CREATE TABLE ai_analyst_job (
  id            VARCHAR(64) PRIMARY KEY,
  alert_id      INT NOT NULL,
  customer_code VARCHAR(64) NOT NULL,
  status        ENUM('pending','running','completed','failed') DEFAULT 'pending',
  alert_type    VARCHAR(64),
  triggered_by  ENUM('scheduled','manual','webhook') NOT NULL,
  template_used VARCHAR(128),
  created_at    DATETIME NOT NULL,
  started_at    DATETIME,
  completed_at  DATETIME,
  error_message TEXT
);

-- Full investigation report per alert
CREATE TABLE ai_analyst_report (
  id                  INT AUTO_INCREMENT PRIMARY KEY,
  job_id              VARCHAR(64) NOT NULL,
  alert_id            INT NOT NULL,
  customer_code       VARCHAR(64) NOT NULL,
  severity_assessment ENUM('Critical','High','Medium','Low','Informational'),
  report_markdown     MEDIUMTEXT,
  summary             TEXT,
  recommended_actions TEXT,
  created_at          DATETIME NOT NULL
);

-- IOCs extracted and enriched during investigation
CREATE TABLE ai_analyst_ioc (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  report_id     INT NOT NULL,
  alert_id      INT NOT NULL,
  customer_code VARCHAR(64) NOT NULL,
  ioc_value     VARCHAR(512) NOT NULL,
  ioc_type      ENUM('ip','domain','hash','process','url','user','command'),
  vt_verdict    ENUM('malicious','suspicious','clean','unknown') DEFAULT 'unknown',
  vt_score      VARCHAR(32),
  details       TEXT,
  created_at    DATETIME NOT NULL
);
```

---

## Agent Write-Back (CoPilot MCP Tools)

The agent has **read-only** access to MySQL. All writes go through CoPilot REST API endpoints exposed as MCP tools in the agent's environment. CoPilot validates the payload and persists results.

> **Status:** MCP tools under development in CoPilot. NanoClaw-side integration pending.

### MCP Tools (from `github.com/socfortress/copilot-mcp-server`)

**Customers**

| Tool | Method + Path | Purpose |
|------|--------------|---------|
| `GetCustomersTool` | `GET /api/customers` | List all customers visible to the authenticated user |

**Jobs**

| Tool | Method + Path | Purpose |
|------|--------------|---------|
| `CreateAiAnalystJobTool` | `POST /api/ai_analyst/jobs` | Register a new investigation job |
| `UpdateAiAnalystJobTool` | `PATCH /api/ai_analyst/jobs/{job_id}` | Update job status and metadata |
| `GetAiAnalystJobTool` | `GET /api/ai_analyst/jobs/{job_id}` | Fetch a single job by ID |
| `ListAiAnalystJobsByAlertTool` | `GET /api/ai_analyst/jobs/alert/{alert_id}` | List jobs for an alert (deduplication check) |
| `ListAiAnalystJobsByCustomerTool` | `GET /api/ai_analyst/jobs/customer/{customer_code}` | List all jobs for a customer |

**Reports**

| Tool | Method + Path | Purpose |
|------|--------------|---------|
| `SubmitAiAnalystReportTool` | `POST /api/ai_analyst/reports` | Submit full investigation report; returns `report_id` |
| `ListAiAnalystReportsByAlertTool` | `GET /api/ai_analyst/reports/alert/{alert_id}` | List reports for an alert |

**IOCs**

| Tool | Method + Path | Purpose |
|------|--------------|---------|
| `SubmitAiAnalystIocsTool` | `POST /api/ai_analyst/iocs` | Submit bulk extracted IOCs with VT verdicts |
| `ListAiAnalystIocsByReportTool` | `GET /api/ai_analyst/iocs/report/{report_id}` | List IOCs for a report |
| `ListAiAnalystIocsByAlertTool` | `GET /api/ai_analyst/iocs/alert/{alert_id}` | List all IOCs for an alert |
| `ListAiAnalystIocsByCustomerTool` | `GET /api/ai_analyst/iocs/customer/{customer_code}` | List IOCs for a customer, filterable by `vt_verdict` |

**Combined**

| Tool | Method + Path | Purpose |
|------|--------------|---------|
| `GetAlertAiAnalysisTool` | `GET /api/ai_analyst/alert/{alert_id}` | Fetch complete bundle: job + latest report + all IOCs |

---

## NanoClaw HTTP API

Endpoints on the HTTP channel (default port `3100`) that CoPilot can call or display:

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Liveness check |
| `GET /status` | Queue depth, active containers, last N completed jobs |
| `GET /jobs/:alertId` | Job status and report link for a specific alert |
| `POST /investigate` | Trigger a deep investigation for `{ alert_id, customer_code }` |
| `POST /message` | Ad-hoc prompt from an analyst — routes to the copilot agent |

> **Status:** `/investigate`, `/status`, and `/jobs/:alertId` are planned. `/message` and `/health` exist today.

---

## CoPilot UI Integration (Planned)

Once the write-back API and NanoClaw endpoints are in place, CoPilot can surface:

- **Alert detail page** — "AI Analysis" tab: severity badge, summary, full report, IOC table
- **Alert list** — status column: `⚡ Analyzed` / `⏳ Analyzing` / `✗ Failed` / `—`
- **Dashboard widget** — NanoClaw queue: N running, N completed today, N failed
- **IOC browser** — filter by `vt_verdict = 'malicious'` across all AI-discovered IOCs
- **"Analyze with AI" button** — calls `POST /investigate`, shows a spinner, auto-refreshes

---

## Human-in-the-Loop Review & Training

The goal: let analysts steer the agent toward the right behavior for **their environment** without anyone editing prompt files, writing MCP calls, or re-training a model. Reviews captured in the CoPilot UI feed two distinct channels:

1. **Prompt-level feedback** (global) → flagged template issues → SOC leads tweak the `.txt` files in [groups/copilot/prompts/](../groups/copilot/prompts/).
2. **Environment-level knowledge** (per-customer) → written to **MemPalace** → auto-recalled by the agent on the next investigation for that customer (Step 0.5 of the workflow).

Keep these two lanes separate. Templates are global; MemPalace lessons are per-wing (customer).

### Flow

```
Analyst reads AI report in CoPilot UI
  │
  ├─► Thumbs up/down + IOC verdict checks      ──► ai_analyst_review (CoPilot MySQL)
  │
  ├─► Teach the palace (free-text lesson + room dropdown)
  │     CoPilot queues the lesson in ai_analyst_palace_lesson
  │     Async drainer POSTs to NanoClaw → POST /palace/lesson
  │     NanoClaw wraps the MemPalace MCP call (mempalace_add_drawer / mempalace_kg_add)
  │
  ├─► Re-run with different template
  │     CoPilot → POST /investigate (NanoClaw) with template_override
  │     New job runs, side-by-side diff shown in UI
  │
  └─► Flag template issue (missed step, wrong choice, etc.)
        Aggregated into the Feedback Dashboard → drives .txt edits
```

### CoPilot side

**UI surface — Review panel on the alert detail page**

Placed directly below the AI report so the reviewer never context-switches. Progressive disclosure — simple signals first, full rubric on expand.

- **Default (5-second review):**
  - Thumbs up / down on the overall report
  - Per-IOC inline checkmarks: `verdict correct?` ✓ / ✗
  - "Template picked was correct?" → correct / wrong / partial (dropdown shows what was picked)
- **Expanded rubric (30–60 seconds):**
  - Star ratings: template choice, instruction clarity, artifacts collected, severity verdict
  - Free text: missing steps, suggested edits
  - **Teach the palace** sub-panel (see below)

**Teach-the-palace UX**

The reviewer writes prose; the system handles MCP tool names, wing/room routing, and duplicate detection.

```
┌─ Teach the palace ─────────────────────────────────┐
│ Customer: ACME (auto-filled from alert)            │
│ Lesson type: [Environment ▼]                       │
│   • Environment — expected behavior / admin patterns│
│   • False positive — known noisy rule+asset combo   │
│   • Asset — facts about a specific host             │
│   • Threat intel — IOC seen in this environment     │
│ Lesson: [ DC01 runs SCCM patching at 02:00, expect │
│           svchost children in that window        ] │
│ Similar existing lessons: (CoPilot → GET /palace/search on NanoClaw) │
│ Durability: ( ) one-off  (•) durable                │
│ [ Save to palace ]                                 │
└─────────────────────────────────────────────────────┘
```

**Replay / A-B testing**

A **"Re-investigate with…"** button opens a modal with a template dropdown (current pick highlighted, experimental `.v2.txt` variants listed). CoPilot calls `POST /investigate` with a `template_override` parameter. When the new job completes, the UI shows a side-by-side diff (verdict, IOCs, actions) and lets the reviewer pick the winner — that choice is itself a signal logged to `ai_analyst_review`.

**Feedback Dashboard (separate page)**

Aggregates reviews across customers:
- Template selection accuracy per customer (`sysmon_event_1.txt` — 87% on ACME, 62% on BETA-CORP)
- Most-flagged missing steps across all templates (candidates for `.txt` edits)
- Top palace lessons by recall hit rate (how often a lesson was surfaced in Step 0.5 of a future investigation)

**New MySQL tables**

```sql
-- One row per analyst review of an AI report
CREATE TABLE ai_analyst_review (
  id                     INT AUTO_INCREMENT PRIMARY KEY,
  report_id              INT NOT NULL,
  alert_id               INT NOT NULL,
  customer_code          VARCHAR(64) NOT NULL,
  reviewer_user_id       INT NOT NULL,
  overall_verdict        ENUM('up','down') NULL,
  template_choice        ENUM('correct','wrong','partial') NULL,
  template_used          VARCHAR(128),         -- snapshot at review time
  rating_instructions    TINYINT,              -- 1–5
  rating_artifacts       TINYINT,              -- 1–5
  rating_severity        TINYINT,              -- 1–5
  missing_steps          TEXT,
  suggested_edits        TEXT,
  created_at             DATETIME NOT NULL
);

-- Per-IOC verdict corrections (optional, one row per flagged IOC)
CREATE TABLE ai_analyst_ioc_review (
  id             INT AUTO_INCREMENT PRIMARY KEY,
  review_id      INT NOT NULL,
  ioc_id         INT NOT NULL,
  verdict_correct BOOLEAN NOT NULL,
  note           TEXT,
  created_at     DATETIME NOT NULL
);

-- Queued palace lessons — async worker drains this into MemPalace
CREATE TABLE ai_analyst_palace_lesson (
  id             INT AUTO_INCREMENT PRIMARY KEY,
  review_id      INT,                    -- nullable (can be submitted standalone)
  customer_code  VARCHAR(64) NOT NULL,   -- becomes wing
  lesson_type    ENUM('environment','false_positives','assets','threat_intel') NOT NULL,
  lesson_text    TEXT NOT NULL,
  durability     ENUM('one_off','durable') DEFAULT 'durable',
  status         ENUM('pending','ingested','failed') DEFAULT 'pending',
  ingested_at    DATETIME,
  created_at     DATETIME NOT NULL
);
```

**New CoPilot REST endpoints**

| Endpoint | Purpose |
|---|---|
| `POST /api/ai_analyst/reports/{report_id}/review` | Submit a review (rubric + thumbs + template verdict) |
| `POST /api/ai_analyst/reports/{report_id}/replay` | Trigger `POST /investigate` on NanoClaw with `template_override` |
| `POST /api/ai_analyst/palace_lessons` | Queue a teach-the-palace lesson for async ingestion |
| `GET /api/ai_analyst/reviews/customer/{customer_code}` | Feed the Feedback Dashboard |
| `GET /api/ai_analyst/palace_lessons/customer/{customer_code}` | List already-ingested lessons for the UI's similar-lessons preview (proxies `GET /palace/search` on NanoClaw) |

**Async palace ingestion drainer (CoPilot-side)**

MemPalace itself runs inside NanoClaw — CoPilot does not hold an MCP client and does not talk to the palace directly. Instead, a lightweight CoPilot worker drains `ai_analyst_palace_lesson` where `status = 'pending'` and POSTs each row to the NanoClaw HTTP endpoint:

```
POST http://nanoclaw:3100/palace/lesson
Authorization: Bearer <HTTP_API_KEY>
{
  "customer_code": "acme",
  "lesson_type":   "environment",
  "lesson_text":   "DC01 runs SCCM patching at 02:00...",
  "durability":    "durable"
}
```

On a `2xx` response the worker marks the row `ingested`; on failure it retries with backoff and marks `failed` after N attempts. CoPilot's responsibility ends at the HTTP call — NanoClaw owns the MemPalace write, room/wing routing, and durability metadata.

Similarly, the **live similar-lessons preview** in the teach-the-palace UI is served by CoPilot proxying to NanoClaw's `GET /palace/search` rather than hitting MemPalace directly.

### NanoClaw (Talon) side

**Eval output alongside every investigation**

The copilot agent writes a structured eval file at the end of Step 6 of the workflow. One per investigation, siblings to the transcript in `groups/copilot/logs/`:

```
groups/copilot/evals/<alert_id>-<job_id>.json
```

```json
{
  "alert_id": 12345,
  "job_id": "copilot-inv-12345-1714000000",
  "customer_code": "acme",
  "alert_name": "Suspicious PowerShell",
  "template_used": "sysmon_event_1.txt",
  "selection_method": "ollama",
  "template_override": null,
  "tools_called": [
    "mcp__mysql__query",
    "mcp__opensearch_anon__get_document",
    "mcp__ollama__ollama_generate",
    "mcp__velociraptor__GetAgentInfo",
    "mcp__velociraptor__CollectArtifactTool:Windows.System.Pslist"
  ],
  "artifacts_collected": ["Windows.System.Pslist", "Windows.Forensics.Prefetch"],
  "ioc_count": 4,
  "severity": "Suspicious",
  "duration_sec": 87,
  "ollama_model": "qwen2.5:7b",
  "palace_lessons_recalled": 2
}
```

The CoPilot Feedback Dashboard reads these to compute selection-accuracy and tool-usage stats without parsing transcripts.

**New HTTP endpoints on the NanoClaw channel**

NanoClaw is the sole owner of MemPalace — every palace interaction from CoPilot goes through these endpoints, not through an MCP client on the CoPilot side.

| Endpoint | Purpose |
|---|---|
| `POST /investigate` *(extended)* | Now accepts `template_override: "<filename>"` — agent skips Step 2.5 selection and loads that template directly |
| `POST /palace/lesson` | Wraps `mempalace_add_drawer`. Body: `{ customer_code, lesson_type, lesson_text, durability }`. NanoClaw maps `customer_code → wing` and `lesson_type → room`, writes the drawer, and returns `{ drawer_id, ingested_at }`. Called by CoPilot's async drainer. |
| `GET /palace/search` | Wraps `mempalace_search`. Query: `?customer_code=<code>&room=<room>&query=<text>&limit=<n>`. Powers the similar-lessons preview in the teach-the-palace UI. |
| `GET /evals/:alertId` | Returns the eval JSON for a given alert — used by the CoPilot dashboard |

**Investigation workflow changes**

- **Step 2.5** — if the job was created with `template_override`, skip Ollama ranking and filename fallback; load the override directly. Log `selection_method: "override"` in the eval.
- **Step 6 (end of write-back)** — write the eval JSON to `groups/copilot/evals/`.
- **Step 0.5 enhancement** — record how many palace lessons were recalled into the eval; powers the "hit rate" metric on the dashboard.

**MemPalace room taxonomy for reviews**

Reuse the existing taxonomy from `groups/copilot/CLAUDE.md` — no new rooms needed for teach-the-palace. One new room for tracking review signals themselves:

| Wing | Room | What goes here |
|---|---|---|
| `<customer_code>` | `prompt_feedback` | Selection-accuracy signals per template: `(template, reviewer_verdict, timestamp)` tuples. Consumed by the dashboard. |

### Role gating

Recommend separating capability by analyst tier:

| Role | Can… |
|---|---|
| Tier 1 | Thumbs up/down, flag IOC verdicts |
| Tier 2+ | Full rubric, teach-the-palace, re-run with override |
| SOC lead / Admin | Feedback dashboard, promote `.v2.txt` experimental templates to production |

### Durability & palace hygiene

Reviews can generate lessons fast. Two guards keep the palace useful:

1. **Durability flag** on each lesson. `one_off` lessons expire after N days (default 30); `durable` lessons persist until manually removed. Enforced by a daily sweeper on the MemPalace side.
2. **Quarterly consolidation pass** — SOC lead runs the `anthropic-skills:consolidate-memory` skill against a wing: merges duplicates, flags stale lessons, drops outdated patterns.

### Tradeoffs captured here, for posterity

- **Replay cost** — re-running investigations burns tool credits + VT lookups. Plan to cache threat-intel by IOC for ~7 days so replays are cheap.
- **UI friction vs. adoption** — ship thumbs-up/down + teach-the-palace first; skip the full rubric until reviewers ask for it.
- **Palace growth** — UI makes contributions easy, so lesson volume will scale with alert volume. Durability flag + quarterly consolidation are load-bearing, not optional.
- **Subjective rubric** — 1–5 stars is fast to adopt, low ceiling. Adding an LLM-as-judge pass (review agent scores the AI agent) is a natural later step once there's a baseline corpus.

---

## Implementation Roadmap

| # | Item | Owner | Status |
|---|------|-------|--------|
| 1 | Alert-type prompt templates (`sysmon_event_1.txt`) | NanoClaw | ✅ Done |
| 2 | Investigation workflow + index mapping step (CLAUDE.md) | NanoClaw | ✅ Done |
| 3 | Upgraded scheduled task (full investigation per alert) | NanoClaw | ✅ Done |
| 4 | MySQL schema: `ai_analyst_job/report/ioc` tables | CoPilot | ✅ Done |
| 5 | CoPilot write-back REST API endpoints | CoPilot | ✅ Done |
| 6 | CoPilot MCP server (`copilot-mcp-server`) + NanoClaw integration | Both | ✅ Done |
| 7 | Scheduled task deduplication + full write-back with real tool names | NanoClaw | ✅ Done |
| 8 | `POST /investigate` endpoint in NanoClaw | NanoClaw | ✅ Done |
| 9 | `GET /status` endpoint in NanoClaw | NanoClaw | ✅ Done |
| 10 | Additional prompt templates (events 3, 7, 11, 22) | NanoClaw | Planned |
| 11 | CoPilot UI: alert analysis tab + status badges | CoPilot | Planned |
| 12 | Eval JSON output per investigation (`groups/copilot/evals/`) | NanoClaw | Planned |
| 13 | `template_override` param on `POST /investigate` | NanoClaw | Planned |
| 14 | NanoClaw palace HTTP endpoints: `POST /palace/lesson` + `GET /palace/search` wrapping MemPalace MCP tools | NanoClaw | Planned |
| 15 | Review MySQL tables (`ai_analyst_review`, `ai_analyst_ioc_review`, `ai_analyst_palace_lesson`) | CoPilot | Planned |
| 16 | CoPilot REST endpoints: review submit, replay, palace lesson queue | CoPilot | Planned |
| 17 | CoPilot async palace drainer (POSTs queued lessons to NanoClaw `/palace/lesson`) | CoPilot | Planned |
| 18 | CoPilot UI: inline review panel + teach-the-palace | CoPilot | Planned |
| 19 | CoPilot UI: re-run / A-B template comparison modal | CoPilot | Planned |
| 20 | CoPilot UI: feedback dashboard (selection accuracy, flagged steps, lesson hit rate) | CoPilot | Planned |
| 21 | Durability sweeper + quarterly palace consolidation workflow | Both | Planned |
