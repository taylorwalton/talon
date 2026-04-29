# Post-investigation notification fan-out

**Audience:** the SOC agent (Talon), reading this after report write-back.
**Trigger:** every successful investigation that reaches Step 6c.
**Failure mode:** best-effort. If notification dispatch fails, log it but
do **not** fail the investigation.

---

## What this is

After you've finished writing the investigation report back to CoPilot
(step 6b) and delivered the summary to the analyst (step 6c), CoPilot's
notification engine can fan the result out to per-customer destinations
— Slack channels, email distribution lists, etc. — based on rules a
human admin configured in the CoPilot UI.

Your job is **one HTTP call** to CoPilot's `/notifications/dispatch`
endpoint with the relevant fields from the report you just wrote. CoPilot
does the rest:

1. Looks up the customer's notification routes
2. Filters by trigger + severity threshold
3. Formats the message body per channel
4. Calls Slack / SMTP / etc.
5. Records the outcome in `notification_dispatch_log`
6. Enforces idempotency (re-runs are no-ops)

You don't need to query the routes table. You don't need to format the
message. You don't need to call Slack or SMTP yourself.

---

## When to call

Call exactly once per investigation, **after** step 6b's `submitReport`
returns successfully. Do not call:

- Before write-back finishes (the dispatch references the alert by ID,
  which only exists after the report row lands)
- For investigations that fail (status != 'completed') — the
  `severity_assessment` won't be reliable
- More than once for the same alert in the same run — CoPilot's
  idempotency log will skip duplicates anyway, but the wasted call
  shows up in dispatch logs as `skipped`

---

## How to call

Use Bash with curl. The CoPilot API key and base URL are already in your
environment via the existing `copilot-mcp` setup — same credentials you
use for the MCP write-back.

```bash
curl -fsS -X POST "${COPILOT_BASE_URL}/api/notifications/dispatch" \
  -H "Authorization: Bearer ${COPILOT_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "customer_code": "<the alert's customer_code>",
    "alert_id": <the integer alert_id>,
    "trigger": "<one of: investigation_complete | severity_critical_or_high>",
    "severity_assessment": "<Critical | High | Medium | Low | Informational>",
    "summary": "<the one-paragraph summary you wrote in the report>",
    "alert_name": "<the original alert name>",
    "report_url": "<deep link to the report in CoPilot, if you have one>"
  }'
```

### Picking the trigger

You **must** pick one trigger value per call. Use the rules below:

| If your report's `severity_assessment` is... | Pick this trigger |
|----------------------------------------------|-------------------|
| `Critical` or `High`                         | `severity_critical_or_high` |
| `Medium`, `Low`, or `Informational`          | `investigation_complete` |

Only fire **one** trigger per investigation. CoPilot's routes are
configured per-trigger, so:

- A customer with no routes at all → empty result, that's fine
- A customer with only an `investigation_complete` route → they'll see
  every investigation regardless of severity
- A customer with both routes → high-severity investigations fire the
  `severity_critical_or_high` route; lower ones fire `investigation_complete`

You only call with the trigger that matches the severity. Do not call
twice (once per trigger). The dispatch service handles route matching.

### Required fields

| Field | Source |
|-------|--------|
| `customer_code` | from the alert (you queried it in step 1) |
| `alert_id` | the integer alert ID, same as the one you wrote to `ai_analyst_report.alert_id` |
| `severity_assessment` | the same value you wrote to `ai_analyst_report.severity_assessment` |
| `summary` | the same value you wrote to `ai_analyst_report.summary` |

### Optional fields

| Field | When to include |
|-------|-----------------|
| `alert_name` | always, if you have it — helps recipients identify the alert |
| `report_url` | if your environment surfaces a deep link to the report (e.g. `https://copilot.example.com/incident-management/alert/<alert_id>`) |

---

## Handling the response

The endpoint returns a JSON body like:

```json
{
  "success": true,
  "message": "Dispatched 2 of 2 matching route(s) for customer 00001 alert 147",
  "routes_matched": 2,
  "dispatched": 2,
  "skipped": 0,
  "failed": 0,
  "outcomes": [
    {"route_id": 1, "route_name": "SOC Slack #alerts", "channel": "slack_webhook", "status": "sent", "latency_ms": 312},
    {"route_id": 3, "route_name": "IR email", "channel": "smtp_email", "status": "sent", "latency_ms": 1840}
  ]
}
```

### What to do with each outcome

| Field | Meaning | What to do |
|-------|---------|------------|
| `routes_matched: 0` | Customer has no rules for this trigger/severity | Nothing — expected for many customers |
| `failed > 0` | One or more channels errored (Slack 4xx, SMTP timeout, etc.) | Mention briefly in your final summary to the analyst (e.g. "note: 1 of 3 notifications failed — check the dispatch log") |
| `skipped > 0` | Idempotency hit — these were already dispatched | Don't worry about it — means the agent ran twice for the same alert |

If the curl itself fails (network error, 5xx from CoPilot, JSON parse
error, etc.):

1. Log a warning to your turn output (a 1-line "notification dispatch
   failed: <error>")
2. **Do not retry**, **do not fail the investigation**, **do not block
   the rest of the analyst delivery**

The investigation report is the primary deliverable. Notifications are
secondary.

---

## What you do **not** need to do

- ❌ Query `customer_notification_route` directly
- ❌ Look up Slack webhook URLs or SMTP recipients
- ❌ Format messages for specific channels
- ❌ Insert rows into `notification_dispatch_log` yourself
- ❌ Implement retry logic
- ❌ Track which alerts you've already notified about — CoPilot does

All of that lives in CoPilot's `app/notifications/` module. You're a
single-call client.

---

## End-to-end example

After completing investigation for alert 147 (customer 00001, severity
Critical):

```bash
# Step 6b already wrote the report — alert_id 147, severity Critical, etc.

# Step 6d — fan out:
curl -fsS -X POST "${COPILOT_BASE_URL}/api/notifications/dispatch" \
  -H "Authorization: Bearer ${COPILOT_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "customer_code": "00001",
    "alert_id": 147,
    "trigger": "severity_critical_or_high",
    "severity_assessment": "Critical",
    "summary": "BloodHound CE healthcheck firing rule 200288 (curl). Confirmed false positive — Docker HEALTHCHECK on piHole agent 088. Recommend rule exception.",
    "alert_name": "Curl process start",
    "report_url": "https://copilot.example.com/incident-management/alert/147"
  }'
```

Response (typical):
```json
{
  "success": true,
  "routes_matched": 1,
  "dispatched": 1,
  "skipped": 0,
  "failed": 0,
  "outcomes": [
    {"route_id": 4, "route_name": "SOC Slack #alerts", "channel": "slack_webhook", "status": "sent", "latency_ms": 287}
  ]
}
```

That's it — proceed to step 6c (deliver to analyst).
