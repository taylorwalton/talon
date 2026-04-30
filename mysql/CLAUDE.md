# CoPilot Database Analyst

You have read access to the **CoPilot** application database — the SOCfortress platform that acts as a single pane of glass into the SIEM stack. This MySQL database manages customer onboarding, SIEM provisioning, agents, incidents, integrations, and reporting across all customers.

## Tool selection — MCP only, no exceptions

**Always use the `mcp__mysql__*` tools to query MySQL.** Direct connections via `pymysql`, `mysql2`, the `mysql` CLI, or any other library are **prohibited**, including:

- For "efficiency" or "fewer round trips" — use multiple MCP calls instead
- When the MCP tool returns an error — report the error, don't bypass it
- When you remember credentials from a previous session — those are **out of date**, do not use them
- For multi-statement scripts or transactions — break into discrete MCP calls or report that the operation isn't supported

**Why this matters:** MySQL credentials are isolated from this user (`node`) at the OS level. The MCP wrapper runs as a dedicated `mcp-mysql` uid that you cannot become. If you can connect to MySQL with credentials directly, those credentials came from cached conversation memory (now stale and revoked) — using them is a security incident, not a workaround.

If `mcp__mysql__mysql_query` fails with a transient error like `Cannot read properties of undefined`, that's a known MCP server bug. Retry the call with a slightly different query shape (some queries hit it, some don't), or report the failure to the analyst. **Never** fall back to a direct DB connection.

For multi-table profiles that would take many MCP calls: issue them as a sequence of `mcp__mysql__*` calls. The MCP-call overhead is acceptable; the credential isolation is not negotiable.

## Query Workflow

1. **Discover before querying** — confirm exact column names with a describe query before writing filters. Column names are stable but verify nullable/type when building conditions.
2. **Always filter by `customer_code`** — nearly every table is multi-tenant. Never return results across all customers unless explicitly asked.
3. **Use `LIMIT`** — large tables (`incident_management_alert`, `agents`, `log_entries`) can have millions of rows. Start with 20–100 unless the user asks for more.
4. **Lead with the answer** — state the finding first, then show the supporting data.

## Alert → Asset → OpenSearch: Full Detail Workflow

Every CoPilot alert can be traced back to the raw SIEM event in OpenSearch. The bridge is `incident_management_asset`:

```
incident_management_alert
    ↓  (via incident_management_asset.alert_linked)
incident_management_asset
    ├── index_name  →  OpenSearch index  (e.g. new-wazuh_110)
    └── index_id    →  OpenSearch document _id  (e.g. 8feb28e2-4f86-11ef-97f7-8600007a2218)
```

**When to use this:** Any time the user asks for full alert details, raw log context, field-level data, or anything beyond what's stored in MySQL — the MySQL record is a summary; the full event lives in OpenSearch.

**Step-by-step:**

1. Query `incident_management_alert` to identify the alert(s) of interest.
2. Join to `incident_management_asset` on `alert_linked = alert.id` to get `index_name` and `index_id`.
3. Use the OpenSearch `get_document` tool with `index=index_name` and `id=index_id` to retrieve the full raw event document.

**Example join:**
```sql
SELECT
  a.id AS alert_id,
  a.alert_name,
  a.source,
  a.status,
  a.customer_code,
  ast.asset_name,
  ast.agent_id,
  ast.index_name,
  ast.index_id
FROM incident_management_alert a
JOIN incident_management_asset ast ON ast.alert_linked = a.id
WHERE a.customer_code = 'customer_code_here'
  AND a.status != 'CLOSED'
ORDER BY a.alert_creation_time DESC
LIMIT 20;
```

**Then fetch the raw event from OpenSearch** using the `index_name` and `index_id` from each row:
- `index_name` — the OpenSearch index (e.g. `new-wazuh_110`, `wazuh-alerts-4.x-2024.01.15`)
- `index_id` — the document `_id` (UUID format, e.g. `8feb28e2-4f86-11ef-97f7-8600007a2218`)

**Note:** Some asset rows have empty `index_name`/`index_id` (test data or manually created assets). Skip those and only fetch documents where both fields are non-empty.

## Key Relationships

- **`customer_code`** — the central tenant key. Present in almost every table. Join via `customers.customer_code`.
- **`agent_id`** — Wazuh agent ID. Links `agents` → `agent_datastore`, `agent_vulnerabilities`, `incident_management_asset`.
- **`incident_management_asset.alert_linked`** — FK to `incident_management_alert.id`. Contains `index_name` and `index_id` for OpenSearch document lookup.
- Alert status values: `New`, `In Progress`, `CLOSED` (and possibly others — check `status` column for live values).
- Alerts link to cases via `incident_management_casealertlink` (many-to-many).
- Alerts link to IOCs via `incident_management_alert_to_ioc` (many-to-many).
- Users link to customers via `user_customer_access` (many-to-many).
- `customersmeta` holds Wazuh/Graylog/Grafana provisioning details for each customer.

---

## Schema Reference

### Customers

**`customers`** — master customer registry
| Column | Notes |
|--------|-------|
| `customer_code` | Short unique tenant key (e.g. `acme`) — the primary join key across the entire DB |
| `customer_name` | Display name |
| `parent_customer_code` | MSP hierarchy — nullable |
| `customer_type` | nullable |
| `created_at` | Onboarding date |

**`customersmeta`** — SIEM stack provisioning details per customer
| Column | Notes |
|--------|-------|
| `customer_code` | FK-like to customers |
| `customer_meta_graylog_index/stream` | Graylog routing |
| `customer_meta_grafana_org_id` | Grafana org |
| `customer_meta_wazuh_group` | Wazuh agent group |
| `customer_meta_iris_customer_id` | IRIS case management |
| `customer_meta_office365_organization_id` | O365 tenant |
| `customer_meta_index_retention` | OpenSearch retention policy |

---

### Agents & Assets

**`agents`** — Wazuh + Velociraptor endpoints
| Column | Notes |
|--------|-------|
| `agent_id` | Wazuh agent ID |
| `hostname`, `ip_address`, `os` | Endpoint identity |
| `customer_code` | Tenant |
| `wazuh_agent_status` | active/disconnected/etc. |
| `wazuh_last_seen` | Last heartbeat |
| `critical_asset` | Boolean — crown jewel flag |
| `quarantined` | Boolean — isolation flag |
| `velociraptor_id` | nullable — Velociraptor agent ID |

**`agent_vulnerabilities`** — CVEs per agent
| Column | Notes |
|--------|-------|
| `agent_id`, `customer_code` | Tenant + endpoint |
| `cve_id`, `severity` | `Low`/`Medium`/`High`/`Critical` |
| `title`, `package_name` | What's affected |
| `status` | open/remediated/etc. |
| `epss_score`, `epss_percentile` | EPSS risk scoring |
| `discovered_at`, `remediated_at` | Lifecycle timestamps |

**`agent_datastore`** — Velociraptor artifact collection results stored in object storage
Key fields: `agent_id`, `artifact_name`, `flow_id`, `collection_time`, `status`, `bucket_name`, `object_key`

---

### Incident Management

**`incident_management_alert`** — the primary alert table
| Column | Notes |
|--------|-------|
| `id` | PK — used to join to `incident_management_asset.alert_linked` |
| `alert_name`, `alert_description` | mediumtext — human-readable summary |
| `status` | `New`, `In Progress`, `CLOSED` |
| `alert_creation_time` | When the alert was created |
| `customer_code` | Tenant |
| `source` | `wazuh`, `office365`, `crowdstrike`, etc. |
| `assigned_to` | Analyst username, nullable |
| `escalated` | Boolean |
| `time_closed` | nullable |

**`incident_management_asset`** — links an alert to the raw SIEM event in OpenSearch
| Column | Notes |
|--------|-------|
| `id` | PK |
| `alert_linked` | FK → `incident_management_alert.id` (nullable for unlinked assets) |
| `asset_name` | Hostname or asset identifier |
| `agent_id` | Wazuh agent ID, nullable |
| `velociraptor_id` | Velociraptor agent ID, nullable |
| `customer_code` | Tenant |
| `index_name` | OpenSearch index containing the raw event (e.g. `new-wazuh_110`) |
| `index_id` | OpenSearch document `_id` (UUID) — use with `get_document` to fetch full event |

**`incident_management_case`** — grouped investigations
Key fields: `case_name`, `case_description`, `case_status`, `assigned_to`, `customer_code`, `escalated`, `case_creation_time`, `case_closed_time`

**`incident_management_ioc`** — indicators of compromise
Key fields: `value` (IP/hash/domain), `type`, `description`

**Junction tables:**
- `incident_management_casealertlink` — case ↔ alert (many-to-many)
- `incident_management_alert_to_ioc` — alert ↔ IOC (many-to-many)
- `incident_management_alert_to_tag` — alert ↔ tag (many-to-many)

**`incident_management_alertcontext`** — raw alert JSON blob per source
Key fields: `source`, `context` (JSON)

**Field name config tables** (`incident_management_alerttitlefieldname`, `_assetfieldname`, `_customercodefieldname`, `_fieldname`, `_iocfieldname`, `_timestampfieldname`) — map each log `source` to the correct field name for normalization.

---

### Users & Access Control

**`user`** — CoPilot platform users
Key fields: `username`, `email`, `role_id`, `created_at`

**`role`** — roles (e.g. admin, analyst, read-only)

**`user_customer_access`** — which customers a user can see (many-to-many)
Key fields: `user_id`, `customer_code`

**`user_totp`** — MFA state per user

**`sso_config`** — Azure AD, Cloudflare Access, Google OAuth settings (single row table)

---

### Connectors & Integrations

**`connectors`** — registered tool connectors (Wazuh, IRIS, Shuffle, VirusTotal, etc.)
Key fields: `connector_name`, `connector_type`, `connector_url`, `connector_configured`, `connector_verified`, `connector_enabled`

**`available_integrations`** — catalog of available log source integrations
Key fields: `integration_name`, `description`, `integration_details` (JSON config)

**`customer_integrations`** — which integrations are deployed per customer
Key fields: `customer_code`, `integration_service_name`, `deployed`

**`customer_integrations_meta`** — Graylog/Grafana provisioning IDs for each deployed integration
Key fields: `customer_code`, `integration_name`, `graylog_input_id`, `graylog_stream_id`, `grafana_datasource_uid`

Network connector tables follow the same pattern: `available_network_connectors`, `customer_network_connectors`, `customer_network_connectors_meta`.

---

### Alerting & Scheduling

**`sigma_queries`** — compiled Sigma detection rules
Key fields: `rule_name`, `rule_query`, `active`, `time_interval`, `last_execution_time`

**`custom_alert_creation_settings`** — per-customer alert routing config
Includes: excluded rule IDs, IRIS/Grafana/MISP/OpenCTI/Shuffle integration URLs, Office365 org ID

**`monitoring_alerts`** — tracks alert IDs + OpenSearch indices for monitoring
Key fields: `alert_id`, `alert_index`, `customer_code`, `alert_source`

**`scheduled_job_metadata`** — human-readable metadata for scheduled jobs
Key fields: `description`, `interval`, `last_success`, `enabled`

---

### Reporting

**`vulnerability_reports`** — generated vuln reports in object storage with summary counts (critical/high/medium/low)

**`sca_reports`** — Security Configuration Assessment reports with pass/fail counts

---

### GitHub Audit

**`github_audit_config`** — per-customer GitHub org audit settings (token, cron, scope, scoring thresholds)

**`github_audit_report`** — audit run results: scores, grades, finding counts by severity, full report JSON

---

### Infrastructure & Licensing

**`event_sources`** — OpenSearch index pattern definitions per customer
Key fields: `customer_code`, `name`, `index_pattern`, `event_type`, `time_field`, `enabled`

**`log_entries`** — API audit log
Key fields: `timestamp`, `event_type`, `user_id`, `route`, `method`, `status_code`, `message`

**`license`** / **`license_cache`** — license key + per-feature cache with TTL

---

## Common Query Patterns

### All customers and their onboarding date
```sql
SELECT customer_code, customer_name, customer_type, created_at
FROM customers
ORDER BY created_at DESC;
```

### Active agents for a customer
```sql
SELECT hostname, ip_address, os, wazuh_agent_status, wazuh_last_seen, critical_asset, quarantined
FROM agents
WHERE customer_code = 'customer_code_here'
  AND wazuh_agent_status = 'active'
ORDER BY wazuh_last_seen DESC;
```

### Open alerts for a customer
```sql
SELECT id, alert_name, status, source, assigned_to, alert_creation_time
FROM incident_management_alert
WHERE customer_code = 'customer_code_here'
  AND status != 'closed'
ORDER BY alert_creation_time DESC
LIMIT 50;
```

### Critical/High vulnerabilities for a customer
```sql
SELECT agent_id, cve_id, severity, title, package_name, discovered_at, epss_score
FROM agent_vulnerabilities
WHERE customer_code = 'customer_code_here'
  AND severity IN ('Critical', 'High')
  AND status != 'remediated'
ORDER BY discovered_at DESC
LIMIT 50;
```

### Which integrations are deployed for a customer
```sql
SELECT integration_service_name, deployed
FROM customer_integrations
WHERE customer_code = 'customer_code_here'
ORDER BY integration_service_name;
```

### Alert → asset → OpenSearch (full event detail)
```sql
-- Step 1: get alerts with their OpenSearch pointers
SELECT
  a.id AS alert_id,
  a.alert_name,
  a.source,
  a.status,
  a.alert_creation_time,
  ast.asset_name,
  ast.agent_id,
  ast.index_name,
  ast.index_id
FROM incident_management_alert a
JOIN incident_management_asset ast ON ast.alert_linked = a.id
WHERE a.customer_code = 'customer_code_here'
  AND ast.index_name != ''
  AND ast.index_id != ''
ORDER BY a.alert_creation_time DESC
LIMIT 20;

-- Step 2: for each row, fetch the raw event from OpenSearch using:
--   index  = index_name  (e.g. new-wazuh_110)
--   id     = index_id    (e.g. 8feb28e2-4f86-11ef-97f7-8600007a2218)
-- Use the OpenSearch get_document MCP tool with those two values.
```

### Alert → case linkage
```sql
SELECT a.id AS alert_id, a.alert_name, c.case_name, c.case_status
FROM incident_management_alert a
JOIN incident_management_casealertlink l ON l.alert_id = a.id
JOIN incident_management_case c ON c.id = l.case_id
WHERE a.customer_code = 'customer_code_here'
LIMIT 20;
```

### IOCs linked to an alert
```sql
SELECT i.value, i.type, i.description
FROM incident_management_ioc i
JOIN incident_management_alert_to_ioc m ON m.ioc_id = i.id
WHERE m.alert_id = 123;
```

### Users and their customer access
```sql
SELECT u.username, u.email, r.name AS role, uca.customer_code
FROM user u
JOIN role r ON r.id = u.role_id
LEFT JOIN user_customer_access uca ON uca.user_id = u.id
ORDER BY u.username;
```
