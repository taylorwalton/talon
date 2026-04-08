import http from 'http';
import path from 'path';

import { createTask, getTaskById, getTasksForGroup } from '../db.js';
import { logger } from '../logger.js';
import { computeNextRun } from '../task-scheduler.js';
import { registerChannel, ChannelOpts } from './registry.js';
import { WEBHOOK_JID } from './webhook.js';
import { Channel, RegisteredGroup } from '../types.js';

const COPILOT_JID = process.env.COPILOT_JID || 'http:copilot';
const COPILOT_GROUP_FOLDER = process.env.COPILOT_GROUP_FOLDER || 'copilot';
const COPILOT_HTTP_PORT = parseInt(process.env.COPILOT_HTTP_PORT || '3100', 10);

interface SseWriter {
  res: http.ServerResponse;
  resolve: () => void;
}

export class HttpChannel implements Channel {
  name = 'http';

  private server: http.Server | null = null;
  private opts: ChannelOpts;
  private startedAt = Date.now();
  private activeInvestigations = 0;

  // FIFO queue: each POST /message enqueues a writer; setTyping(true) dequeues it
  private pendingQueue: SseWriter[] = [];
  private currentWriter: SseWriter | null = null;

  constructor(opts: ChannelOpts) {
    this.opts = opts;
  }

  private seedAlertDigestTask(): void {
    const TASK_ID = 'copilot-alert-digest-15m';
    if (getTaskById(TASK_ID)) return;

    const task = {
      id: TASK_ID,
      group_folder: COPILOT_GROUP_FOLDER,
      chat_jid: WEBHOOK_JID,
      schedule_type: 'cron' as const,
      schedule_value: '*/15 * * * *',
      context_mode: 'group' as const,
      status: 'active' as const,
      created_at: new Date().toISOString(),
      next_run: null as string | null,
      prompt: `You are running as a scheduled SOC monitor. Follow these steps exactly for each alert.

1. Query MySQL for OPEN alerts with no completed AI investigation:

   SELECT a.id, a.alert_name, a.source, a.alert_creation_time,
          a.customer_code, ast.asset_name, ast.agent_id,
          ast.index_name, ast.index_id
   FROM incident_management_alert a
   JOIN incident_management_asset ast ON ast.alert_linked = a.id
   WHERE a.status = 'OPEN'
     AND a.alert_creation_time >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)
     AND ast.index_name != ''
     AND ast.index_id != ''
   ORDER BY a.alert_creation_time DESC;

2. If no rows are returned, stop here. Do not send any message.

3. For each alert:

   a. DEDUPLICATION — call ListAiAnalystJobsByAlertTool(alert_id=<id>).
      If a job with status "completed" already exists, skip this alert.

   b. REGISTER JOB — call CreateAiAnalystJobTool:
        id="copilot-inv-<alert_id>-<unix_timestamp>"
        alert_id=<id>, customer_code=<code>, triggered_by="scheduled"
      Then immediately call UpdateAiAnalystJobTool(job_id=<id>, status="running").

   c. FETCH INDEX MAPPING + RAW EVENT in parallel:
      - get_document(index_name, index_id) → full raw alert event
      - get_index(index_name) → field mapping (confirms field names and types)
      Use the mapping before writing any OpenSearch query.

   d. DETECT ALERT TYPE from the raw event:
      - Check rule.groups array for an entry matching sysmon_event_<N>
      - If not found, map data.win.system.eventID:
          1→sysmon_event_1, 3→sysmon_event_3, 7→sysmon_event_7,
          11→sysmon_event_11, 22→sysmon_event_22

   e. LOAD TEMPLATE — Read /workspace/group/prompts/<alert_type>.txt.
      If found, follow its steps substituting:
        {{ alert }} → raw OpenSearch event JSON
        {{ event_id }} → numeric event ID
        {{ pipeline | default('wazuh') }} → wazuh
        {{ virustotal_results }} → VT results after threat intel
      If no template, use the default steps below.

   f. DEFAULT INVESTIGATION (when no template matches):
      - Extract IOCs: IPs (data.win.eventdata.destinationIp, data.srcip, data.dstip),
        domains (data.win.eventdata.queryName, data.win.eventdata.destinationHostname),
        hashes (data.win.eventdata.hashes), processes (data.win.eventdata.image,
        data.win.eventdata.parentImage), commands (data.win.eventdata.commandLine)
      - For each external IP/domain: WebSearch "<value>" site:virustotal.com
      - For each SHA256 hash: WebFetch https://www.virustotal.com/gui/file/<hash>
      - Check rule.level, rule.description, rule.mitre.tactic

   g. WRITE BACK TO COPILOT — call in order:
      1. UpdateAiAnalystJobTool(job_id=<id>, status="completed",
           template_used=<alert_type or null>)
      2. SubmitAiAnalystReportTool(
           job_id=<id>, alert_id=<id>, customer_code=<code>,
           severity_assessment=<Critical|High|Medium|Low|Informational>,
           summary=<1-2 sentence tl;dr>,
           report_markdown=<full markdown report>,
           recommended_actions=<action list>)
         → note the returned report_id
      3. SubmitAiAnalystIocsTool(
           report_id=<from step 2>, alert_id=<id>, customer_code=<code>,
           iocs=[{ ioc_value, ioc_type, vt_verdict, vt_score, details }, ...])
         ioc_type: ip|domain|hash|process|url|user|command
         vt_verdict: malicious|suspicious|clean|unknown

   h. SEND REPORT via send_message:
      🔍 **SOC Investigation** — <alert_name>
      Customer: <customer_code> | Asset: <asset_name> | Created: <alert_creation_time>
      **Severity**: <assessment> | **Template**: <alert_type or "default">

      **Alert Summary**: rule description, MITRE tactic/technique
      **IOC Analysis**: table of IOCs with type and VT verdict
      **Severity Assessment**: reasoning
      **Recommended Actions**: specific actionable steps

      On any error during write-back, call UpdateAiAnalystJobTool with
      status="failed" and error_message=<exception details>.`,
    };

    const fullTask = { ...task, last_run: null, last_result: null };
    fullTask.next_run = computeNextRun(fullTask);
    createTask(fullTask);
    logger.info(
      { taskId: TASK_ID },
      'Seeded CoPilot alert digest scheduled task',
    );
  }

  async connect(): Promise<void> {
    // Self-register the copilot group so NanoClaw routes messages to it.
    // The siem/ directory is mounted at /workspace/extra/siem so the agent-runner
    // discovers it as an additional directory: CLAUDE.md is loaded automatically
    // and the opensearch-mcp.sh script is available for the MCP server.
    const group: RegisteredGroup = {
      name: 'CoPilot',
      folder: COPILOT_GROUP_FOLDER,
      trigger: '',
      added_at: new Date().toISOString(),
      requiresTrigger: false,
      containerConfig: {
        additionalMounts: [
          {
            hostPath: path.join(process.cwd(), 'siem'),
            containerPath: 'siem',
            readonly: true,
          },
          {
            hostPath: path.join(process.cwd(), 'mysql'),
            containerPath: 'mysql',
            readonly: true,
          },
          {
            hostPath: path.join(process.cwd(), 'copilot-mcp'),
            containerPath: 'copilot-mcp',
            readonly: true,
          },
          {
            hostPath: path.join(process.cwd(), 'ollama'),
            containerPath: 'ollama',
            readonly: true,
          },
          {
            hostPath: path.join(process.cwd(), 'mempalace'),
            containerPath: 'mempalace',
            readonly: true,
          },
          {
            hostPath: path.join(process.cwd(), 'mempalace-data'),
            containerPath: 'mempalace-data',
            readonly: false,
          },
        ],
      },
    };
    this.opts.registerGroup?.(COPILOT_JID, group);
    this.seedAlertDigestTask();

    this.opts.onChatMetadata(
      COPILOT_JID,
      new Date().toISOString(),
      'CoPilot',
      'http',
      false,
    );

    this.server = http.createServer((req, res) => {
      if (req.method === 'GET' && req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', channel: 'http' }));
        return;
      }

      if (req.method === 'GET' && req.url === '/status') {
        const tasks = getTasksForGroup(COPILOT_GROUP_FOLDER);
        const uptime = Math.floor((Date.now() - this.startedAt) / 1000);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            status: 'ok',
            uptime_seconds: uptime,
            active_investigations: this.activeInvestigations,
            pending_queue_depth: this.pendingQueue.length,
            scheduled_tasks: tasks.map((t) => ({
              id: t.id,
              status: t.status,
              schedule_type: t.schedule_type,
              schedule_value: t.schedule_value,
              next_run: t.next_run,
              last_run: t.last_run,
            })),
          }),
        );
        return;
      }

      if (req.method === 'POST' && req.url === '/investigate') {
        let body = '';
        req.on('data', (chunk) => {
          body += chunk;
        });
        req.on('end', () => {
          let parsed: {
            alert_id?: number;
            customer_code?: string;
            triggered_by?: string;
          } = {};
          try {
            parsed = JSON.parse(body);
          } catch {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid JSON' }));
            return;
          }

          const { alert_id, customer_code } = parsed;
          if (!alert_id || !customer_code) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({ error: 'alert_id and customer_code required' }),
            );
            return;
          }

          const triggered_by = parsed.triggered_by || 'webhook';
          const jobId = `copilot-inv-${alert_id}-${Date.now()}`;

          const prompt = `You are running a targeted SOC investigation triggered by CoPilot. Follow the full investigation workflow from CLAUDE.md.

Alert to investigate:
- alert_id: ${alert_id}
- customer_code: ${customer_code}
- job_id: ${jobId}
- triggered_by: ${triggered_by}

Steps:
1. Skip Step 0 deduplication — this job has already been registered by the caller with id="${jobId}". Call UpdateAiAnalystJobTool(job_id="${jobId}", status="running") immediately.
2. Pull the alert from MySQL using alert_id=${alert_id} and customer_code="${customer_code}".
3. Follow Steps 2–6 from CLAUDE.md exactly (fetch raw event + index mapping, detect alert type, load template, extract IOCs, threat intel, SIEM correlation).
4. Write back to CoPilot using job_id="${jobId}" and the report/IOC tools.
5. Send the full investigation report via send_message.`;

          this.opts.onMessage(COPILOT_JID, {
            id: `investigate-${jobId}`,
            chat_jid: COPILOT_JID,
            sender: 'copilot-webhook',
            sender_name: 'CoPilot',
            content: prompt,
            timestamp: new Date().toISOString(),
            is_from_me: false,
          });

          logger.info(
            { alert_id, customer_code, jobId, triggered_by },
            'HTTP channel: investigation queued',
          );

          res.writeHead(202, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ job_id: jobId, status: 'queued' }));
        });
        return;
      }

      if (req.method === 'OPTIONS') {
        res.writeHead(204, {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
        });
        res.end();
        return;
      }

      if (req.method === 'POST' && req.url === '/message') {
        let body = '';
        req.on('data', (chunk) => {
          body += chunk;
        });
        req.on('end', () => {
          let parsed: { message?: string; sender?: string } = {};
          try {
            parsed = JSON.parse(body);
          } catch {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid JSON' }));
            return;
          }

          const message = parsed.message?.trim();
          if (!message) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'message field required' }));
            return;
          }

          const senderName = parsed.sender || 'copilot';

          // Start SSE response
          res.writeHead(200, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            Connection: 'keep-alive',
            'Access-Control-Allow-Origin': '*',
          });

          // Hold the SSE connection open until the agent finishes.
          // Use res.on('close') — fires when the client disconnects.
          // req.on('close') fires when the POST body is consumed (almost immediately).
          new Promise<void>((resolve) => {
            const writer: SseWriter = { res, resolve };
            this.pendingQueue.push(writer);

            res.on('close', () => {
              const idx = this.pendingQueue.indexOf(writer);
              if (idx !== -1) this.pendingQueue.splice(idx, 1);
              if (this.currentWriter === writer) this.currentWriter = null;
              resolve();
            });

            // Route into NanoClaw's pipeline — GroupQueue → container → agent
            this.opts.onMessage(COPILOT_JID, {
              id: `http-${Date.now()}`,
              chat_jid: COPILOT_JID,
              sender: senderName,
              sender_name: senderName,
              content: message,
              timestamp: new Date().toISOString(),
              is_from_me: false,
            });

            logger.info(
              { sender: senderName, length: message.length },
              'HTTP channel: message received',
            );
          });
        });
        return;
      }

      res.writeHead(404);
      res.end();
    });

    return new Promise<void>((resolve, reject) => {
      this.server!.listen(COPILOT_HTTP_PORT, () => {
        logger.info({ port: COPILOT_HTTP_PORT }, 'HTTP channel listening');
        console.log(`\n  HTTP channel: http://localhost:${COPILOT_HTTP_PORT}`);
        console.log(
          `  POST /message     { "message": "...", "sender": "..." }`,
        );
        console.log(
          `  POST /investigate { "alert_id": 123, "customer_code": "acme" }`,
        );
        console.log(`  GET  /status`);
        console.log(`  GET  /health\n`);
        resolve();
      });
      this.server!.on('error', reject);
    });
  }

  async sendMessage(_jid: string, text: string): Promise<void> {
    if (!this.currentWriter) {
      logger.warn('HTTP channel: sendMessage called with no active SSE writer');
      return;
    }
    const event = JSON.stringify({ type: 'text', content: text });
    this.currentWriter.res.write(`data: ${event}\n\n`);
    logger.info({ length: text.length }, 'HTTP channel: wrote SSE text chunk');
  }

  async setTyping(_jid: string, isTyping: boolean): Promise<void> {
    if (isTyping) {
      this.activeInvestigations++;
      // Agent is starting — dequeue the next waiting SSE writer
      if (this.pendingQueue.length > 0) {
        this.currentWriter = this.pendingQueue.shift()!;
        logger.info(
          { remainingQueue: this.pendingQueue.length },
          'HTTP channel: dequeued SSE writer',
        );
      } else {
        logger.warn('HTTP channel: setTyping(true) but no pending SSE writer');
      }
    } else {
      // setTyping(false) fires when the container exits (~30 min idle timeout).
      // onTurnComplete already closed the stream when the agent finished the turn.
      // This is just a safety net in case onTurnComplete wasn't called.
      this.activeInvestigations = Math.max(0, this.activeInvestigations - 1);
      if (this.currentWriter) {
        logger.warn(
          'HTTP channel: setTyping(false) called with active writer — closing via safety net',
        );
        const event = JSON.stringify({ type: 'done' });
        this.currentWriter.res.write(`data: ${event}\n\n`);
        this.currentWriter.res.end();
        this.currentWriter.resolve();
        this.currentWriter = null;
      }
    }
  }

  async onTurnComplete(_jid: string): Promise<void> {
    // Called when result.status === 'success' — close the SSE stream immediately
    // rather than waiting for the container's idle timeout.
    this.activeInvestigations = Math.max(0, this.activeInvestigations - 1);
    if (this.currentWriter) {
      const event = JSON.stringify({ type: 'done' });
      this.currentWriter.res.write(`data: ${event}\n\n`);
      this.currentWriter.res.end();
      this.currentWriter.resolve();
      this.currentWriter = null;
      logger.info('HTTP channel: SSE stream closed (turn complete)');
    }
  }

  isConnected(): boolean {
    return this.server !== null;
  }

  ownsJid(jid: string): boolean {
    return jid === COPILOT_JID;
  }

  async disconnect(): Promise<void> {
    if (this.server) {
      this.server.close();
      this.server = null;
      logger.info('HTTP channel stopped');
    }
  }
}

registerChannel('http', (opts: ChannelOpts) => {
  return new HttpChannel(opts);
});
