import http from 'http';
import path from 'path';

import { createTask, getTaskById } from '../db.js';
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
      prompt: `You are running as a scheduled SOC monitor. Follow these steps exactly:

1. Query the CoPilot MySQL database for all OPEN alerts created in the
   last 15 minutes across all customers:

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

3. For each alert, run a full investigation:

   a. In parallel, fetch from OpenSearch using index_name and index_id:
      - get_document (index_name, index_id) → the full raw alert event
      - get_index (index_name) → the field mapping for this index
      Use the mapping to confirm exact field names and types (keyword vs text)
      before building any search or aggregation query.

   b. Detect the alert type from the raw event (check in order):
      - Look at rule.groups (array) for an entry matching sysmon_event_<N>
        (e.g. sysmon_event_1, sysmon_event_3, sysmon_event_7).
      - If not found, map data.win.system.eventID:
          1  → sysmon_event_1  (Process Creation)
          3  → sysmon_event_3  (Network Connection)
          7  → sysmon_event_7  (Image Load / DLL)
          11 → sysmon_event_11 (File Create)
          22 → sysmon_event_22 (DNS Query)

   c. Load the investigation template:
      - Read /workspace/group/prompts/<alert_type>.txt
        (e.g. /workspace/group/prompts/sysmon_event_1.txt)
      - If the file exists, follow the analysis steps it defines.
        Substitute template variables as follows:
          {{ alert }}                      → the full raw OpenSearch event JSON
          {{ event_id }}                   → the numeric event ID (e.g. 1)
          {{ pipeline | default('wazuh') }} → wazuh
          {{ virustotal_results }}         → your VT results after threat intel
      - If no template file exists, use the default steps below.

   d. Default investigation steps (when no template matches):
      - Extract all IOCs from the raw event:
          IPs     → data.win.eventdata.destinationIp, data.srcip, data.dstip
          Domains → data.win.eventdata.queryName, data.win.eventdata.destinationHostname
          Hashes  → data.win.eventdata.hashes (MD5, SHA1, SHA256)
          Processes → data.win.eventdata.image, data.win.eventdata.parentImage
          Commands  → data.win.eventdata.commandLine
      - For each external IP or domain: WebSearch "<value>" site:virustotal.com
      - For each SHA256 hash: WebFetch https://www.virustotal.com/gui/file/<hash>
      - Note rule.level, rule.description, and rule.mitre.tactic

   e. Send a full investigation report via send_message for each alert:

      🔍 **SOC Investigation** — <alert_name>
      Customer: <customer_code> | Asset: <asset_name> | Created: <alert_creation_time>

      <Full investigation findings following the template format, or:>

      **Alert Summary**: rule description, severity level, MITRE tactic/technique
      **IOC Analysis**: table of IOCs with type and VT verdict
      **Severity Assessment**: Critical / High / Medium / Low with reasoning
      **Recommended Actions**: specific, actionable next steps`,
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
        console.log(`  POST /message  { "message": "...", "sender": "..." }`);
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
