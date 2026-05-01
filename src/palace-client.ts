import { spawn } from 'child_process';
import path from 'path';

import { logger } from './logger.js';

const PALACE_CALL_SCRIPT = path.join(
  process.cwd(),
  'mempalace',
  'palace-call.sh',
);

const PALACE_TIMEOUT_MS = 30_000;

export type LessonType =
  | 'environment'
  | 'false_positives'
  | 'assets'
  | 'threat_intel';

export type Durability = 'one_off' | 'durable';

export interface AddLessonInput {
  customer_code: string;
  lesson_type: LessonType;
  lesson_text: string;
  durability?: Durability;
}

export interface SearchInput {
  customer_code: string;
  room?: LessonType;
  query: string;
  limit?: number;
}

export interface ForgetLessonInput {
  drawer_id: string;
}

export const VALID_LESSON_TYPES: ReadonlySet<LessonType> = new Set([
  'environment',
  'false_positives',
  'assets',
  'threat_intel',
]);

function runPalaceCall(payload: object): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const child = spawn(PALACE_CALL_SCRIPT, [], {
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(
        new Error(`palace-call.sh timed out after ${PALACE_TIMEOUT_MS}ms`),
      );
    }, PALACE_TIMEOUT_MS);

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });

    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });

    child.on('close', (code) => {
      clearTimeout(timer);
      if (stderr.trim()) {
        logger.debug({ stderr }, 'palace-call.sh stderr');
      }
      if (code !== 0) {
        reject(
          new Error(
            `palace-call.sh exited ${code}: ${stderr.trim() || stdout.trim()}`,
          ),
        );
        return;
      }
      // Defensive parse: mempalace's own logging or chromadb internals
      // can occasionally print to stdout despite palace_call.py's
      // contextlib.redirect_stdout. Rather than fail the whole call when
      // a stray log line precedes the JSON, scan from the bottom for the
      // last `{...}` line and parse that. The python wrapper always
      // writes the response as the final line.
      const tryParse = (raw: string): unknown | undefined => {
        try {
          return JSON.parse(raw);
        } catch {
          return undefined;
        }
      };
      const direct = tryParse(stdout.trim());
      if (direct !== undefined) {
        resolve(direct);
        return;
      }
      const lines = stdout
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => l.startsWith('{') && l.endsWith('}'));
      for (let i = lines.length - 1; i >= 0; i--) {
        const parsed = tryParse(lines[i]);
        if (parsed !== undefined) {
          logger.warn(
            { discarded: stdout.slice(0, 200) },
            'palace-call.sh emitted non-JSON noise on stdout; recovered last JSON line',
          );
          resolve(parsed);
          return;
        }
      }
      reject(
        new Error(`palace-call.sh returned non-JSON: ${stdout.slice(0, 200)}`),
      );
    });

    child.stdin.write(JSON.stringify(payload));
    child.stdin.end();
  });
}

export async function addLesson(input: AddLessonInput): Promise<unknown> {
  const durability = input.durability || 'durable';
  return runPalaceCall({
    op: 'add_drawer',
    wing: input.customer_code,
    room: input.lesson_type,
    content: input.lesson_text,
    source_file: `review_lesson:${durability}`,
    added_by: 'copilot-review',
  });
}

export async function searchPalace(input: SearchInput): Promise<unknown> {
  return runPalaceCall({
    op: 'search',
    query: input.query,
    wing: input.customer_code,
    room: input.room,
    limit: input.limit ?? 5,
  });
}

// Durability sweeper: CoPilot tracks drawer_ids returned from add_drawer
// and calls this to remove expired one-off lessons from the palace.
// The mempalace tool returns {success: bool, drawer_id, error?}.
export async function forgetLesson(input: ForgetLessonInput): Promise<unknown> {
  return runPalaceCall({
    op: 'delete_drawer',
    drawer_id: input.drawer_id,
  });
}
