// Usage metering + per-key rate limiting.
// - D1 holds rolling per-month request counters and an audit log of detections.
// - KV `RATE` holds short-lived per-second token buckets.

import type { D1Database, KVNamespace } from "@cloudflare/workers-types";
import { KeyRecord } from "./auth";

const RATE_WINDOW_MS = 1000;
const RATE_LIMIT_PER_SEC = 100;

export async function checkRate(kv: KVNamespace, apiKey: string): Promise<boolean> {
  const bucket = "rate:" + apiKey + ":" + Math.floor(Date.now() / RATE_WINDOW_MS);
  const cur = parseInt((await kv.get(bucket)) || "0", 10);
  if (cur >= RATE_LIMIT_PER_SEC) return false;
  await kv.put(bucket, String(cur + 1), { expirationTtl: 5 });
  return true;
}

export async function ensureUsageRow(db: D1Database, apiKey: string, month: string) {
  await db
    .prepare(
      `INSERT OR IGNORE INTO usage (api_key, month, count, blocked) VALUES (?, ?, 0, 0)`
    )
    .bind(apiKey, month)
    .run();
}

export function currentMonth(): string {
  const d = new Date();
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
}

export async function getUsage(db: D1Database, apiKey: string, month: string): Promise<number> {
  const row = await db
    .prepare(`SELECT count FROM usage WHERE api_key = ? AND month = ?`)
    .bind(apiKey, month)
    .first<{ count: number }>();
  return row?.count ?? 0;
}

export async function bumpUsage(
  db: D1Database,
  apiKey: string,
  month: string,
  blocked: boolean,
): Promise<void> {
  await ensureUsageRow(db, apiKey, month);
  await db
    .prepare(
      `UPDATE usage SET count = count + 1, blocked = blocked + ? WHERE api_key = ? AND month = ?`
    )
    .bind(blocked ? 1 : 0, apiKey, month)
    .run();
}

export async function logScan(
  db: D1Database,
  args: {
    apiKey: string;
    requestId: string;
    context: string;
    confidence: number;
    safe: boolean;
    threat: string;
    textLen: number;
    text?: string; // omitted in no-logging mode
  },
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO scans (api_key, request_id, ts, context, confidence, safe, threat, text_len, text_sample)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      args.apiKey,
      args.requestId,
      Date.now(),
      args.context,
      args.confidence,
      args.safe ? 1 : 0,
      args.threat,
      args.textLen,
      args.text ? args.text.slice(0, 500) : null,
    )
    .run();
}

export async function overLimit(
  db: D1Database,
  record: KeyRecord,
  apiKey: string,
): Promise<{ over: boolean; used: number; limit: number }> {
  const month = currentMonth();
  const used = await getUsage(db, apiKey, month);
  return { over: used >= record.monthly_limit, used, limit: record.monthly_limit };
}
