// Postgres-backed storage for PromptShield (Railway adapter).
// Replaces Cloudflare KV (keys, rate-limit) and D1 (usage, scans) with a
// single pg pool. Rate limiting uses in-process token buckets.

import { Pool } from "pg";
import { randomUUID, createHash } from "crypto";

export type Tier = "free" | "hobby" | "team" | "pro";

export interface KeyRecord {
  api_key: string;
  email: string;
  tier: Tier;
  created: number;
  monthly_limit: number;
  stripe_customer?: string | null;
  stripe_subscription?: string | null;
  no_logging?: boolean;
}

const TIER_LIMITS: Record<Tier, number> = {
  free: 10_000,
  hobby: 500_000,
  team: 5_000_000,
  pro: 100_000_000,
};

export function keyTierLimit(tier: Tier): number { return TIER_LIMITS[tier]; }
export function newApiKey(): string { return "ps_live_" + randomUUID().replace(/-/g, ""); }

let pool: Pool | null = null;
export function getPool(databaseUrl: string): Pool {
  if (!pool) {
    pool = new Pool({
      connectionString: databaseUrl,
      ssl: databaseUrl.includes("railway") ? { rejectUnauthorized: false } : undefined,
      max: 10,
    });
  }
  return pool;
}

export async function migrate(p: Pool): Promise<void> {
  await p.query(`
    CREATE TABLE IF NOT EXISTS keys (
      api_key TEXT PRIMARY KEY,
      email TEXT NOT NULL,
      tier TEXT NOT NULL DEFAULT 'free',
      created BIGINT NOT NULL,
      monthly_limit BIGINT NOT NULL,
      stripe_customer TEXT,
      stripe_subscription TEXT,
      no_logging BOOLEAN NOT NULL DEFAULT FALSE
    );
    CREATE INDEX IF NOT EXISTS idx_keys_email ON keys (email);

    CREATE TABLE IF NOT EXISTS usage (
      api_key TEXT NOT NULL,
      month TEXT NOT NULL,
      count BIGINT NOT NULL DEFAULT 0,
      blocked BIGINT NOT NULL DEFAULT 0,
      PRIMARY KEY (api_key, month)
    );

    CREATE TABLE IF NOT EXISTS scans (
      id BIGSERIAL PRIMARY KEY,
      api_key TEXT NOT NULL,
      request_id TEXT NOT NULL,
      ts BIGINT NOT NULL,
      context TEXT,
      confidence REAL,
      safe BOOLEAN,
      threat TEXT,
      text_len INT,
      text_sample TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_scans_apikey_ts ON scans (api_key, ts DESC);
    CREATE INDEX IF NOT EXISTS idx_scans_threat ON scans (threat);

    CREATE TABLE IF NOT EXISTS signup_throttle (
      ip TEXT NOT NULL,
      day TEXT NOT NULL,
      count INT NOT NULL DEFAULT 0,
      PRIMARY KEY (ip, day)
    );
  `);
}

export async function createKey(
  p: Pool,
  email: string,
  tier: Tier = "free",
  extra: Partial<KeyRecord> = {},
): Promise<KeyRecord> {
  const apiKey = extra.api_key || newApiKey();
  const record: KeyRecord = {
    api_key: apiKey,
    email,
    tier,
    created: Date.now(),
    monthly_limit: TIER_LIMITS[tier],
    stripe_customer: extra.stripe_customer ?? null,
    stripe_subscription: extra.stripe_subscription ?? null,
    no_logging: !!extra.no_logging,
  };
  await p.query(
    `INSERT INTO keys (api_key, email, tier, created, monthly_limit, stripe_customer, stripe_subscription, no_logging)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [
      record.api_key, record.email, record.tier, record.created,
      record.monthly_limit, record.stripe_customer, record.stripe_subscription, record.no_logging,
    ],
  );
  return record;
}

export async function getKey(p: Pool, apiKey: string): Promise<KeyRecord | null> {
  if (!apiKey || !apiKey.startsWith("ps_")) return null;
  const r = await p.query(`SELECT * FROM keys WHERE api_key = $1`, [apiKey]);
  return (r.rows[0] as KeyRecord) || null;
}

export async function updateKey(p: Pool, apiKey: string, patch: Partial<KeyRecord>): Promise<KeyRecord | null> {
  const cur = await getKey(p, apiKey);
  if (!cur) return null;
  const next = { ...cur, ...patch };
  await p.query(
    `UPDATE keys SET tier=$2, monthly_limit=$3, stripe_customer=$4, stripe_subscription=$5, no_logging=$6 WHERE api_key=$1`,
    [
      apiKey, next.tier, next.monthly_limit,
      next.stripe_customer ?? null, next.stripe_subscription ?? null, !!next.no_logging,
    ],
  );
  return next;
}

export async function keysForEmail(p: Pool, email: string): Promise<string[]> {
  const r = await p.query(`SELECT api_key FROM keys WHERE email = $1 ORDER BY created ASC`, [email]);
  return r.rows.map((row: any) => row.api_key);
}

export function currentMonth(): string {
  const d = new Date();
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
}

export async function getUsage(p: Pool, apiKey: string, month: string): Promise<number> {
  const r = await p.query(`SELECT count FROM usage WHERE api_key=$1 AND month=$2`, [apiKey, month]);
  return r.rows[0]?.count ? Number(r.rows[0].count) : 0;
}

export async function bumpUsage(p: Pool, apiKey: string, month: string, blocked: boolean): Promise<void> {
  await p.query(
    `INSERT INTO usage (api_key, month, count, blocked) VALUES ($1,$2,1,$3)
     ON CONFLICT (api_key, month) DO UPDATE
     SET count = usage.count + 1,
         blocked = usage.blocked + EXCLUDED.blocked`,
    [apiKey, month, blocked ? 1 : 0],
  );
}

export async function logScan(p: Pool, args: {
  apiKey: string; requestId: string; context: string;
  confidence: number; safe: boolean; threat: string;
  textLen: number; text?: string;
}): Promise<void> {
  await p.query(
    `INSERT INTO scans (api_key, request_id, ts, context, confidence, safe, threat, text_len, text_sample)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [
      args.apiKey, args.requestId, Date.now(), args.context,
      args.confidence, args.safe, args.threat, args.textLen,
      args.text ? args.text.slice(0, 500) : null,
    ],
  );
}

// In-process per-second rate limiter — fine for a single Railway dyno.
// Behind a load balancer with multiple replicas, swap for Redis.
const RATE_BUCKETS = new Map<string, { ts: number; count: number }>();
const RATE_LIMIT_PER_SEC = 100;
export function checkRate(apiKey: string): boolean {
  const sec = Math.floor(Date.now() / 1000);
  const k = apiKey + ":" + sec;
  const cur = RATE_BUCKETS.get(k);
  // GC old keys lazily.
  if (RATE_BUCKETS.size > 5000) {
    for (const [bk, bv] of RATE_BUCKETS) {
      if (sec - bv.ts > 5) RATE_BUCKETS.delete(bk);
    }
  }
  if (!cur) { RATE_BUCKETS.set(k, { ts: sec, count: 1 }); return true; }
  if (cur.count >= RATE_LIMIT_PER_SEC) return false;
  cur.count++;
  return true;
}

// Signup throttle: 5 keys per IP per day.
export async function bumpSignupThrottle(p: Pool, ip: string): Promise<number> {
  const day = new Date().toISOString().slice(0, 10);
  const r = await p.query(
    `INSERT INTO signup_throttle (ip, day, count) VALUES ($1,$2,1)
     ON CONFLICT (ip, day) DO UPDATE SET count = signup_throttle.count + 1
     RETURNING count`,
    [ip, day],
  );
  return r.rows[0].count as number;
}

// Hashed lookup for "what keys belong to this email" used on Stripe webhook —
// safe because we never expose key values, only allow promotion of an existing
// key to a new tier.
export function fingerprint(s: string): string {
  return createHash("sha256").update(s).digest("hex").slice(0, 16);
}
