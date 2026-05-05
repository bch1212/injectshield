// API-key auth + key issuance.
// Keys are UUIDv4 prefixed `ps_live_` (live) or `ps_demo_` (free-tier sample).
// They're stored in KV (`KEYS` binding) keyed by `key:<plaintext>` so a single
// O(1) lookup validates and returns metadata.

import type { KVNamespace } from "@cloudflare/workers-types";

export type Tier = "free" | "hobby" | "team" | "pro";

export interface KeyRecord {
  email: string;
  tier: Tier;
  created: number;
  monthly_limit: number;
  stripe_customer?: string;
  stripe_subscription?: string;
  // True when no input text should be persisted in audit log.
  no_logging?: boolean;
}

const TIER_LIMITS: Record<Tier, number> = {
  free: 10_000,
  hobby: 500_000,
  team: 5_000_000,
  pro: 100_000_000,
};

export function tierFromPriceId(priceId: string): Tier | null {
  // Filled in by scripts/setup-stripe.mjs. We resolve by env var lookup at
  // worker startup, so this helper just exposes the mapping name space.
  return null;
}

export function keyTierLimit(tier: Tier): number {
  return TIER_LIMITS[tier];
}

function uuid(): string {
  // Worker runtime exposes crypto.randomUUID().
  return crypto.randomUUID().replace(/-/g, "");
}

export function newApiKey(): string {
  return "ps_live_" + uuid();
}

export async function createKey(
  kv: KVNamespace,
  email: string,
  tier: Tier = "free",
  extra: Partial<KeyRecord> = {},
): Promise<{ apiKey: string; record: KeyRecord }> {
  const apiKey = newApiKey();
  const record: KeyRecord = {
    email,
    tier,
    created: Date.now(),
    monthly_limit: TIER_LIMITS[tier],
    ...extra,
  };
  await kv.put("key:" + apiKey, JSON.stringify(record));
  // Index by email so Stripe webhooks can promote the right key on upgrade.
  const existing = (await kv.get<string[]>("email:" + email, "json")) || [];
  if (!existing.includes(apiKey)) existing.push(apiKey);
  await kv.put("email:" + email, JSON.stringify(existing));
  return { apiKey, record };
}

export async function getKey(kv: KVNamespace, apiKey: string): Promise<KeyRecord | null> {
  if (!apiKey || !apiKey.startsWith("ps_")) return null;
  return await kv.get<KeyRecord>("key:" + apiKey, "json");
}

export async function updateKey(
  kv: KVNamespace,
  apiKey: string,
  patch: Partial<KeyRecord>,
): Promise<KeyRecord | null> {
  const cur = await getKey(kv, apiKey);
  if (!cur) return null;
  const next = { ...cur, ...patch };
  await kv.put("key:" + apiKey, JSON.stringify(next));
  return next;
}

export async function keysForEmail(kv: KVNamespace, email: string): Promise<string[]> {
  return (await kv.get<string[]>("email:" + email, "json")) || [];
}

// Pull bearer or X-API-Key from a Request.
export function readApiKey(req: Request): string | null {
  const auth = req.headers.get("authorization") || "";
  const m = auth.match(/^bearer\s+(\S+)/i);
  if (m) return m[1];
  return req.headers.get("x-api-key");
}
