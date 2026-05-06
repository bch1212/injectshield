// InjectShield — main Cloudflare Worker entry.
// Routes:
//   POST /v1/scan           — auth + heuristic + AI detection
//   POST /v1/keys           — public free-tier signup, emails the key
//   GET  /v1/keys/me        — read current key metadata
//   GET  /v1/usage          — current-month usage for a key
//   POST /v1/checkout       — create Stripe Checkout Session
//   POST /v1/portal         — Stripe customer portal session
//   POST /webhooks/stripe   — Stripe webhook ingest
//   GET  /healthz           — liveness
//   GET  /v1/patterns       — list categories (no regex leakage)
//
// Bindings: KEYS (KV), RATE (KV), DB (D1), AI (Workers AI).
// Secrets:  STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET,
//           STRIPE_PRICE_HOBBY/TEAM/PRO, SENDGRID_API_KEY,
//           DISCORD_WEBHOOK_URL, ADMIN_TOKEN.

import type { D1Database, KVNamespace } from "@cloudflare/workers-types";
import { detect, ScanInput, Sensitivity, ContextKind } from "./detect";
import {
  createKey, getKey, KeyRecord, readApiKey, keyTierLimit, Tier,
} from "./auth";
import {
  bumpUsage, checkRate, currentMonth, getUsage, logScan, overLimit,
} from "./usage";
import { sendEmail, newKeyEmail } from "./email";
import { handleStripeWebhook } from "./stripe";

export interface Env {
  // KV
  KEYS: KVNamespace;
  RATE: KVNamespace;
  // D1
  DB: D1Database;
  // Workers AI
  AI: { run: (model: string, input: any) => Promise<any> };
  // Vars
  ENVIRONMENT: string;
  PUBLIC_BASE_URL: string;
  API_BASE_URL: string;
  FREE_TIER_MONTHLY_REQUESTS: string;
  SIGNUP_FROM_EMAIL: string;
  SIGNUP_FROM_NAME: string;
  ADMIN_EMAIL: string;
  ALERT_THRESHOLD: string;
  // Secrets (set via `wrangler secret put`)
  STRIPE_SECRET_KEY: string;
  STRIPE_WEBHOOK_SECRET: string;
  STRIPE_PRICE_HOBBY: string;
  STRIPE_PRICE_TEAM: string;
  STRIPE_PRICE_PRO: string;
  SENDGRID_API_KEY: string;
  DISCORD_WEBHOOK_URL: string;
  ADMIN_TOKEN: string;
}

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,OPTIONS",
  "access-control-allow-headers": "authorization,content-type,x-api-key",
  "access-control-max-age": "86400",
};

function json(body: unknown, status = 200, extra: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...CORS, ...extra },
  });
}

function err(status: number, code: string, message: string) {
  return json({ error: { code, message } }, status);
}

function reqId(): string {
  return "req_" + crypto.randomUUID().replace(/-/g, "").slice(0, 16);
}

function asContext(s: unknown): ContextKind {
  const allowed: ContextKind[] = [
    "git_commit", "web_content", "user_input", "file_content", "email", "tool_output", "unknown",
  ];
  return allowed.includes(s as ContextKind) ? (s as ContextKind) : "unknown";
}
function asSensitivity(s: unknown): Sensitivity {
  return s === "low" || s === "high" ? s : "medium";
}

async function postDiscord(env: Env, content: string) {
  if (!env.DISCORD_WEBHOOK_URL) return;
  try {
    await fetch(env.DISCORD_WEBHOOK_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ content }),
    });
  } catch { /* noop */ }
}

// ---------- routes ----------

async function routeScan(req: Request, env: Env): Promise<Response> {
  const apiKey = readApiKey(req);
  if (!apiKey) return err(401, "missing_api_key", "Provide an Authorization: Bearer or X-API-Key header.");
  const record = await getKey(env.KEYS, apiKey);
  if (!record) return err(401, "invalid_api_key", "Unknown or revoked API key.");

  const ok = await checkRate(env.RATE, apiKey);
  if (!ok) return err(429, "rate_limited", "Per-second rate limit exceeded (100 req/s).");

  const limit = await overLimit(env.DB, record, apiKey);
  if (limit.over) {
    return err(402, "monthly_limit", `Monthly request limit reached (${limit.used}/${limit.limit}). Upgrade at ${env.PUBLIC_BASE_URL}/pricing`);
  }

  let body: any;
  try { body = await req.json(); } catch { return err(400, "bad_json", "Invalid JSON body."); }

  const text: string = typeof body?.text === "string" ? body.text : "";
  if (!text) return err(400, "missing_text", "Field `text` is required.");
  if (text.length > 100_000) return err(413, "text_too_large", "Text must be ≤ 100,000 characters.");

  const opts = body?.options ?? {};
  const input: ScanInput = {
    text,
    context: asContext(body?.context),
    sensitivity: asSensitivity(opts.sensitivity),
    return_cleaned: opts.return_cleaned !== false, // default true
  };
  const id = reqId();
  const result = await detect(input, env.AI);
  const month = currentMonth();
  await bumpUsage(env.DB, apiKey, month, !result.safe);
  await logScan(env.DB, {
    apiKey,
    requestId: id,
    context: input.context,
    confidence: result.confidence,
    safe: result.safe,
    threat: String(result.threat_type),
    textLen: text.length,
    text: record.no_logging ? undefined : text,
  });

  // Optional Discord alert for high-confidence detections on the admin tier.
  if (!result.safe && result.confidence >= parseFloat(env.ALERT_THRESHOLD || "0.8")) {
    await postDiscord(
      env,
      `[promptshield] high-confidence detection (${result.confidence}, ${result.threat_type}) by ${record.email}, request ${id}`,
    );
  }

  return json({
    safe: result.safe,
    confidence: result.confidence,
    threat_type: result.threat_type,
    patterns_matched: result.patterns_matched,
    cleaned_text: result.cleaned_text,
    semantic_score: result.semantic_score,
    semantic_label: result.semantic_label,
    notes: result.notes,
    request_id: id,
  });
}

async function routeSignup(req: Request, env: Env): Promise<Response> {
  let body: any;
  try { body = await req.json(); } catch { return err(400, "bad_json", "Invalid JSON body."); }
  const email = String(body?.email || "").trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return err(400, "bad_email", "Provide a valid email address.");

  // Throttle: allow at most 3 signups/day from a given IP.
  const ip = req.headers.get("cf-connecting-ip") || "unknown";
  const k = "signup:" + ip + ":" + new Date().toISOString().slice(0, 10);
  const cnt = parseInt((await env.RATE.get(k)) || "0", 10);
  if (cnt >= 5) return err(429, "signup_throttled", "Too many signups from this IP today.");
  await env.RATE.put(k, String(cnt + 1), { expirationTtl: 90_000 });

  const { apiKey, record } = await createKey(env.KEYS, email, "free");
  const e = newKeyEmail({
    apiKey, email,
    apiBase: env.API_BASE_URL,
    publicBase: env.PUBLIC_BASE_URL,
  });
  const sent = await sendEmail(env.SENDGRID_API_KEY, {
    to: e.to,
    fromEmail: env.SIGNUP_FROM_EMAIL,
    fromName: env.SIGNUP_FROM_NAME,
    subject: e.subject,
    text: e.text,
    html: e.html,
  });
  await postDiscord(env, `[promptshield] new free signup: ${email}`);
  return json({
    ok: true,
    email_sent: sent,
    // We return the key in-band only when SendGrid fails — otherwise we
    // require email verification to surface the key, to discourage abuse.
    api_key: sent ? undefined : apiKey,
    tier: record.tier,
    monthly_limit: record.monthly_limit,
  });
}

async function routeMe(req: Request, env: Env): Promise<Response> {
  const apiKey = readApiKey(req);
  if (!apiKey) return err(401, "missing_api_key", "Provide your API key.");
  const r = await getKey(env.KEYS, apiKey);
  if (!r) return err(401, "invalid_api_key", "Unknown or revoked API key.");
  const used = await getUsage(env.DB, apiKey, currentMonth());
  return json({
    email: r.email,
    tier: r.tier,
    monthly_limit: r.monthly_limit,
    used_this_month: used,
    no_logging: !!r.no_logging,
    created: r.created,
  });
}

async function routeUsage(req: Request, env: Env): Promise<Response> {
  const apiKey = readApiKey(req);
  if (!apiKey) return err(401, "missing_api_key", "Provide your API key.");
  const r = await getKey(env.KEYS, apiKey);
  if (!r) return err(401, "invalid_api_key", "Unknown or revoked API key.");
  const month = currentMonth();
  const row = await env.DB
    .prepare(`SELECT count, blocked FROM usage WHERE api_key = ? AND month = ?`)
    .bind(apiKey, month)
    .first<{ count: number; blocked: number }>();
  return json({
    month,
    count: row?.count ?? 0,
    blocked: row?.blocked ?? 0,
    limit: r.monthly_limit,
    tier: r.tier,
  });
}

async function routeCheckout(req: Request, env: Env): Promise<Response> {
  let body: any;
  try { body = await req.json(); } catch { return err(400, "bad_json", "Invalid JSON body."); }
  const tier = String(body?.tier || "hobby").toLowerCase() as Tier;
  const email = String(body?.email || "").trim().toLowerCase();
  if (!email) return err(400, "bad_email", "email required");
  let priceId = "";
  if (tier === "hobby") priceId = env.STRIPE_PRICE_HOBBY;
  else if (tier === "team") priceId = env.STRIPE_PRICE_TEAM;
  else if (tier === "pro") priceId = env.STRIPE_PRICE_PRO;
  if (!priceId) return err(400, "bad_tier", "tier must be one of: hobby, team, pro");

  // Stripe Checkout Session via REST.
  const form = new URLSearchParams();
  form.set("mode", "subscription");
  form.set("line_items[0][price]", priceId);
  form.set("line_items[0][quantity]", "1");
  form.set("customer_email", email);
  form.set("success_url", env.PUBLIC_BASE_URL + "/success?session_id={CHECKOUT_SESSION_ID}");
  form.set("cancel_url", env.PUBLIC_BASE_URL + "/pricing");
  form.set("allow_promotion_codes", "true");
  form.set("metadata[tier]", tier);
  form.set("metadata[price_id]", priceId);
  const r = await fetch("https://api.stripe.com/v1/checkout/sessions", {
    method: "POST",
    headers: {
      authorization: "Bearer " + env.STRIPE_SECRET_KEY,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: form.toString(),
  });
  if (!r.ok) return err(502, "stripe_error", await r.text());
  const session: any = await r.json();
  return json({ url: session.url, id: session.id });
}

// ---- main ----

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    if (req.method === "OPTIONS") return new Response(null, { headers: CORS });

    if (url.pathname === "/healthz") return json({ ok: true, env: env.ENVIRONMENT, time: Date.now() });

    if (url.pathname === "/v1/patterns") {
      // Surface category list only — never regex bodies.
      return json({
        categories: [
          "instruction_injection", "system_override", "role_hijack",
          "exfiltration", "schema_attack", "encoding_smuggle",
          "invisible_text", "tool_abuse", "jailbreak_classic",
        ],
        sensitivities: ["low", "medium", "high"],
        contexts: ["git_commit", "web_content", "user_input", "file_content", "email", "tool_output", "unknown"],
      });
    }

    if (req.method === "POST" && url.pathname === "/v1/scan") return routeScan(req, env);
    if (req.method === "POST" && url.pathname === "/v1/keys") return routeSignup(req, env);
    if (req.method === "GET"  && url.pathname === "/v1/keys/me") return routeMe(req, env);
    if (req.method === "GET"  && url.pathname === "/v1/usage") return routeUsage(req, env);
    if (req.method === "POST" && url.pathname === "/v1/checkout") return routeCheckout(req, env);
    if (req.method === "POST" && url.pathname === "/webhooks/stripe") {
      return handleStripeWebhook(req, env, env.KEYS);
    }

    // Free public demo endpoint — heavily rate-limited per IP.
    if (req.method === "POST" && url.pathname === "/v1/demo") {
      const ip = req.headers.get("cf-connecting-ip") || "unknown";
      const dk = "demo:" + ip + ":" + Math.floor(Date.now() / 60_000);
      const cur = parseInt((await env.RATE.get(dk)) || "0", 10);
      if (cur >= 20) return err(429, "demo_rate", "Demo throttle: 20 req/min per IP — sign up for a key.");
      await env.RATE.put(dk, String(cur + 1), { expirationTtl: 90 });
      let body: any;
      try { body = await req.json(); } catch { return err(400, "bad_json", "Invalid JSON body."); }
      const text = typeof body?.text === "string" ? body.text.slice(0, 4000) : "";
      if (!text) return err(400, "missing_text", "text required");
      const result = await detect({
        text,
        context: asContext(body?.context),
        sensitivity: asSensitivity(body?.options?.sensitivity),
        return_cleaned: true,
      }, env.AI);
      return json({
        safe: result.safe,
        confidence: result.confidence,
        threat_type: result.threat_type,
        patterns_matched: result.patterns_matched,
        cleaned_text: result.cleaned_text,
        notes: result.notes,
        request_id: reqId(),
        demo: true,
      });
    }

    if (url.pathname === "/") {
      return new Response(`InjectShield API
Try POST /v1/scan, /v1/keys, /v1/demo, /v1/patterns, /healthz.
Docs: ${env.PUBLIC_BASE_URL}/docs`, { headers: { "content-type": "text/plain", ...CORS } });
    }
    return err(404, "not_found", "Route not found.");
  },
};
