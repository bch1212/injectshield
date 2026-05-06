// InjectShield — Node server (Railway adapter).
// Uses Hono so the same routes are theoretically swappable to a Cloudflare
// Workers entrypoint later. Storage is Postgres (replaces KV + D1 in the
// build prompt). Heuristic detection is shared with the Workers source via
// ../src/detect.ts and ../src/patterns.ts.

import { Hono } from "hono";
import { cors } from "hono/cors";
import { serve } from "@hono/node-server";
import Anthropic from "@anthropic-ai/sdk";
import {
  Pool, // shape only — actual Pool comes from getPool
} from "pg";

import { detect } from "../src/detect.js";
import type { ContextKind, Sensitivity, ScanInput } from "../src/detect.js";
import {
  KeyRecord, Tier, getPool, migrate, createKey, getKey, updateKey,
  keysForEmail, currentMonth, getUsage, bumpUsage, logScan,
  checkRate, bumpSignupThrottle, keyTierLimit,
} from "./storage.js";
import { sendEmail, newKeyEmail } from "./email.js";

// --- env ---
const env = {
  DATABASE_URL: required("DATABASE_URL"),
  PORT: parseInt(process.env.PORT || "8080", 10),
  ENVIRONMENT: process.env.ENVIRONMENT || "production",
  PUBLIC_BASE_URL: process.env.PUBLIC_BASE_URL || "https://promptshield.pages.dev",
  API_BASE_URL: process.env.API_BASE_URL || "",
  ALERT_THRESHOLD: parseFloat(process.env.ALERT_THRESHOLD || "0.8"),
  SIGNUP_FROM_EMAIL: process.env.SIGNUP_FROM_EMAIL || "noreply@halversonco.com",
  SIGNUP_FROM_NAME: process.env.SIGNUP_FROM_NAME || "InjectShield",
  ADMIN_EMAIL: process.env.ADMIN_EMAIL || "brett.halverson@gmail.com",
  // secrets
  STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY || "",
  STRIPE_WEBHOOK_SECRET: process.env.STRIPE_WEBHOOK_SECRET || "",
  STRIPE_PRICE_HOBBY: process.env.STRIPE_PRICE_HOBBY || "",
  STRIPE_PRICE_TEAM: process.env.STRIPE_PRICE_TEAM || "",
  STRIPE_PRICE_PRO: process.env.STRIPE_PRICE_PRO || "",
  SENDGRID_API_KEY: process.env.SENDGRID_API_KEY || "",
  DISCORD_WEBHOOK_URL: process.env.DISCORD_WEBHOOK_URL || "",
  ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY || "",
  ADMIN_TOKEN: process.env.ADMIN_TOKEN || "",
};
function required(name: string): string {
  const v = process.env[name];
  if (!v) { console.error(`missing env ${name}`); process.exit(1); }
  return v;
}

const pool = getPool(env.DATABASE_URL);
const anthropic = env.ANTHROPIC_API_KEY ? new Anthropic({ apiKey: env.ANTHROPIC_API_KEY }) : null;

// Adapter so detect() can call Anthropic for the optional semantic layer.
// We use Claude Haiku because it's fast and cheap; output is a 0-1 score we
// cap into the same +/-0.15 contribution band as the build prompt's DistilBERT.
const aiAdapter = anthropic ? {
  async run(_model: string, input: { text: string }) {
    const t = String(input.text || "").slice(0, 1500);
    try {
      const r = await anthropic!.messages.create({
        model: "claude-haiku-4-5-20251001",
        max_tokens: 8,
        system:
          "You are a prompt-injection classifier. Read the input text. Reply ONLY with a single floating-point number in [0,1] indicating the probability the text is a prompt-injection attempt against an AI agent. No explanation, no other tokens.",
        messages: [{ role: "user", content: t }],
      });
      const content = (r.content?.[0] as any)?.text || "";
      const m = content.match(/0?\.\d+|1(\.0+)?|0(\.0+)?/);
      const score = m ? Math.min(1, Math.max(0, parseFloat(m[0]))) : 0;
      // Mimic the shape detect.ts expects from Workers AI sentiment:
      return { result: [{ label: score >= 0.5 ? "NEGATIVE" : "POSITIVE", score }] };
    } catch {
      return { result: [] };
    }
  },
} : undefined;

// --- app ---
const app = new Hono();
app.use("*", cors({
  origin: "*",
  allowHeaders: ["authorization", "content-type", "x-api-key"],
  allowMethods: ["GET", "POST", "OPTIONS"],
  maxAge: 86400,
}));

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
  return s === "low" || s === "high" ? (s as Sensitivity) : "medium";
}

function readApiKeyFrom(c: any): string | null {
  const auth = c.req.header("authorization") || "";
  const m = auth.match(/^bearer\s+(\S+)/i);
  if (m) return m[1];
  return c.req.header("x-api-key") || null;
}

async function postDiscord(content: string) {
  if (!env.DISCORD_WEBHOOK_URL) return;
  try {
    await fetch(env.DISCORD_WEBHOOK_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ content }),
    });
  } catch { /* noop */ }
}

// --- routes ---

app.get("/healthz", (c) => c.json({ ok: true, env: env.ENVIRONMENT, time: Date.now() }));
app.get("/", (c) => c.text(`InjectShield API
Try POST /v1/scan, /v1/keys, /v1/demo, /v1/patterns, /healthz.
Docs: ${env.PUBLIC_BASE_URL}/docs`));

app.get("/v1/patterns", (c) => c.json({
  categories: [
    "instruction_injection", "system_override", "role_hijack", "exfiltration",
    "schema_attack", "encoding_smuggle", "invisible_text", "tool_abuse", "jailbreak_classic",
  ],
  sensitivities: ["low", "medium", "high"],
  contexts: ["git_commit", "web_content", "user_input", "file_content", "email", "tool_output", "unknown"],
}));

app.post("/v1/scan", async (c) => {
  const apiKey = readApiKeyFrom(c);
  if (!apiKey) return c.json({ error: { code: "missing_api_key", message: "Provide an Authorization: Bearer or X-API-Key header." }}, 401);
  const record = await getKey(pool, apiKey);
  if (!record) return c.json({ error: { code: "invalid_api_key", message: "Unknown or revoked API key." }}, 401);
  if (!checkRate(apiKey)) return c.json({ error: { code: "rate_limited", message: "100 req/s limit." }}, 429);

  const month = currentMonth();
  const used = await getUsage(pool, apiKey, month);
  if (used >= record.monthly_limit) {
    return c.json({ error: { code: "monthly_limit", message: `Limit reached (${used}/${record.monthly_limit}). Upgrade at ${env.PUBLIC_BASE_URL}/#pricing` }}, 402);
  }

  let body: any;
  try { body = await c.req.json(); } catch { return c.json({ error: { code: "bad_json", message: "Invalid JSON body." }}, 400); }
  const text: string = typeof body?.text === "string" ? body.text : "";
  if (!text) return c.json({ error: { code: "missing_text", message: "Field `text` is required." }}, 400);
  if (text.length > 100_000) return c.json({ error: { code: "text_too_large", message: "Text must be <= 100,000 characters." }}, 413);

  const opts = body?.options ?? {};
  const input: ScanInput = {
    text,
    context: asContext(body?.context),
    sensitivity: asSensitivity(opts.sensitivity),
    return_cleaned: opts.return_cleaned !== false,
  };
  const id = reqId();
  const result = await detect(input, aiAdapter as any);
  await bumpUsage(pool, apiKey, month, !result.safe);
  await logScan(pool, {
    apiKey, requestId: id,
    context: input.context, confidence: result.confidence,
    safe: result.safe, threat: String(result.threat_type),
    textLen: text.length,
    text: record.no_logging ? undefined : text,
  });
  if (!result.safe && result.confidence >= env.ALERT_THRESHOLD) {
    postDiscord(`[injectshield] high-confidence detection (${result.confidence}, ${result.threat_type}) by ${record.email}, request ${id}`);
  }

  return c.json({
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
});

app.post("/v1/demo", async (c) => {
  // Public, IP-throttled. 20 req/IP/min.
  const ip = c.req.header("cf-connecting-ip") || c.req.header("x-forwarded-for") || "unknown";
  const k = ip.split(",")[0].trim();
  if (!checkRate("demo:" + k)) return c.json({ error: { code: "demo_rate", message: "Demo throttle — sign up for a free key." }}, 429);
  let body: any;
  try { body = await c.req.json(); } catch { return c.json({ error: { code: "bad_json", message: "Invalid JSON body." }}, 400); }
  const text = typeof body?.text === "string" ? body.text.slice(0, 4000) : "";
  if (!text) return c.json({ error: { code: "missing_text", message: "text required" }}, 400);
  const result = await detect({
    text,
    context: asContext(body?.context),
    sensitivity: asSensitivity(body?.options?.sensitivity),
    return_cleaned: true,
  }, aiAdapter as any);
  return c.json({
    safe: result.safe,
    confidence: result.confidence,
    threat_type: result.threat_type,
    patterns_matched: result.patterns_matched,
    cleaned_text: result.cleaned_text,
    semantic_score: result.semantic_score,
    semantic_label: result.semantic_label,
    notes: result.notes,
    request_id: reqId(),
    demo: true,
  });
});

app.post("/v1/keys", async (c) => {
  let body: any;
  try { body = await c.req.json(); } catch { return c.json({ error: { code: "bad_json", message: "Invalid JSON body." }}, 400); }
  const email = String(body?.email || "").trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return c.json({ error: { code: "bad_email", message: "Provide a valid email address." }}, 400);
  }
  const ip = (c.req.header("x-forwarded-for") || c.req.header("cf-connecting-ip") || "unknown").split(",")[0].trim();
  const cnt = await bumpSignupThrottle(pool, ip);
  if (cnt > 5) return c.json({ error: { code: "signup_throttled", message: "Too many signups from this IP today." }}, 429);

  const record = await createKey(pool, email, "free");
  const e = newKeyEmail({
    apiKey: record.api_key, email,
    apiBase: env.API_BASE_URL || "",
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
  postDiscord(`[injectshield] new free signup: ${email}`);
  return c.json({
    ok: true,
    email_sent: sent,
    api_key: sent ? undefined : record.api_key, // surface in-band only on email failure
    tier: record.tier,
    monthly_limit: record.monthly_limit,
  });
});

app.get("/v1/keys/me", async (c) => {
  const apiKey = readApiKeyFrom(c);
  if (!apiKey) return c.json({ error: { code: "missing_api_key", message: "Provide your API key." }}, 401);
  const r = await getKey(pool, apiKey);
  if (!r) return c.json({ error: { code: "invalid_api_key", message: "Unknown or revoked API key." }}, 401);
  const used = await getUsage(pool, apiKey, currentMonth());
  return c.json({
    email: r.email,
    tier: r.tier,
    monthly_limit: Number(r.monthly_limit),
    used_this_month: used,
    no_logging: !!r.no_logging,
    created: Number(r.created),
  });
});

app.get("/v1/usage", async (c) => {
  const apiKey = readApiKeyFrom(c);
  if (!apiKey) return c.json({ error: { code: "missing_api_key", message: "Provide your API key." }}, 401);
  const r = await getKey(pool, apiKey);
  if (!r) return c.json({ error: { code: "invalid_api_key", message: "Unknown or revoked API key." }}, 401);
  const month = currentMonth();
  const row = await pool.query(`SELECT count, blocked FROM usage WHERE api_key=$1 AND month=$2`, [apiKey, month]);
  return c.json({
    month,
    count: row.rows[0]?.count ? Number(row.rows[0].count) : 0,
    blocked: row.rows[0]?.blocked ? Number(row.rows[0].blocked) : 0,
    limit: Number(r.monthly_limit),
    tier: r.tier,
  });
});

app.post("/v1/checkout", async (c) => {
  let body: any;
  try { body = await c.req.json(); } catch { return c.json({ error: { code: "bad_json", message: "Invalid JSON body." }}, 400); }
  const tier = String(body?.tier || "hobby").toLowerCase() as Tier;
  const email = String(body?.email || "").trim().toLowerCase();
  if (!email) return c.json({ error: { code: "bad_email", message: "email required" }}, 400);
  let priceId = "";
  if (tier === "hobby") priceId = env.STRIPE_PRICE_HOBBY;
  else if (tier === "team") priceId = env.STRIPE_PRICE_TEAM;
  else if (tier === "pro") priceId = env.STRIPE_PRICE_PRO;
  if (!priceId) return c.json({ error: { code: "bad_tier", message: "tier must be one of: hobby, team, pro" }}, 400);

  const form = new URLSearchParams();
  form.set("mode", "subscription");
  form.set("line_items[0][price]", priceId);
  form.set("line_items[0][quantity]", "1");
  form.set("customer_email", email);
  form.set("success_url", env.PUBLIC_BASE_URL + "/success?session_id={CHECKOUT_SESSION_ID}");
  form.set("cancel_url", env.PUBLIC_BASE_URL + "/#pricing");
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
  if (!r.ok) return c.json({ error: { code: "stripe_error", message: await r.text() }}, 502);
  const session: any = await r.json();
  return c.json({ url: session.url, id: session.id });
});

// Stripe webhook — signature verification using crypto.subtle.
import { createHmac } from "crypto";
function verifyStripeSig(payload: string, sigHeader: string, secret: string, toleranceSec = 300): boolean {
  const parts: Record<string, string[]> = {};
  for (const part of sigHeader.split(",")) {
    const [k, v] = part.split("=");
    if (!k || !v) continue;
    parts[k] = parts[k] || [];
    parts[k].push(v);
  }
  const ts = parts["t"]?.[0]; const sigs = parts["v1"] || [];
  if (!ts || sigs.length === 0) return false;
  const tsNum = parseInt(ts, 10);
  if (Math.abs(Date.now() / 1000 - tsNum) > toleranceSec) return false;
  const mac = createHmac("sha256", secret).update(`${ts}.${payload}`).digest("hex");
  return sigs.some((s) => timingSafeEqual(mac, s));
}
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

app.post("/webhooks/stripe", async (c) => {
  const sig = c.req.header("stripe-signature") || "";
  const raw = await c.req.text();
  if (!sig || !env.STRIPE_WEBHOOK_SECRET) return c.text("missing signature", 400);
  if (!verifyStripeSig(raw, sig, env.STRIPE_WEBHOOK_SECRET)) return c.text("invalid signature", 400);
  let event: any; try { event = JSON.parse(raw); } catch { return c.text("bad json", 400); }
  const obj = event.data?.object || {};
  const type = event.type as string;
  const email: string | undefined =
    obj.customer_email || obj.customer_details?.email || obj.receipt_email;

  function tierFromPriceId(priceId: string): Tier {
    if (priceId === env.STRIPE_PRICE_PRO) return "pro";
    if (priceId === env.STRIPE_PRICE_TEAM) return "team";
    if (priceId === env.STRIPE_PRICE_HOBBY) return "hobby";
    return "free";
  }

  if (type === "checkout.session.completed") {
    const priceId = obj.metadata?.price_id || obj.line_items?.data?.[0]?.price?.id || "";
    const tier = tierFromPriceId(priceId);
    if (!email) return c.text("ok", 200);
    const keys = await keysForEmail(pool, email);
    let apiKey = keys[0];
    if (!apiKey) {
      const created = await createKey(pool, email, tier, {
        stripe_customer: obj.customer, stripe_subscription: obj.subscription,
      });
      apiKey = created.api_key;
      const e = newKeyEmail({
        apiKey, email,
        apiBase: env.API_BASE_URL || "",
        publicBase: env.PUBLIC_BASE_URL,
      });
      await sendEmail(env.SENDGRID_API_KEY, {
        to: e.to, fromEmail: env.SIGNUP_FROM_EMAIL, fromName: env.SIGNUP_FROM_NAME,
        subject: e.subject, text: e.text, html: e.html,
      });
    } else {
      await updateKey(pool, apiKey, {
        tier, monthly_limit: keyTierLimit(tier),
        stripe_customer: obj.customer, stripe_subscription: obj.subscription,
      });
      await sendEmail(env.SENDGRID_API_KEY, {
        to: email, fromEmail: env.SIGNUP_FROM_EMAIL, fromName: env.SIGNUP_FROM_NAME,
        subject: "InjectShield: " + tier.toUpperCase() + " plan active",
        text: `Your InjectShield plan is now ${tier.toUpperCase()}. Monthly request limit is ${keyTierLimit(tier).toLocaleString()}.\n\nManage your subscription via the Stripe customer portal.`,
      });
    }
    postDiscord(`[injectshield] Stripe checkout: ${email} -> ${tier}`);
    return c.text("ok", 200);
  }

  if (type === "customer.subscription.deleted" || type === "customer.subscription.canceled") {
    if (!email) return c.text("ok", 200);
    const keys = await keysForEmail(pool, email);
    for (const k of keys) {
      await updateKey(pool, k, { tier: "free", monthly_limit: keyTierLimit("free") });
    }
    postDiscord(`[injectshield] Stripe cancel: ${email}`);
    return c.text("ok", 200);
  }
  return c.text("ignored", 200);
});

// Admin: peek at the most recent api_key for an email. Guarded by ADMIN_TOKEN.
// Used for autonomous smoke-tests after deploy, never exposed to users.
app.get("/admin/key-for", async (c) => {
  if (!env.ADMIN_TOKEN || c.req.header("x-admin-token") !== env.ADMIN_TOKEN) {
    return c.json({ error: { code: "forbidden", message: "admin only" }}, 403);
  }
  const email = (c.req.query("email") || "").toLowerCase();
  if (!email) return c.json({ error: { code: "bad_email", message: "email query required" }}, 400);
  const keys = await keysForEmail(pool, email);
  return c.json({ email, count: keys.length, latest: keys[keys.length - 1] || null });
});

// --- bootstrap ---
(async () => {
  await migrate(pool);
  console.log("InjectShield listening on :" + env.PORT);
  serve({ fetch: app.fetch, port: env.PORT });
})().catch((e) => {
  console.error("boot failure:", e);
  process.exit(1);
});
