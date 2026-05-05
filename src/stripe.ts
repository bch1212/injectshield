// Stripe webhook handler — promotes a key's tier when a checkout completes
// or a subscription updates, downgrades it on cancel/payment_failure.

import { KVNamespace } from "@cloudflare/workers-types";
import { createKey, getKey, keyTierLimit, KeyRecord, keysForEmail, Tier, updateKey } from "./auth";
import { sendEmail, newKeyEmail } from "./email";

export interface StripeEnv {
  STRIPE_WEBHOOK_SECRET: string;
  STRIPE_PRICE_HOBBY: string;
  STRIPE_PRICE_TEAM: string;
  STRIPE_PRICE_PRO: string;
  SENDGRID_API_KEY: string;
  SIGNUP_FROM_EMAIL: string;
  SIGNUP_FROM_NAME: string;
  PUBLIC_BASE_URL: string;
  API_BASE_URL: string;
}

function tierFromPriceId(env: StripeEnv, priceId: string): Tier {
  if (priceId === env.STRIPE_PRICE_PRO) return "pro";
  if (priceId === env.STRIPE_PRICE_TEAM) return "team";
  if (priceId === env.STRIPE_PRICE_HOBBY) return "hobby";
  return "free";
}

// Stripe webhook signature verification — HMAC SHA-256 over the timestamp + payload.
async function verifyStripeSignature(
  payload: string,
  sigHeader: string,
  secret: string,
  toleranceSec = 300,
): Promise<boolean> {
  // Header format: t=<ts>,v1=<sig>[,v0=<sig>]
  const parts: Record<string, string[]> = {};
  for (const part of sigHeader.split(",")) {
    const [k, v] = part.split("=");
    if (!k || !v) continue;
    parts[k] = parts[k] || [];
    parts[k].push(v);
  }
  const ts = parts["t"]?.[0];
  const sigs = parts["v1"] || [];
  if (!ts || sigs.length === 0) return false;
  const tsNum = parseInt(ts, 10);
  if (Math.abs(Date.now() / 1000 - tsNum) > toleranceSec) return false;

  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = await crypto.subtle.sign("HMAC", key, enc.encode(`${ts}.${payload}`));
  const macHex = [...new Uint8Array(mac)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return sigs.some((s) => timingSafeEqual(macHex, s));
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

export async function handleStripeWebhook(
  req: Request,
  env: StripeEnv,
  kv: KVNamespace,
): Promise<Response> {
  const sig = req.headers.get("stripe-signature");
  const raw = await req.text();
  if (!sig || !env.STRIPE_WEBHOOK_SECRET) {
    return new Response("missing signature", { status: 400 });
  }
  const ok = await verifyStripeSignature(raw, sig, env.STRIPE_WEBHOOK_SECRET);
  if (!ok) return new Response("invalid signature", { status: 400 });

  let event: any;
  try { event = JSON.parse(raw); } catch { return new Response("bad json", { status: 400 }); }

  const obj = event.data?.object || {};
  const type = event.type as string;
  const email: string | undefined =
    obj.customer_email ||
    obj.customer_details?.email ||
    obj.receipt_email;

  if (type === "checkout.session.completed") {
    const priceId =
      obj.metadata?.price_id ||
      obj.line_items?.data?.[0]?.price?.id ||
      obj.display_items?.[0]?.price?.id;
    const tier = tierFromPriceId(env, priceId || "");
    if (!email) return new Response("ok", { status: 200 });
    // Find existing free key for this email or mint a new one with tier set.
    const keys = await keysForEmail(kv, email);
    let apiKey = keys[0];
    if (!apiKey) {
      const created = await createKey(kv, email, tier, {
        stripe_customer: obj.customer,
        stripe_subscription: obj.subscription,
      });
      apiKey = created.apiKey;
      // First-ever key — email it.
      const e = newKeyEmail({ apiKey, email, apiBase: env.API_BASE_URL, publicBase: env.PUBLIC_BASE_URL });
      await sendEmail(env.SENDGRID_API_KEY, {
        to: e.to,
        fromEmail: env.SIGNUP_FROM_EMAIL,
        fromName: env.SIGNUP_FROM_NAME,
        subject: e.subject,
        text: e.text,
        html: e.html,
      });
    } else {
      await updateKey(kv, apiKey, {
        tier,
        monthly_limit: keyTierLimit(tier),
        stripe_customer: obj.customer,
        stripe_subscription: obj.subscription,
      });
      // Email the upgrade confirmation.
      await sendEmail(env.SENDGRID_API_KEY, {
        to: email,
        fromEmail: env.SIGNUP_FROM_EMAIL,
        fromName: env.SIGNUP_FROM_NAME,
        subject: "PromptShield: " + tier.toUpperCase() + " plan active",
        text: `Your PromptShield plan is now ${tier.toUpperCase()}. Monthly request limit is ${keyTierLimit(tier).toLocaleString()}.\n\nManage your subscription via the Stripe customer portal: ${env.PUBLIC_BASE_URL}/account`,
      });
    }
    return new Response("ok", { status: 200 });
  }

  if (type === "customer.subscription.deleted" || type === "customer.subscription.canceled") {
    if (!email) return new Response("ok", { status: 200 });
    const keys = await keysForEmail(kv, email);
    for (const k of keys) {
      const rec = await getKey(kv, k);
      if (!rec) continue;
      await updateKey(kv, k, { tier: "free", monthly_limit: keyTierLimit("free") });
    }
    return new Response("ok", { status: 200 });
  }

  return new Response("ignored", { status: 200 });
}
