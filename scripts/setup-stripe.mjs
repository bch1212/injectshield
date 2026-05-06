#!/usr/bin/env node
// Idempotent: creates the three InjectShield subscription products + prices
// in live Stripe (or test, when STRIPE_TEST_SECRET_KEY is exported and
// INJECTSHIELD_TEST=1). If a product with the same name already exists we
// reuse it. Writes IDs to .stripe-prices.env for the deploy script to pick up.
//
// Usage:
//   STRIPE_SECRET_KEY=sk_live_... node scripts/setup-stripe.mjs

import fs from "node:fs";
import path from "node:path";

const TEST = process.env.INJECTSHIELD_TEST === "1";
const KEY = TEST
  ? (process.env.STRIPE_TEST_SECRET_KEY || process.env.STRIPE_SECRET_KEY)
  : process.env.STRIPE_SECRET_KEY;
if (!KEY) {
  console.error("missing STRIPE_SECRET_KEY (or STRIPE_TEST_SECRET_KEY when INJECTSHIELD_TEST=1)");
  process.exit(1);
}
const MODE = KEY.startsWith("sk_test_") ? "test" : "live";
console.log(`Provisioning Stripe in ${MODE} mode…`);

const TIERS = [
  { name: "InjectShield Hobby",  amount: 2900,  interval: "month", desc: "500K requests/mo, basic dashboard, webhook alerts." },
  { name: "InjectShield Team",   amount: 9900,  interval: "month", desc: "5M requests/mo, custom patterns, team accounts." },
  { name: "InjectShield Pro",    amount: 49900, interval: "month", desc: "Unlimited requests, SLA, no-logging mode." },
];

async function stripe(method, path, body) {
  const init = {
    method,
    headers: {
      authorization: "Bearer " + KEY,
      "content-type": "application/x-www-form-urlencoded",
    },
  };
  if (body) init.body = new URLSearchParams(body).toString();
  const r = await fetch("https://api.stripe.com/v1" + path, init);
  if (!r.ok) {
    console.error("stripe error", method, path, await r.text());
    process.exit(1);
  }
  return await r.json();
}

async function findProductByName(name) {
  // Stripe doesn't have name search; list and match.
  const r = await stripe("GET", "/products?limit=100&active=true");
  return r.data.find((p) => p.name === name) || null;
}

async function findPrice(productId, amount, interval) {
  const r = await stripe("GET", `/prices?product=${productId}&active=true&limit=100`);
  return r.data.find(
    (p) =>
      p.unit_amount === amount &&
      p.currency === "usd" &&
      p.recurring?.interval === interval,
  ) || null;
}

const out = {};
for (const t of TIERS) {
  let product = await findProductByName(t.name);
  if (!product) {
    product = await stripe("POST", "/products", {
      name: t.name,
      description: t.desc,
      "metadata[product]": "promptshield",
    });
    console.log(`  created product ${t.name} ${product.id}`);
  } else {
    console.log(`  reused product ${t.name} ${product.id}`);
  }
  let price = await findPrice(product.id, t.amount, t.interval);
  if (!price) {
    price = await stripe("POST", "/prices", {
      product: product.id,
      currency: "usd",
      unit_amount: String(t.amount),
      "recurring[interval]": t.interval,
      "metadata[tier]": t.name.split(" ")[1].toLowerCase(),
    });
    console.log(`    created price ${price.id}`);
  } else {
    console.log(`    reused price ${price.id}`);
  }
  const tierKey = t.name.split(" ")[1].toUpperCase();
  out[`STRIPE_PRICE_${tierKey}`] = price.id;
  out[`STRIPE_PRODUCT_${tierKey}`] = product.id;
}

const file = path.join(process.cwd(), ".stripe-prices.env");
const lines = [`# Stripe ${MODE} mode prices for InjectShield`, `STRIPE_MODE=${MODE}`];
for (const [k, v] of Object.entries(out)) lines.push(`${k}=${v}`);
fs.writeFileSync(file, lines.join("\n") + "\n");
console.log(`\nWrote ${file}:`);
console.log(lines.join("\n"));
