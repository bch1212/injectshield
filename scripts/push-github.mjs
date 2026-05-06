#!/usr/bin/env node
// Push the entire repo (minus .gitignore matches) to GitHub via the Contents
// API. We use a single tree+commit to keep history clean (one commit for the
// initial push). Re-runs perform an incremental update against `main`.

import fs from "node:fs";
import path from "node:path";

const PAT = process.env.GITHUB_CLASSIC_PAT;
if (!PAT) { console.error("missing GITHUB_CLASSIC_PAT"); process.exit(1); }
const OWNER = "bch1212";
const REPO = "injectshield";
const BRANCH = "main";

const ROOT = path.resolve(process.cwd());
const IGNORE = [
  // Match node_modules / dist anywhere in the tree, not just at root.
  /(^|\/)node_modules\//, /(^|\/)dist\//,
  /^\.env/, /^\.deploy-secrets/,
  /^\.stripe-prices\.env$/, /^\.railway-deploy\.json/,
  /\.log$/, /(^|\/)\.DS_Store$/, /^_dbg\.mjs$/,
  /(^|\/)package-lock\.json$/, /^\.git\//,
  // Skip the legacy MCP directory — superseded by packages/injectshield-mcp.
  /^packages\/promptshield-mcp\//,
];

function shouldIgnore(rel) {
  return IGNORE.some((re) => re.test(rel));
}

function walk(dir, base = "") {
  const out = [];
  for (const name of fs.readdirSync(dir)) {
    const full = path.join(dir, name);
    const rel = base ? `${base}/${name}` : name;
    if (shouldIgnore(rel)) continue;
    const st = fs.statSync(full);
    if (st.isDirectory()) out.push(...walk(full, rel));
    else if (st.isFile()) out.push({ rel, full });
  }
  return out;
}

async function gh(method, urlPath, body) {
  const r = await fetch("https://api.github.com" + urlPath, {
    method,
    headers: {
      authorization: "token " + PAT,
      accept: "application/vnd.github+json",
      "x-github-api-version": "2022-11-28",
      "content-type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  let json;
  try { json = JSON.parse(text); } catch { json = { _raw: text }; }
  if (!r.ok) {
    console.error("GitHub", method, urlPath, r.status, json);
    process.exit(1);
  }
  return json;
}

const files = walk(ROOT);
console.log(`Found ${files.length} files to push`);

// 1. Create blobs for each file.
const blobs = [];
let i = 0;
for (const f of files) {
  i++;
  const content = fs.readFileSync(f.full).toString("base64");
  const r = await gh("POST", `/repos/${OWNER}/${REPO}/git/blobs`, {
    content, encoding: "base64",
  });
  blobs.push({ path: f.rel, mode: "100644", type: "blob", sha: r.sha });
  if (i % 10 === 0) console.log(`  ${i}/${files.length}…`);
}

// 2. Get current main sha (might 404 if empty repo).
let parentSha = null;
try {
  const ref = await gh("GET", `/repos/${OWNER}/${REPO}/git/ref/heads/${BRANCH}`);
  parentSha = ref.object.sha;
} catch { /* empty repo */ }

// 3. Create tree.
const tree = await gh("POST", `/repos/${OWNER}/${REPO}/git/trees`, { tree: blobs });
console.log(`  tree=${tree.sha}`);

// 4. Create commit.
const commit = await gh("POST", `/repos/${OWNER}/${REPO}/git/commits`, {
  message: parentSha ? "update" : "initial commit — heuristic ruleset, API, landing page",
  tree: tree.sha,
  parents: parentSha ? [parentSha] : [],
});
console.log(`  commit=${commit.sha}`);

// 5. Update ref. Use create if missing, update otherwise.
if (parentSha) {
  await gh("PATCH", `/repos/${OWNER}/${REPO}/git/refs/heads/${BRANCH}`, { sha: commit.sha, force: false });
} else {
  await gh("POST", `/repos/${OWNER}/${REPO}/git/refs`, { ref: `refs/heads/${BRANCH}`, sha: commit.sha });
}
console.log(`Pushed to https://github.com/${OWNER}/${REPO} (branch ${BRANCH}).`);
