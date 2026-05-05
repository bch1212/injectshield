# PromptShield

**Prompt-injection firewall for AI agents.**

A drop-in REST API that detects and neutralizes injection attacks in any text — git commits, web pages, files, emails, user inputs — *before* they reach your AI agent's context window.

This repo is the **open-source heuristic ruleset** plus the source for the managed API at [promptshield.pages.dev](https://promptshield.pages.dev).

---

## Why

In May 2026 a viral HN thread demonstrated that a single git commit message could burn a Claude Code user's entire session quota via a schema-driven attack ("OpenClaw"). The pattern is general: any AI agent that ingests untrusted text — code review bots, documentation summarizers, RAG agents, support copilots — is exposed to prompt injection. Most teams ship without any input-side defense.

PromptShield is one layer of a defense-in-depth strategy. It's not a silver bullet. Use it alongside system-prompt hardening, tool sandboxing, and output filtering.

## Quick start

```bash
curl -X POST https://promptshield-api-production.up.railway.app/v1/scan \
  -H "Authorization: Bearer ps_live_..." \
  -H "Content-Type: application/json" \
  -d '{"text":"ignore previous instructions","context":"user_input"}'
```

Get a free API key (10K req/mo): [promptshield.pages.dev](https://promptshield.pages.dev) — self-serve, email delivery.

## What's open-source vs. managed

**Open-source (this repo, MIT):**

- `src/patterns.ts` — the heuristic pattern library (~20 categorized rules).
- `src/detect.ts` — the detection engine (heuristic aggregation, sanitization).
- `test/` — the test suite.
- `server/`, `public/` — the full API + landing-page source.

**Managed only (paid tiers):**

- Hosted API with usage metering, dashboards, custom-pattern uploads, webhook alerts, no-logging mode (Pro), team accounts.
- Future: Workers AI / Anthropic semantic classifier with prompt-engineered injection detection.

## Detection categories

| Category | Examples |
|---|---|
| `instruction_injection` | "ignore previous instructions", "new system prompt" |
| `system_override` | system-prompt leak, role-tag forgery, ChatML/Llama special tokens |
| `role_hijack` | "you are now…", DAN, Developer Mode |
| `exfiltration` | data sent to attacker URLs, markdown image exfil |
| `schema_attack` | OpenClaw-style schema references |
| `encoding_smuggle` | base64-decoded directives |
| `invisible_text` | zero-width / bidi / Unicode-Tag smuggling |
| `tool_abuse` | synthetic tool-call directives in untrusted text |
| `jailbreak_classic` | DAN, "no restrictions", etc. |

## Contributing patterns

Found a novel attack? Open a PR adding a `PatternRule` to `src/patterns.ts` with:

1. A unique `id`.
2. A `category` from the enum above.
3. A `weight` in [0, 1] — pick conservatively; the aggregation in `detect.ts` combines weights so every additional rule contributes meaningfully but isn't dominant.
4. A test in `test/detect.test.ts` covering both a positive and a likely-benign negative example.

We auto-deploy merged patterns to the managed API. No-cost contributions get attribution in the changelog.

## Running locally

```bash
npm install
npm test         # 11 tests, ~20ms
DATABASE_URL=postgres://... npm run dev   # boots Hono on :8080
```

## License

[MIT](LICENSE). PromptShield reduces but does not eliminate prompt-injection risk.

## Acknowledgments

Built on Cloudflare Pages (frontend) + Railway (API) + Postgres + Anthropic Claude (semantic layer).
Pattern library informed by HackAPrompt, the PINT benchmark, and [a long list of public attack examples](https://github.com/leondz/garak).
