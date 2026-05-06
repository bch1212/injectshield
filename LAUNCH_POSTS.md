# PromptShield — Launch Post Drafts

Brett owns launch timing per the steady-state-only convention. These are ready-to-post drafts. Personalize/edit before posting; don't paste verbatim.

**Live links to embed:**
- Landing page: https://injectshield.dev
- API base: https://api.injectshield.dev
- Docs: https://injectshield.dev/docs
- GitHub: https://github.com/bch1212/promptshield

---

## 1. Show HN

**Title:** `Show HN: PromptShield – a prompt-injection firewall for AI agents`

**Body:**

After watching the OpenClaw thread last week (the schema-driven attack that burned Claude Code users' session quota with a single git commit), I built a small layer that sits between untrusted text and an AI agent's context window.

PromptShield is a REST API that takes any string — git commit, web page, file, email, user input — and returns:

- a confidence score
- a threat category (instruction_injection, system_override, role_hijack, exfiltration, schema_attack, encoding_smuggle, invisible_text, tool_abuse, jailbreak_classic)
- a list of matched patterns (without leaking the regexes)
- an optional sanitized version with redacted spans

Free tier is 10K requests/month, no credit card. Paid tiers add custom patterns, webhook alerts, and a no-logging mode.

**The heuristic ruleset is open-source** (MIT) at github.com/bch1212/promptshield. Twenty-ish categorized regexes covering the patterns I've seen in the wild — ChatML/Llama special-token forgery, role-tag injection, ASCII smuggling via Unicode Tag block, base64-decoded directives, OpenClaw schema references, etc. The semantic layer (Claude Haiku classifier with capped contribution) is in the managed API.

I'm explicitly not claiming this catches everything. It's one layer of defense in depth — pair it with system-prompt hardening, tool sandboxing, and output filtering. But "no detection at all" is what most teams ship today, and that's the gap I wanted to close.

Live demo on the landing page (paste anything, see what we'd flag): https://injectshield.dev

Pattern PRs welcome.

---

## 2. r/LocalLLaMA

**Title:** `Open-source prompt-injection rule library + free managed API`

**Body:**

Built a heuristic ruleset for prompt-injection detection after watching the OpenClaw HN thread. ~20 categorized patterns covering ChatML/Llama special-token forgery, role-tag injection, ASCII smuggling (Unicode Tag block U+E0000-E007F), base64-decoded directives, exfil markdown images, and the OpenClaw schema attack itself.

Repo: https://github.com/bch1212/promptshield (MIT)

There's also a managed API at https://injectshield.dev with a free 10K req/month tier. It runs the same ruleset plus a Claude Haiku semantic classifier (cap'd contribution so it can't single-handedly flip the verdict). Self-serve signup, no waitlist.

Curious what attacks are missing. Issues / PRs welcome.

---

## 3. r/ClaudeAI

**Title:** `I built a prompt-injection firewall after the OpenClaw incident`

**Body:**

You've probably seen the OpenClaw thread — the git-commit attack that exhausted Claude Code session quotas. I built a small REST layer to detect that kind of pattern before it reaches an agent's context window.

Heuristic ruleset is open-source (MIT): https://github.com/bch1212/promptshield

Managed API w/ free tier: https://injectshield.dev — paste any text, see what we'd flag. The OpenClaw schema is one of the patterns we explicitly catch.

Caveat: this is a defense-in-depth layer, not a silver bullet. Pair with system-prompt hardening + tool sandboxing.

---

## 4. r/LangChain

**Title:** `Drop-in input-side prompt-injection detection for agents`

**Body:**

If you're building LangChain agents that ingest untrusted text (RAG, web tools, file readers, MCP), you probably want a layer that scans inputs before they hit the model. I built one — heuristic ruleset (open-source) + Claude-Haiku semantic classifier (managed).

```python
import requests
def safe_for_agent(text, ctx="user_input"):
    r = requests.post(
      "https://api.injectshield.dev/v1/scan",
      headers={"Authorization": f"Bearer {API_KEY}"},
      json={"text": text, "context": ctx},
    ).json()
    return r["safe"], r.get("threat_type"), r.get("cleaned_text")
```

Free tier 10K/mo. Repo: https://github.com/bch1212/promptshield

---

## 5. ProductHunt

**Tagline:** `A firewall for your AI agent's context window`

**Description:**

PromptShield detects and neutralizes prompt-injection attacks in any text — git commits, web pages, files, emails, user input — before they reach your AI agent. Heuristic ruleset (open-source, MIT) plus an optional semantic classifier. Free tier: 10K requests/month. Self-serve, no waitlist.

**Topics:** Developer Tools · AI · Security · APIs

---

## 6. Twitter / X thread (4 posts)

**1/4** I built PromptShield — a small REST API that detects prompt-injection attacks in any text before it reaches your AI agent's context window. After the OpenClaw thread, this seemed overdue. https://injectshield.dev

**2/4** ~20 categorized regex rules (instruction-override, ChatML/Llama special tokens, role-tag forgery, ASCII smuggling via Unicode Tag block, base64-smuggle, exfil markdown images, OpenClaw schema). Open-source ruleset, MIT: https://github.com/bch1212/promptshield

**3/4** Managed API adds a Claude Haiku semantic classifier (contribution capped at ±0.15 so it can't single-handedly flip a verdict). Free tier: 10K requests/month, no credit card.

**4/4** Not a silver bullet — use as one layer alongside system-prompt hardening, tool sandboxing, output filtering. That said, "no detection at all" is what most teams ship today. Pattern PRs welcome.

---

## 7. Anthropic Discord (#prompt-injection or #builders)

> **PromptShield** — drop-in prompt-injection firewall for AI agents
>
> Heuristic ruleset + Claude Haiku semantic classifier. Free tier 10K/mo.
> https://injectshield.dev — github.com/bch1212/promptshield (MIT ruleset)
>
> Detection categories: instruction-override, system-override, role-hijack, exfiltration, schema-attacks (incl. OpenClaw), encoding-smuggle, invisible-Unicode, tool-abuse, classic jailbreaks.
>
> Built this after the OpenClaw thread. Pattern PRs welcome.

---

## 8. LinkedIn

**Headline:** `Shipped PromptShield — a prompt-injection firewall for AI agents`

**Body:**

A few weeks ago a single git commit message demonstrated it could burn an entire Claude Code session's quota by exploiting prompt-injection. The "OpenClaw" attack is a single instance of a much larger problem: AI agents ingest untrusted text from many sources, and most teams ship without any input-side detection layer.

I built PromptShield to close that gap.

It's a REST API that scans any text and returns a confidence score, threat category, matched patterns, and a sanitized version. Free tier is 10K requests/month. The heuristic ruleset is open-source (MIT) so anyone can audit, contribute, or self-host it.

PromptShield isn't a silver bullet — it's one layer of defense-in-depth. But it's a useful layer most agents lack today.

→ https://injectshield.dev
→ https://github.com/bch1212/promptshield

#AI #Security #PromptInjection #DeveloperTools

---

## Order of operations (when Brett is ready)

1. **Show HN first** — it sets the canonical narrative. Post Tuesday 9am ET (best HN engagement window).
2. **Twitter thread + Anthropic Discord** — same morning, hours after HN goes live.
3. **r/LocalLLaMA + r/ClaudeAI + r/LangChain** — staggered over the next 24h. Wait for Reddit account warm-up status if reusing the @brett_halv warmup pattern.
4. **ProductHunt + LinkedIn** — within 48h of HN.

Don't post all at once — different audiences notice the spread, and the HN thread is the highest-leverage placement.
