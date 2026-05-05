import { RULES, INVISIBLE_CHAR_RE, TAG_BLOCK_RE, Category, PatternRule } from "./patterns.js";

export type Sensitivity = "low" | "medium" | "high";
export type ContextKind =
  | "git_commit"
  | "web_content"
  | "user_input"
  | "file_content"
  | "email"
  | "tool_output"
  | "unknown";

export interface ScanInput {
  text: string;
  context: ContextKind;
  sensitivity: Sensitivity;
  return_cleaned: boolean;
}

export interface RuleHit {
  id: string;
  category: Category;
  weight: number;
  excerpt: string;
}

export interface DetectResult {
  safe: boolean;
  confidence: number; // 0..1 — overall maliciousness probability
  threat_type: Category | "none";
  patterns_matched: string[];
  hits: RuleHit[];
  cleaned_text?: string;
  semantic_score?: number; // optional AI classifier output
  semantic_label?: string;
  notes: string[];
}

const CONTEXT_BIAS: Record<ContextKind, number> = {
  // Adds/subtracts to the final score before threshold compare.
  git_commit: 0.10, // commits should never carry instructions
  tool_output: 0.05,
  file_content: 0.03,
  web_content: 0.02,
  email: 0.05,
  user_input: 0.0, // baseline
  unknown: 0.0,
};

const SENSITIVITY_THRESHOLD: Record<Sensitivity, number> = {
  low: 0.75,
  medium: 0.55,
  high: 0.40,
};

function excerpt(text: string, idx: number, len: number): string {
  const start = Math.max(0, idx - 20);
  const end = Math.min(text.length, idx + len + 20);
  return text.slice(start, end).replace(/\s+/g, " ").trim().slice(0, 140);
}

export function runHeuristics(text: string): RuleHit[] {
  const hits: RuleHit[] = [];
  for (const rule of RULES) {
    const m = rule.pattern.exec(text);
    if (m) {
      hits.push({
        id: rule.id,
        category: rule.category,
        weight: rule.weight,
        excerpt: excerpt(text, m.index, m[0].length),
      });
    }
  }
  if (INVISIBLE_CHAR_RE.test(text)) {
    hits.push({
      id: "invisible-unicode",
      category: "invisible_text",
      weight: 0.7,
      excerpt: "[invisible/zero-width characters detected]",
    });
  }
  if (TAG_BLOCK_RE.test(text)) {
    hits.push({
      id: "tag-block-smuggle",
      category: "invisible_text",
      weight: 0.95,
      excerpt: "[Unicode Tag block (E0000-E007F) — ASCII smuggling]",
    });
  }
  return hits;
}

// Combine independent heuristic weights via 1 - prod(1 - w_i).
// Caps each contribution to avoid one rule dominating.
export function aggregateConfidence(hits: RuleHit[]): number {
  if (hits.length === 0) return 0;
  let p = 1;
  for (const h of hits) {
    p *= 1 - Math.min(0.95, h.weight);
  }
  return 1 - p;
}

// Pick the threat_type by highest-weight hit.
export function topCategory(hits: RuleHit[]): Category | "none" {
  if (hits.length === 0) return "none";
  const sorted = [...hits].sort((a, b) => b.weight - a.weight);
  return sorted[0].category;
}

// Strip detected pattern matches and invisible characters.
export function sanitize(text: string, hits: RuleHit[]): string {
  let cleaned = text;
  // Drop invisible/tag characters first.
  cleaned = cleaned.replace(INVISIBLE_CHAR_RE, "");
  cleaned = cleaned.replace(TAG_BLOCK_RE, "");
  for (const rule of RULES) {
    cleaned = cleaned.replace(rule.pattern, "[REDACTED:" + rule.category + "]");
  }
  return cleaned;
}

export interface AIBinding {
  run: (model: string, input: { text: string }) => Promise<unknown>;
}

// Ask Workers AI for a malicious-prompt classification. The response shape
// varies by model — we're tolerant of common variants. Falls back silently
// on errors so the heuristic verdict still ships.
export async function semanticScore(
  ai: AIBinding | undefined,
  text: string,
): Promise<{ score: number; label: string } | null> {
  if (!ai) return null;
  try {
    // DistilBERT base sentiment as a stand-in maliciousness signal —
    // injection attempts tend to produce high-arousal NEGATIVE/COMMAND tone.
    // When Workers AI ships a dedicated injection classifier we can swap
    // the model id without touching anything else.
    const resp: any = await ai.run("@cf/huggingface/distilbert-sst-2-int8", {
      text: text.slice(0, 1000),
    });
    // Response is typically { result: [{ label: "NEGATIVE", score: 0.9 }, ...] }
    // or directly an array. Normalize.
    const arr = Array.isArray(resp) ? resp : resp?.result ?? [];
    let neg = 0, lbl = "neutral";
    for (const item of arr as any[]) {
      if (item?.label === "NEGATIVE" && typeof item.score === "number") {
        neg = item.score;
        lbl = "negative";
      }
    }
    return { score: neg, label: lbl };
  } catch {
    return null;
  }
}

export async function detect(
  input: ScanInput,
  ai?: AIBinding,
): Promise<DetectResult> {
  const hits = runHeuristics(input.text);
  const heuristicScore = aggregateConfidence(hits);
  const bias = CONTEXT_BIAS[input.context] ?? 0;

  // Optional semantic boost. Sentiment alone is weak signal so we cap its
  // contribution to 0.15 — useful for tiebreaking but won't flip safe→unsafe
  // by itself.
  const sem = await semanticScore(ai, input.text);
  const semBoost = sem ? Math.min(0.15, Math.max(0, sem.score - 0.85)) : 0;

  let confidence = Math.min(1, heuristicScore + bias + semBoost);
  // If text is very short and we have no hits, low signal — keep score 0.
  if (hits.length === 0) confidence = Math.min(confidence, 0.05);

  const threshold = SENSITIVITY_THRESHOLD[input.sensitivity];
  const safe = confidence < threshold;

  const result: DetectResult = {
    safe,
    confidence: Math.round(confidence * 100) / 100,
    threat_type: safe ? "none" : (topCategory(hits) as Category),
    patterns_matched: hits.map((h) => h.id),
    hits,
    notes: [],
  };
  if (sem) {
    result.semantic_score = Math.round(sem.score * 100) / 100;
    result.semantic_label = sem.label;
  }
  if (input.return_cleaned) {
    result.cleaned_text = sanitize(input.text, hits);
  }
  if (input.context === "git_commit" && hits.length > 0) {
    result.notes.push("Git commits should rarely contain natural-language directives — verify origin.");
  }
  return result;
}
