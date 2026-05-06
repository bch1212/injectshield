// InjectShield heuristic pattern library.
// Each pattern emits a category + base weight (0-1). Final confidence is
// the softmax-style aggregate computed in detect.ts. Categories let the
// API surface threat_type without leaking specific patterns to attackers.

export type Category =
  | "instruction_injection"
  | "system_override"
  | "role_hijack"
  | "exfiltration"
  | "schema_attack"
  | "encoding_smuggle"
  | "invisible_text"
  | "tool_abuse"
  | "jailbreak_classic";

export interface PatternRule {
  id: string;
  category: Category;
  weight: number; // base contribution to confidence, 0..1
  // Either a regex (case-insensitive) or a function for cheaper string scans.
  pattern: RegExp;
  description: string;
}

// IMPORTANT: All regexes are case-insensitive (i flag). Use \b boundaries
// where the literal could otherwise occur as a substring of benign words.
export const RULES: PatternRule[] = [
  // ---- Classic instruction-override phrases ----
  {
    id: "ignore-previous",
    category: "instruction_injection",
    weight: 0.85,
    pattern: /\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|all|above|earlier|system|the)\s*(instructions?|prompts?|rules?|directives?|commands?|messages?)/i,
    description: "Asks the model to discard prior instructions.",
  },
  {
    id: "new-instructions",
    category: "instruction_injection",
    weight: 0.7,
    pattern: /\b(new|updated|revised|replacement)\s+(instructions?|prompts?|system\s*prompt|directives?)\b/i,
    description: "Announces a fresh instruction set, often to overwrite the developer prompt.",
  },
  {
    id: "above-this-line",
    category: "instruction_injection",
    weight: 0.6,
    pattern: /\b(everything|all\s+content|all\s+text)\s+(above|before)\s+(this\s+line|here|the\s+separator)\b/i,
    description: "Tries to invalidate text above a synthetic separator.",
  },

  // ---- System-prompt override / role hijack ----
  {
    id: "you-are-now",
    category: "role_hijack",
    weight: 0.7,
    pattern: /\byou\s+are\s+(now|actually|really)\s+([a-z][a-z0-9 ]{0,40})/i,
    description: "Reassigns the assistant's persona.",
  },
  {
    id: "act-as-different",
    category: "role_hijack",
    weight: 0.55,
    pattern: /\b(act|pretend|behave|roleplay)\s+as\s+(if\s+)?(you\s+(are|were)\s+)?(an?|the)?\s*[a-z]+/i,
    description: "Asks the assistant to roleplay a different persona.",
  },
  {
    id: "system-prompt-leak",
    category: "system_override",
    weight: 0.9,
    pattern: /\b(reveal|print|output|show|display|repeat|verbatim)\b[^.\n]{0,30}\b(system|developer|hidden|secret|internal|original)\s+(prompt|instructions?|message|rules?)\b/i,
    description: "Asks the model to reveal its system prompt.",
  },
  {
    id: "system-tag-injection",
    category: "system_override",
    weight: 0.85,
    pattern: /<\s*\/?\s*(system|assistant|developer|tool_use|tool_result)\s*>/i,
    description: "Injects fake role tags to confuse the chat template.",
  },
  {
    id: "im-start-injection",
    category: "system_override",
    weight: 0.85,
    pattern: /<\|(im_start|im_end|start_header_id|end_header_id|eot_id|begin_of_text|end_of_text)\|>/i,
    description: "Uses ChatML / Llama special tokens to forge turn boundaries.",
  },

  // ---- Classic jailbreak personas ----
  {
    id: "dan-jailbreak",
    category: "jailbreak_classic",
    weight: 0.95,
    pattern: /\b(DAN|D\.A\.N\.|do\s+anything\s+now|developer\s+mode\s+enabled|jailbreak\s+mode)\b/i,
    description: "DAN/Developer-Mode jailbreak markers.",
  },
  {
    id: "no-restrictions",
    category: "jailbreak_classic",
    weight: 0.6,
    pattern: /\b(no|without)\s+(restrictions|filters|safety|guardrails|limits|moral\s+constraints)\b/i,
    description: "Requests an unrestricted persona.",
  },

  // ---- Exfiltration ----
  {
    id: "exfil-url",
    category: "exfiltration",
    weight: 0.7,
    pattern: /\b(send|post|exfiltrate|transmit|forward|upload|fetch)\b[^.\n]{0,40}\b(to|via)\s+https?:\/\/[^\s)>\]]+/i,
    description: "Tries to send data to an external URL.",
  },
  {
    id: "exfil-image",
    category: "exfiltration",
    weight: 0.65,
    pattern: /!\[[^\]]*]\(\s*https?:\/\/[^)]+\?[^)]{0,200}\)/i,
    description: "Markdown image with query string — common exfil channel.",
  },
  {
    id: "exfil-secret-keywords",
    category: "exfiltration",
    weight: 0.55,
    pattern: /\b(api[_-]?key|password|secret|private[_-]?key|access[_-]?token|aws[_-]?secret|bearer[_-]?token)\b/i,
    description: "References to credentials — high signal in untrusted text.",
  },

  // ---- Schema-driven attacks (the OpenClaw style) ----
  {
    id: "openclaw-schema",
    category: "schema_attack",
    weight: 0.95,
    pattern: /\bOpenClaw\b/i,
    description: "Reference to the OpenClaw quota-burn schema attack.",
  },
  {
    id: "tool-call-injection",
    category: "tool_abuse",
    weight: 0.7,
    pattern: /\b(invoke|call|execute|run)\s+(tool|function|skill|action)\s*[:=]\s*"?[a-z_][a-z0-9_]*"?/i,
    description: "Synthetic tool/function-call directive in untrusted text.",
  },
  {
    id: "json-tool-block",
    category: "tool_abuse",
    weight: 0.55,
    pattern: /"(tool|function|action|command)"\s*:\s*"[a-z_][a-z0-9_]*"/i,
    description: "JSON object naming a tool/action — suspicious in commit/web text.",
  },

  // ---- Markdown / fence smuggling ----
  {
    id: "markdown-codefence-system",
    category: "instruction_injection",
    weight: 0.45,
    pattern: /```\s*(system|assistant|developer|prompt)\b/i,
    description: "Code fence labelled with a chat role.",
  },

  // ---- Base64-encoded directive heuristic ----
  // Long base64 token (>= 32 chars) immediately preceded by "decode" or
  // "base64". Pure-length match without context produces too many FPs.
  {
    id: "base64-decode-directive",
    category: "encoding_smuggle",
    weight: 0.6,
    pattern: /\b(decode|base[\-_ ]?64|atob)\b[^.\n]{0,40}[A-Za-z0-9+/=]{32,}/i,
    description: "Asks the model to decode a base64 blob.",
  },
];

// Invisible / formatting unicode — detected separately because it requires
// scanning the raw string rather than the regex engine. Built via RegExp()
// so the source file stays plain-ASCII safe under any editor/transport.
//   U+200B–U+200F  zero-width + directional marks
//   U+202A–U+202E  bidirectional override
//   U+2066–U+2069  isolate marks
//   U+FEFF        BOM
//   U+00AD        soft hyphen
export const INVISIBLE_CHAR_RE = new RegExp(
  "[\\u200B-\\u200F\\u202A-\\u202E\\u2066-\\u2069\\uFEFF\\u00AD]",
  "u",
);
// Tag/sub characters used in "ASCII Smuggling" attacks (CVE-class):
//   U+E0000 – U+E007F
export const TAG_BLOCK_RE = new RegExp("[\\u{E0000}-\\u{E007F}]", "u");
