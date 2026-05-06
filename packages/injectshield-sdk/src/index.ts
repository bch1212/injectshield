// @injectshield/sdk — official Node/TypeScript SDK for the InjectShield API.
// Thin wrapper around the REST API. No retries, no caching — wire those in
// at the layer above. Uses global `fetch` (Node 18+) so no runtime deps.

export const DEFAULT_BASE_URL = "https://api.injectshield.dev";
const SDK_VERSION = "0.1.0";
const USER_AGENT = `injectshield-node/${SDK_VERSION}`;

export type ContextKind =
  | "git_commit"
  | "web_content"
  | "user_input"
  | "file_content"
  | "email"
  | "tool_output"
  | "unknown";

export type Sensitivity = "low" | "medium" | "high";
export type ThreatType =
  | "instruction_injection"
  | "system_override"
  | "role_hijack"
  | "exfiltration"
  | "schema_attack"
  | "encoding_smuggle"
  | "invisible_text"
  | "tool_abuse"
  | "jailbreak_classic"
  | "none";

export interface ScanOptions {
  context?: ContextKind;
  sensitivity?: Sensitivity;
  return_cleaned?: boolean;
}

export interface ScanResult {
  safe: boolean;
  confidence: number;
  threat_type: ThreatType;
  patterns_matched: string[];
  cleaned_text?: string;
  semantic_score?: number;
  semantic_label?: string;
  notes: string[];
  request_id: string;
}

export interface KeyMeta {
  email: string;
  tier: "free" | "hobby" | "team" | "pro";
  monthly_limit: number;
  used_this_month: number;
  no_logging: boolean;
  created: number;
}

export interface UsageReport {
  month: string;
  count: number;
  blocked: number;
  limit: number;
  tier: string;
}

export class InjectShieldError extends Error {
  code: string;
  status?: number;
  constructor(code: string, message: string, status?: number) {
    super(`${code}: ${message}`);
    this.name = "InjectShieldError";
    this.code = code;
    this.status = status;
  }
}
export class AuthError extends InjectShieldError {}
export class RateLimitError extends InjectShieldError {}
export class QuotaExceededError extends InjectShieldError {}

export interface InjectShieldOptions {
  apiKey: string;
  baseUrl?: string;
  /** Per-request timeout in ms. Default 15000. */
  timeoutMs?: number;
  /** Override the global fetch (e.g. node-fetch, undici). */
  fetch?: typeof fetch;
}

export class InjectShield {
  private readonly base: string;
  private readonly apiKey: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: InjectShieldOptions) {
    if (!opts.apiKey) throw new Error("apiKey is required");
    this.apiKey = opts.apiKey;
    this.base = (opts.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.timeoutMs = opts.timeoutMs ?? 15_000;
    this.fetchImpl = opts.fetch ?? globalThis.fetch;
    if (!this.fetchImpl) {
      throw new Error("global fetch unavailable — pass `fetch` option (Node < 18)");
    }
  }

  /** Scan one string for prompt-injection. */
  async scan(text: string, options: ScanOptions = {}): Promise<ScanResult> {
    const body = {
      text,
      context: options.context ?? "unknown",
      options: {
        sensitivity: options.sensitivity ?? "medium",
        return_cleaned: options.return_cleaned !== false,
      },
    };
    return await this.req<ScanResult>("POST", "/v1/scan", body);
  }

  /** Convenience: serial scan over a list. */
  async scanMany(
    texts: readonly string[],
    options: ScanOptions = {},
  ): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    for (const t of texts) results.push(await this.scan(t, options));
    return results;
  }

  /** Current-month request count + blocked count for the bearer key. */
  async usage(): Promise<UsageReport> {
    return await this.req<UsageReport>("GET", "/v1/usage");
  }

  /** Key metadata (email, tier, limit, usage). */
  async me(): Promise<KeyMeta> {
    return await this.req<KeyMeta>("GET", "/v1/keys/me");
  }

  /** Public — list supported categories / contexts / sensitivities. */
  async patterns(): Promise<{
    categories: ThreatType[];
    sensitivities: Sensitivity[];
    contexts: ContextKind[];
  }> {
    return await this.req("GET", "/v1/patterns");
  }

  // ---- internal ----

  private async req<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const url = this.base + path;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const r = await this.fetchImpl(url, {
        method,
        signal: ctrl.signal,
        headers: {
          authorization: `Bearer ${this.apiKey}`,
          "user-agent": USER_AGENT,
          ...(body ? { "content-type": "application/json" } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
      });
      let parsed: any;
      try {
        parsed = await r.json();
      } catch {
        parsed = { error: { code: `http_${r.status}`, message: await r.text() } };
      }
      if (r.status >= 400) this.throwFor(r.status, parsed);
      return parsed as T;
    } finally {
      clearTimeout(timer);
    }
  }

  private throwFor(status: number, body: any): never {
    const err = body?.error ?? {};
    const code = String(err.code ?? `http_${status}`);
    const message = String(err.message ?? "Unknown error.");
    if (status === 401) throw new AuthError(code, message, status);
    if (status === 402) throw new QuotaExceededError(code, message, status);
    if (status === 429) throw new RateLimitError(code, message, status);
    throw new InjectShieldError(code, message, status);
  }
}

/** Convenience factory matching common SDK ergonomics. */
export function createClient(opts: InjectShieldOptions): InjectShield {
  return new InjectShield(opts);
}

export default InjectShield;
