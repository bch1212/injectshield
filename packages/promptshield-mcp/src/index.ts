#!/usr/bin/env node
// PromptShield MCP server — wraps the PromptShield REST API as MCP tools.
//
// Tools:
//   - scan        Scan a string for prompt-injection.
//   - scan_url    Fetch a URL and scan its body.
//   - patterns    List supported categories / contexts / sensitivities.
//
// Configuration (env):
//   PROMPTSHIELD_API_KEY   Required. ps_live_… key from https://promptshield-6hz.pages.dev
//   PROMPTSHIELD_API_BASE  Optional. Defaults to the public managed endpoint.
//
// Transport: stdio (standard MCP local-server transport).

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ErrorCode,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";

const API_BASE =
  process.env.PROMPTSHIELD_API_BASE ||
  "https://promptshield-api-production.up.railway.app";
const API_KEY = process.env.PROMPTSHIELD_API_KEY || "";

const PKG_VERSION = "0.1.0";

type Sensitivity = "low" | "medium" | "high";
type ContextKind =
  | "git_commit"
  | "web_content"
  | "user_input"
  | "file_content"
  | "email"
  | "tool_output"
  | "unknown";

interface ScanArgs {
  text: string;
  context?: ContextKind;
  sensitivity?: Sensitivity;
  return_cleaned?: boolean;
}

interface ScanUrlArgs {
  url: string;
  context?: ContextKind;
  sensitivity?: Sensitivity;
  return_cleaned?: boolean;
  max_bytes?: number;
}

const TOOL_DEFINITIONS = [
  {
    name: "scan",
    description:
      "Scan text for prompt-injection. Use BEFORE passing any untrusted text " +
      "(web pages, file contents, user inputs, git commits, tool outputs) into " +
      "another LLM call. Returns a verdict (safe/unsafe), a confidence score, " +
      "the threat category, the matched pattern IDs, and an optional sanitized " +
      "version with injection spans redacted.",
    inputSchema: {
      type: "object",
      properties: {
        text: { type: "string", description: "Text to scan (max 100,000 chars)." },
        context: {
          type: "string",
          enum: [
            "git_commit", "web_content", "user_input", "file_content",
            "email", "tool_output", "unknown",
          ],
          description:
            "Where the text came from. Affects scoring — git commits are " +
            "treated as more suspicious than user input by default.",
          default: "unknown",
        },
        sensitivity: {
          type: "string",
          enum: ["low", "medium", "high"],
          description:
            "Detection threshold. low = fewest false positives, high = " +
            "fewest false negatives. Default: medium.",
          default: "medium",
        },
        return_cleaned: {
          type: "boolean",
          description: "Return the input with detected spans redacted.",
          default: true,
        },
      },
      required: ["text"],
    },
  },
  {
    name: "scan_url",
    description:
      "Fetch a URL and scan its body for prompt-injection. Useful before " +
      "feeding scraped page content into another LLM call. Sets the context " +
      "to web_content automatically.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "URL to fetch and scan." },
        context: {
          type: "string",
          enum: [
            "git_commit", "web_content", "user_input", "file_content",
            "email", "tool_output", "unknown",
          ],
          description: "Override the default web_content context.",
          default: "web_content",
        },
        sensitivity: {
          type: "string",
          enum: ["low", "medium", "high"],
          default: "medium",
        },
        return_cleaned: { type: "boolean", default: true },
        max_bytes: {
          type: "integer",
          description: "Truncate fetched body before scanning. Default 50000.",
          default: 50_000,
        },
      },
      required: ["url"],
    },
  },
  {
    name: "patterns",
    description:
      "List supported threat categories, context kinds, and sensitivity levels. " +
      "Use this to discover what threat_type values scan() can return.",
    inputSchema: { type: "object", properties: {} },
  },
];

async function callApi(
  path: string,
  body: unknown,
  init: RequestInit = {},
): Promise<any> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "user-agent": `promptshield-mcp/${PKG_VERSION}`,
    ...((init.headers as Record<string, string>) || {}),
  };
  if (API_KEY) headers["authorization"] = "Bearer " + API_KEY;
  const r = await fetch(API_BASE + path, {
    method: "POST",
    body: JSON.stringify(body),
    headers,
    ...init,
  });
  let json: any;
  try {
    json = await r.json();
  } catch {
    throw new McpError(
      ErrorCode.InternalError,
      `PromptShield API returned non-JSON (status ${r.status}).`,
    );
  }
  if (!r.ok) {
    const code = json?.error?.code || `http_${r.status}`;
    const message =
      json?.error?.message ||
      `PromptShield API error (status ${r.status}).`;
    if (code === "missing_api_key" || code === "invalid_api_key") {
      throw new McpError(
        ErrorCode.InvalidRequest,
        `${message} Set the PROMPTSHIELD_API_KEY env var. Get a free key at https://promptshield-6hz.pages.dev`,
      );
    }
    throw new McpError(ErrorCode.InternalError, `${code}: ${message}`);
  }
  return json;
}

async function fetchUrl(url: string, maxBytes: number): Promise<string> {
  const r = await fetch(url, {
    method: "GET",
    redirect: "follow",
    headers: { "user-agent": `promptshield-mcp/${PKG_VERSION}` },
  });
  if (!r.ok) {
    throw new McpError(
      ErrorCode.InternalError,
      `Fetch failed: HTTP ${r.status} for ${url}`,
    );
  }
  const buf = await r.arrayBuffer();
  const text = new TextDecoder("utf-8", { fatal: false })
    .decode(buf)
    .slice(0, maxBytes);
  return text;
}

function unwrap<T = any>(val: unknown, label: string): T {
  if (val === undefined || val === null) {
    throw new McpError(ErrorCode.InvalidParams, `${label} is required.`);
  }
  return val as T;
}

async function handleScan(args: ScanArgs) {
  if (!args.text || typeof args.text !== "string") {
    throw new McpError(ErrorCode.InvalidParams, "text must be a non-empty string");
  }
  const data = await callApi("/v1/scan", {
    text: args.text,
    context: args.context ?? "unknown",
    options: {
      sensitivity: args.sensitivity ?? "medium",
      return_cleaned: args.return_cleaned !== false,
    },
  });
  return data;
}

async function handleScanUrl(args: ScanUrlArgs) {
  const url = unwrap<string>(args.url, "url");
  const body = await fetchUrl(url, args.max_bytes ?? 50_000);
  const data = await callApi("/v1/scan", {
    text: body,
    context: args.context ?? "web_content",
    options: {
      sensitivity: args.sensitivity ?? "medium",
      return_cleaned: args.return_cleaned !== false,
    },
  });
  return { url, fetched_bytes: body.length, ...data };
}

async function handlePatterns() {
  const r = await fetch(API_BASE + "/v1/patterns", {
    headers: { "user-agent": `promptshield-mcp/${PKG_VERSION}` },
  });
  return await r.json();
}

const server = new Server(
  { name: "promptshield-mcp", version: PKG_VERSION },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOL_DEFINITIONS,
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const name = req.params.name;
  const args = (req.params.arguments ?? {}) as any;
  let result: unknown;
  try {
    if (name === "scan") result = await handleScan(args);
    else if (name === "scan_url") result = await handleScanUrl(args);
    else if (name === "patterns") result = await handlePatterns();
    else {
      throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
    }
  } catch (e: any) {
    if (e instanceof McpError) throw e;
    throw new McpError(
      ErrorCode.InternalError,
      `${name} failed: ${e?.message ?? String(e)}`,
    );
  }
  return {
    content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
  };
});

async function main() {
  if (!API_KEY) {
    // Don't hard-fail at startup — patterns() works without auth, and the
    // helpful error is delivered at first scan() call. But warn on stderr.
    process.stderr.write(
      "[promptshield-mcp] PROMPTSHIELD_API_KEY not set — scan/scan_url will return auth errors. " +
        "Get a free key: https://promptshield-6hz.pages.dev\n",
    );
  }
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((e) => {
  process.stderr.write(`[promptshield-mcp] fatal: ${e?.stack || e}\n`);
  process.exit(1);
});
