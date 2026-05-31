// Typed error model (plan §1.6, §3.x). One error class carrying a stable `code`
// plus a human message; helpers map HTTP/ServiceNow failures to codes and render an
// MCP tool result. Pure host logic — unit-verified locally.

import { ERROR_CODES, type ErrorCode } from "@servicenow-codemode/shared";

const ERROR_CODE_SET: ReadonlySet<string> = new Set(ERROR_CODES);

export class McpToolError extends Error {
  readonly code: ErrorCode;
  /** Optional structured detail (never includes secrets/script body — §7.1). */
  readonly detail?: Record<string, unknown>;
  constructor(code: ErrorCode, message: string, detail?: Record<string, unknown>) {
    super(message);
    this.name = "McpToolError";
    this.code = code;
    if (detail !== undefined) this.detail = detail;
  }
}

/** Render any error as an MCP tool result `{ content, isError, structuredContent }`. */
export function toToolResult(err: unknown): {
  content: { type: "text"; text: string }[];
  isError: true;
  structuredContent: { code: ErrorCode; message: string; detail?: Record<string, unknown> };
} {
  const code: ErrorCode = err instanceof McpToolError ? err.code : "internal_error";
  const message = err instanceof Error ? err.message : String(err);
  // Carry structured detail (e.g. reauth_required.authorizeUrl, budget_exceeded.dimension)
  // through the non-sandbox throw path so preflight conditions survive (plan §P2).
  const detail = err instanceof McpToolError ? err.detail : undefined;
  return {
    content: [{ type: "text", text: `[${code}] ${message}` }],
    isError: true,
    structuredContent: detail !== undefined ? { code, message, detail } : { code, message },
  };
}

// ── Preserving the typed code across the sandbox boundary ──
// codemode propagates only `err.message` from a thrown tool fn (ToolDispatcher returns
// `{ error: err.message }`). To keep the typed `code` auditable end-to-end (§3.5), RPC
// fns encode it into the message; run_code decodes it back into structuredContent.

const CODE_PREFIX = /^\[\[([a-z_]+)\]\]\s?([\s\S]*)$/;

export function encodeSandboxError(err: unknown): string {
  if (err instanceof McpToolError) return `[[${err.code}]] ${err.message}`;
  return err instanceof Error ? err.message : String(err);
}

export function parseSandboxError(message: string): { code?: ErrorCode; message: string } {
  const m = CODE_PREFIX.exec(message);
  // Membership-check the parsed prefix against the known union (advisory hygiene only —
  // §P2). A snippet-forged or non-union `[[…]]` tag yields no `code`. The host never
  // attests this code: it is only used for the advisory message below. Host-attested
  // codes come from monotonic host signals in run_code, never from this parse.
  if (m && ERROR_CODE_SET.has(m[1]!)) return { code: m[1] as ErrorCode, message: m[2]! };
  if (m) return { message: m[2]! };
  return { message };
}

/**
 * Map a ServiceNow HTTP response to a typed error code. `body` is the parsed JSON
 * error payload when available. Returns null when the status is success (2xx).
 */
export function mapServiceNowError(status: number, body?: { error?: { message?: string } }): McpToolError | null {
  if (status >= 200 && status < 300) return null;
  const snMessage = body?.error?.message;

  // Hibernating PDIs answer with a 200 HTML splash or a gateway error; callers detect
  // the splash separately. Here we map the explicit status families.
  if (status === 401) return new McpToolError("reauth_required", snMessage ?? "ServiceNow authentication failed.");
  if (status === 403) {
    return new McpToolError("actor_policy_denied", snMessage ?? "ServiceNow denied access (ACL/role).");
  }
  if (status === 429) {
    return new McpToolError("budget_exceeded", snMessage ?? "ServiceNow rate limit (429).");
  }
  if (status >= 500) {
    return new McpToolError("instance_hibernating", snMessage ?? `ServiceNow ${status} (instance may be hibernating).`);
  }
  return new McpToolError("internal_error", snMessage ?? `ServiceNow error ${status}.`);
}
