// Secret redaction for logs/observability (plan §7.1, T5). Never log script bodies or
// full RPC responses; scrub tokens and denylisted fields before anything is emitted.
// Pure host logic — verified locally.

const TOKEN_PATTERNS: readonly RegExp[] = [
  /\b(Bearer|Basic)\s+[A-Za-z0-9._\-+/=]{8,}/gi, // auth headers
  /\beyJ[A-Za-z0-9._\-]{10,}/g, // JWT-ish
  /\b(?:password|secret|token|api[_-]?key|client_secret)\s*[=:]\s*[^\s,&"']+/gi,
];

/** Field names whose VALUES are always redacted in objects (case-insensitive). */
const DENY_FIELDS = new Set(
  [
    "password",
    "secret",
    "client_secret",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "hmac_secret",
    "token_kek",
    "snapshot_kek",
    "x_mcp_executor_hmac_key",
  ].map((s) => s.toLowerCase()),
);

export const REDACTED = "[REDACTED]";

export function redactString(input: string): string {
  let out = input;
  for (const re of TOKEN_PATTERNS) out = out.replace(re, REDACTED);
  return out;
}

/** Deep-redact: scrub denylisted field values and token patterns in strings. */
export function redactValue(value: unknown, depth = 0): unknown {
  if (depth > 8) return "[depth-limit]";
  if (typeof value === "string") return redactString(value);
  if (Array.isArray(value)) return value.map((v) => redactValue(v, depth + 1));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = DENY_FIELDS.has(k.toLowerCase()) ? REDACTED : redactValue(v, depth + 1);
    }
    return out;
  }
  return value;
}
