// Host-side run_code result serialization (plan §4.4, §10 safe-serialize spirit).
// Never throws on a non-serializable / over-cap result.

const enc = new TextEncoder();
const dec = new TextDecoder();

export function utf8Len(s: string): number {
  // TextEncoder gives exact UTF-8 byte length.
  return enc.encode(s).length;
}

function truncateEncodedUtf8(bytes: Uint8Array, maxBytes: number): string {
  let end = maxBytes;
  // Walk back off continuation bytes (0b10xxxxxx) to the start of the boundary sequence.
  while (end > 0 && (bytes[end]! & 0xc0) === 0x80) end--;
  return dec.decode(bytes.subarray(0, end));
}

/**
 * Truncate `s` to at most `maxBytes` UTF-8 bytes, never splitting a multi-byte sequence
 * (plan §P2). Encode → byte-slice at `maxBytes` → back off any trailing continuation
 * bytes (`10xxxxxx`) plus the lead byte they belong to → decode the whole-sequence prefix.
 * Backing off BEFORE decode avoids a replacement char (U+FFFD, 3 bytes) pushing the
 * result back over the cap.
 */
export function truncateUtf8(s: string, maxBytes: number): string {
  const bytes = enc.encode(s);
  if (bytes.length <= maxBytes) return s;
  return truncateEncodedUtf8(bytes, maxBytes);
}

export interface SerializedResult {
  text: string;
  truncated: boolean;
  totalBytes: number;
}

interface SanitizedJson {
  value: unknown;
  path?: string;
}

const SANITIZE_MAX_DEPTH = 32;
const SANITIZE_MAX_NODES = 1_000;

function sanitizeForJson(value: unknown): SanitizedJson {
  const seen = new WeakSet<object>();
  let nodes = 0;
  let firstPath: string | undefined;
  const notePath = (path: string): void => {
    firstPath ??= path;
  };

  const visit = (v: unknown, path: string, depth: number): unknown => {
    if (nodes++ >= SANITIZE_MAX_NODES) {
      notePath(path);
      return "[Truncated]";
    }
    if (typeof v === "bigint") {
      notePath(path);
      return v.toString();
    }
    if (typeof v === "function" || typeof v === "symbol") {
      notePath(path);
      return `[${typeof v}]`;
    }
    if (!v || typeof v !== "object") return v;
    if (depth >= SANITIZE_MAX_DEPTH) {
      notePath(path);
      return "[MaxDepth]";
    }
    if (seen.has(v)) {
      notePath(path);
      return "[Circular]";
    }
    seen.add(v);
    if (Array.isArray(v)) {
      const out: unknown[] = [];
      for (let i = 0; i < v.length; i++) {
        if (nodes >= SANITIZE_MAX_NODES) {
          notePath(`${path}[${i}]`);
          out.push("[Truncated]");
          break;
        }
        out.push(visit(v[i], `${path}[${i}]`, depth + 1));
      }
      return out;
    }
    const out: Record<string, unknown> = {};
    for (const [k, item] of Object.entries(v as Record<string, unknown>)) {
      if (nodes >= SANITIZE_MAX_NODES) {
        notePath(`${path}.${k}`);
        out[k] = "[Truncated]";
        break;
      }
      out[k] = visit(item, `${path}.${k}`, depth + 1);
    }
    return out;
  };

  return { value: visit(value, "$", 0), ...(firstPath ? { path: firstPath } : {}) };
}

function cappedJsonText(json: string, maxBytes: number): SerializedResult {
  const bytes = enc.encode(json);
  const totalBytes = bytes.length;
  if (totalBytes > maxBytes) {
    return { text: truncateEncodedUtf8(bytes, maxBytes), truncated: true, totalBytes };
  }
  return { text: json, truncated: false, totalBytes };
}

/** Serialize a value to JSON text, truncating beyond `maxBytes`. Safe on circular/deep. */
export function serializeResult(value: unknown, maxBytes: number): SerializedResult {
  let json: string;
  try {
    json = JSON.stringify(value === undefined ? null : value);
  } catch {
    const sanitized = sanitizeForJson(value);
    let replacementJson: string;
    try {
      replacementJson = JSON.stringify({
        error: "result_not_serializable",
        ...(sanitized.path ? { path: sanitized.path } : {}),
        value: sanitized.value,
      });
    } catch {
      replacementJson = JSON.stringify({ error: "result_not_serializable", ...(sanitized.path ? { path: sanitized.path } : {}) });
    }
    return cappedJsonText(replacementJson, maxBytes);
  }
  return cappedJsonText(json, maxBytes);
}

export interface CappedLogs {
  logs: string[];
  truncated: boolean;
}

/**
 * Cap snippet-captured console logs (M-3). The sandbox's `console.log` capture is unbounded, and
 * the logs were spliced into the tool result verbatim — past the documented output cap. Bound BOTH
 * entry count and cumulative UTF-8 bytes, truncating the final retained entry byte-safely
 * (reuses truncateUtf8 — never split a multi-byte sequence). Returns a `truncated` flag so the
 * caller can surface `logsTruncated`.
 */
export function capLogs(logs: readonly unknown[], maxEntries: number, maxBytes: number): CappedLogs {
  let truncated = false;
  let entries = logs;
  if (entries.length > maxEntries) {
    entries = entries.slice(0, maxEntries);
    truncated = true;
  }
  const out: string[] = [];
  let total = 0;
  for (const e of entries) {
    const s = typeof e === "string" ? e : String(e);
    const len = utf8Len(s);
    if (total + len > maxBytes) {
      const remaining = maxBytes - total;
      if (remaining > 0) out.push(truncateUtf8(s, remaining));
      truncated = true;
      break;
    }
    out.push(s);
    total += len;
  }
  return { logs: out, truncated };
}
