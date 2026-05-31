// Host-side run_code result serialization (plan §4.4, §10 safe-serialize spirit).
// Never throws on a non-serializable / over-cap result.

export function utf8Len(s: string): number {
  // TextEncoder gives exact UTF-8 byte length.
  return new TextEncoder().encode(s).length;
}

/**
 * Truncate `s` to at most `maxBytes` UTF-8 bytes, never splitting a multi-byte sequence
 * (plan §P2). Encode → byte-slice at `maxBytes` → back off any trailing continuation
 * bytes (`10xxxxxx`) plus the lead byte they belong to → decode the whole-sequence prefix.
 * Backing off BEFORE decode avoids a replacement char (U+FFFD, 3 bytes) pushing the
 * result back over the cap.
 */
export function truncateUtf8(s: string, maxBytes: number): string {
  const bytes = new TextEncoder().encode(s);
  if (bytes.length <= maxBytes) return s;
  let end = maxBytes;
  // Walk back off continuation bytes (0b10xxxxxx) to the start of the boundary sequence.
  while (end > 0 && (bytes[end]! & 0xc0) === 0x80) end--;
  return new TextDecoder().decode(bytes.subarray(0, end));
}

export interface SerializedResult {
  text: string;
  truncated: boolean;
  totalBytes: number;
}

/** Serialize a value to JSON text, truncating beyond `maxBytes`. Safe on circular/deep. */
export function serializeResult(value: unknown, maxBytes: number): SerializedResult {
  let json: string;
  try {
    json = JSON.stringify(value === undefined ? null : value);
  } catch {
    const fallback = JSON.stringify({ error: "result_not_serializable" });
    return { text: fallback, truncated: false, totalBytes: utf8Len(fallback) };
  }
  const totalBytes = utf8Len(json);
  if (totalBytes > maxBytes) {
    // Byte-safe truncation: cap at maxBytes UTF-8 bytes without splitting a sequence
    // (§P2). Flag truncation (never re-parse the slice).
    return { text: truncateUtf8(json, maxBytes), truncated: true, totalBytes };
  }
  return { text: json, truncated: false, totalBytes };
}
