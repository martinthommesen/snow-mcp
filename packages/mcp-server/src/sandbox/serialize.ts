// Host-side run_code result serialization (plan §4.4, §10 safe-serialize spirit).
// Never throws on a non-serializable / over-cap result.

export function utf8Len(s: string): number {
  // TextEncoder gives exact UTF-8 byte length.
  return new TextEncoder().encode(s).length;
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
    // Truncate the JSON text to a sample; flag truncation (never re-parse the slice).
    return { text: json.slice(0, maxBytes), truncated: true, totalBytes };
  }
  return { text: json, truncated: false, totalBytes };
}
