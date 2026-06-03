import { serializeResult, utf8Len } from "../sandbox/serialize.js";

// Cloudflare Durable Object values are limited to 128 KiB. Keep replay payloads below that so
// the ledger record wrapper and metadata still fit after JSON serialization.
export const MUTATION_REPLAY_MAX_BYTES = 96 * 1024;

export function isReplaySafeWrapper(result: unknown): boolean {
  if (typeof result !== "object" || result === null || Array.isArray(result)) return false;
  const keys = Object.keys(result);
  return (
    keys.length === 3 &&
    keys.includes("truncated") &&
    keys.includes("totalBytes") &&
    keys.includes("serializedResult") &&
    (result as { truncated?: unknown }).truncated === true &&
    typeof (result as { totalBytes?: unknown }).totalBytes === "number" &&
    typeof (result as { serializedResult?: unknown }).serializedResult === "string" &&
    utf8Len((result as { serializedResult: string }).serializedResult) <= MUTATION_REPLAY_MAX_BYTES
  );
}

export function replaySafeResult(result: unknown): unknown {
  if (isReplaySafeWrapper(result)) return result;
  const serialized = serializeResult(result, MUTATION_REPLAY_MAX_BYTES);
  if (serialized.truncated) {
    return {
      truncated: true,
      totalBytes: serialized.totalBytes,
      serializedResult: serialized.text,
    };
  }
  try {
    return JSON.parse(serialized.text);
  } catch {
    return {
      truncated: true,
      totalBytes: serialized.totalBytes,
      serializedResult: serialized.text,
    };
  }
}
