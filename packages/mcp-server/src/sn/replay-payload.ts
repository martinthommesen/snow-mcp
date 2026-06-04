import { serializeResult, utf8Len } from "../sandbox/serialize.js";

// Cloudflare Durable Object values are limited to 128 KiB. Keep replay payloads below that so
// the ledger record wrapper and metadata still fit after JSON serialization.
export const MUTATION_REPLAY_MAX_BYTES = 96 * 1024;

/** A serialized, size-bounded replay payload stored in the mutation ledger. */
export interface ReplaySafeWrapper {
  replaySafe: true;
  truncated: boolean;
  totalBytes: number;
  serializedResult: string;
}

function isTruncatedReplayPayload(result: unknown): result is Omit<ReplaySafeWrapper, "replaySafe"> {
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

export function isReplaySafeWrapper(result: unknown): result is ReplaySafeWrapper {
  if (typeof result !== "object" || result === null || Array.isArray(result)) return false;
  const keys = Object.keys(result);
  return (
    keys.length === 4 &&
    keys.includes("replaySafe") &&
    keys.includes("truncated") &&
    keys.includes("totalBytes") &&
    keys.includes("serializedResult") &&
    (result as { replaySafe?: unknown }).replaySafe === true &&
    typeof (result as { truncated?: unknown }).truncated === "boolean" &&
    typeof (result as { totalBytes?: unknown }).totalBytes === "number" &&
    typeof (result as { serializedResult?: unknown }).serializedResult === "string" &&
    utf8Len((result as { serializedResult: string }).serializedResult) <= MUTATION_REPLAY_MAX_BYTES
  );
}

export function replaySafeResult(result: unknown): ReplaySafeWrapper {
  if (isReplaySafeWrapper(result)) return result;
  if (isTruncatedReplayPayload(result)) {
    return {
      replaySafe: true,
      truncated: true,
      totalBytes: result.totalBytes,
      serializedResult: result.serializedResult,
    };
  }
  const serialized = serializeResult(result, MUTATION_REPLAY_MAX_BYTES);
  return {
    replaySafe: true,
    truncated: serialized.truncated,
    totalBytes: serialized.totalBytes,
    serializedResult: serialized.text,
  };
}

export function visibleReplayResult(result: ReplaySafeWrapper): unknown {
  if (result.truncated) {
    return {
      truncated: true,
      totalBytes: result.totalBytes,
      serializedResult: result.serializedResult,
    };
  }
  return JSON.parse(result.serializedResult);
}
