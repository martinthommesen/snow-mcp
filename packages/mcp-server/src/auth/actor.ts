// Host-side actor attribution: canonicalize + HMAC-SHA256 sign (plan §2.0).
//
// In integration_user mode every mutating/executor call carries a host-signed actor
// payload that the x_mcp executor VERIFIES in-scope (freshness + nonce, fail-closed).
// The signing here is unit-verified locally; the AUTHORITATIVE verification lives on
// ServiceNow (Script Include `x_mcp_verify`, Phase 0.13a/5.4a — blocked on a PDI).

export interface ActorClaims {
  mcp_actor_user_id: string;
  mcp_actor_email: string;
  snow_effective_user_sys_id: string;
  instance: string;
  request_id: string;
}

export interface SignedActorPayload extends ActorClaims {
  script_sha256: string;
  issued_at: number; // epoch ms
  nonce: string;
}

export interface SignedActor {
  actor: SignedActorPayload;
  actor_sig: string; // base64 HMAC-SHA256 over the canonical payload
}

// Stable key order — MUST match the executor's verifier (§2.0). Do not reorder.
const CANONICAL_KEYS: readonly (keyof SignedActorPayload)[] = [
  "mcp_actor_user_id",
  "mcp_actor_email",
  "snow_effective_user_sys_id",
  "instance",
  "request_id",
  "script_sha256",
  "issued_at",
  "nonce",
];

// Engine-independent, ASCII-ONLY string escaper. The bytes that get HMAC'd must be
// reproduced byte-for-byte by ServiceNow's (Rhino-derived) engine, whose JSON.stringify
// may escape non-ASCII differently from V8. We therefore escape EVERY char outside
// printable ASCII (and the JSON specials) as \uXXXX, so the canonical form is pure ASCII
// regardless of engine. x_mcp_verify.js MUST use the identical scheme (see that file).
function asciiJsonString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += "\\\\";
    else if (c < 0x20 || c >= 0x7f) out += "\\u" + c.toString(16).padStart(4, "0");
    else out += s[i];
  }
  return out + '"';
}

/**
 * Deterministic, ASCII-only canonical encoding over the fixed key order (the bytes that
 * get HMAC'd). Engine-independent by construction — see asciiJsonString above. This is
 * the security-critical contract shared with the in-scope verifier (B1).
 */
export function canonicalize(payload: SignedActorPayload): string {
  const parts: string[] = [];
  for (const k of CANONICAL_KEYS) {
    const v = payload[k];
    const valStr = typeof v === "number" ? String(v) : asciiJsonString(String(v));
    parts.push(`${asciiJsonString(k)}:${valStr}`);
  }
  return `{${parts.join(",")}}`;
}

const enc = new TextEncoder();

function b64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s);
}

/** SHA-256(base64) of a string — used for script_sha256 (matches GlideDigest base64). */
export async function sha256Base64(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(input) as BufferSource);
  return b64(new Uint8Array(digest));
}

async function hmacKey(keyBytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    keyBytes as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

/** Base64 HMAC-SHA256 of `canonical` under `keyBytes`. */
export async function hmacSha256Base64(canonical: string, keyBytes: Uint8Array): Promise<string> {
  const key = await hmacKey(keyBytes);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(canonical) as BufferSource);
  return b64(new Uint8Array(sig));
}

export interface SignActorInput {
  claims: ActorClaims;
  script: string;
  issuedAt: number; // epoch ms — caller supplies (testable, no hidden clock)
  nonce: string; // caller supplies a unique value
  hmacKey: Uint8Array;
}

/** Build the canonical signed-actor payload + signature for an executor/mutation call. */
export async function signActor(input: SignActorInput): Promise<SignedActor> {
  const script_sha256 = await sha256Base64(input.script);
  const payload: SignedActorPayload = {
    ...input.claims,
    script_sha256,
    issued_at: input.issuedAt,
    nonce: input.nonce,
  };
  const actor_sig = await hmacSha256Base64(canonicalize(payload), input.hmacKey);
  return { actor: payload, actor_sig };
}

/**
 * Host-side mirror of the executor's verification — used ONLY to unit-test the signing
 * logic and to support the optional stdio path. The AUTHORITATIVE verifier is the
 * in-scope ServiceNow Script Include; do not treat this as the security boundary.
 */
export async function verifyActorSignatureLocal(
  signed: SignedActor,
  script: string,
  keyBytes: Uint8Array,
  opts: { now: number; freshnessMs?: number },
): Promise<boolean> {
  const freshness = opts.freshnessMs ?? 120_000;
  if (Math.abs(opts.now - signed.actor.issued_at) > freshness) return false;
  if ((await sha256Base64(script)) !== signed.actor.script_sha256) return false;
  const expected = await hmacSha256Base64(canonicalize(signed.actor), keyBytes);
  // Constant-time-ish compare.
  if (expected.length !== signed.actor_sig.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ signed.actor_sig.charCodeAt(i);
  return diff === 0;
}
