// AES-256-GCM versioned, AAD-bound token envelope + KEK rotation (plan §2.7, §2.1/2.1).
// WebCrypto only — fully unit-verified locally (round-trip, AAD-mismatch fail-closed,
// current+previous KEK rotation window).

export interface TokenEnvelope {
  version: 1;
  kekVersion: string;
  alg: "AES-256-GCM";
  iv: string; // base64, 12 bytes
  aad: string; // "user_id|instance_host|token_type"
  ciphertext: string; // base64 (includes the GCM auth tag)
}

export interface Kek {
  version: string; // e.g. "2026-05"
  /** 32 raw bytes (AES-256). */
  keyBytes: Uint8Array;
}

export interface KekRing {
  current: Kek;
  previous?: Kek; // accepted during a rotation window
}

function b64encode(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s);
}
function b64decode(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function importKey(kek: Kek): Promise<CryptoKey> {
  if (kek.keyBytes.length !== 32) {
    throw new Error(`KEK "${kek.version}" must be 32 bytes (AES-256), got ${kek.keyBytes.length}.`);
  }
  return crypto.subtle.importKey("raw", kek.keyBytes as BufferSource, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

const enc = new TextEncoder();
const dec = new TextDecoder();

/** Encrypt `plaintext` under the current KEK, binding `aad`. */
export async function seal(plaintext: string, aad: string, ring: KekRing): Promise<TokenEnvelope> {
  const key = await importKey(ring.current);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv as BufferSource, additionalData: enc.encode(aad) as BufferSource },
      key,
      enc.encode(plaintext) as BufferSource,
    ),
  );
  return {
    version: 1,
    kekVersion: ring.current.version,
    alg: "AES-256-GCM",
    iv: b64encode(iv),
    aad,
    ciphertext: b64encode(ct),
  };
}

/**
 * Decrypt an envelope, binding `expectedAad`. Fails closed (throws) on AAD mismatch,
 * tampering, or an unknown KEK version. Tries the KEK whose version matches, then the
 * previous KEK if the matching one fails (rotation window).
 */
export async function open(envelope: TokenEnvelope, expectedAad: string, ring: KekRing): Promise<string> {
  if (envelope.aad !== expectedAad) {
    throw new Error("token envelope AAD mismatch — refusing to decrypt (fail closed).");
  }
  const candidates: Kek[] = [];
  if (envelope.kekVersion === ring.current.version) candidates.push(ring.current);
  if (ring.previous && envelope.kekVersion === ring.previous.version) candidates.push(ring.previous);
  // Rotation safety: if the stamped version matches neither, still try both keys.
  if (candidates.length === 0) {
    candidates.push(ring.current);
    if (ring.previous) candidates.push(ring.previous);
  }

  const iv = b64decode(envelope.iv);
  const ct = b64decode(envelope.ciphertext);
  let lastErr: unknown;
  for (const kek of candidates) {
    try {
      const key = await importKey(kek);
      const pt = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv as BufferSource, additionalData: enc.encode(expectedAad) as BufferSource },
        key,
        ct as BufferSource,
      );
      return dec.decode(pt);
    } catch (e) {
      lastErr = e;
    }
  }
  throw new Error(`token decrypt failed under all candidate KEKs: ${String(lastErr)}`);
}

/** Canonical AAD for a ServiceNow token row (§2.7). */
export function tokenAad(userId: string, instanceHost: string, tokenType: string): string {
  return `${userId}|${instanceHost}|${tokenType}`;
}

/**
 * Derive a 32-byte AES-256 key from an arbitrary KEK passphrase via SHA-256. Lets a KEK
 * secret be any string (not necessarily base64-32). Deterministic, so the same passphrase
 * always yields the same key.
 */
export async function deriveKeyBytes(secret: string): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(secret) as BufferSource);
  return new Uint8Array(digest);
}
