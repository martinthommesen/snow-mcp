// AES-256-GCM versioned, AAD-bound token envelope + KEK rotation (plan §2.7, §2.1/2.1).
// WebCrypto only — fully unit-verified locally (round-trip, AAD-mismatch fail-closed,
// current+previous KEK rotation window).

import { base64ToBytes, bytesToBase64, bytesToHex } from "./encoding.js";

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

const aesKeys = new WeakMap<Uint8Array, Promise<CryptoKey>>();

async function importKey(kek: Kek): Promise<CryptoKey> {
  if (kek.keyBytes.length !== 32) {
    throw new Error(`KEK "${kek.version}" must be 32 bytes (AES-256), got ${kek.keyBytes.length}.`);
  }
  let key = aesKeys.get(kek.keyBytes);
  if (!key) {
    key = crypto.subtle.importKey("raw", kek.keyBytes as BufferSource, { name: "AES-GCM" }, false, [
      "encrypt",
      "decrypt",
    ]);
    aesKeys.set(kek.keyBytes, key);
  }
  return key;
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
    iv: bytesToBase64(iv),
    aad,
    ciphertext: bytesToBase64(ct),
  };
}

/**
 * Decrypt an envelope, binding `expectedAad`. Fails closed (throws) on AAD mismatch,
 * tampering, or an unknown KEK version. Uses the stamped KEK version, accepting the previous
 * KEK only during an explicit rotation window.
 */
export async function open(envelope: TokenEnvelope, expectedAad: string, ring: KekRing): Promise<string> {
  if (envelope.aad !== expectedAad) {
    throw new Error("token envelope AAD mismatch — refusing to decrypt (fail closed).");
  }
  const candidates: Kek[] = [];
  if (envelope.kekVersion === ring.current.version) candidates.push(ring.current);
  if (ring.previous && envelope.kekVersion === ring.previous.version) candidates.push(ring.previous);
  if (candidates.length === 0) throw new Error(`unknown KEK version "${envelope.kekVersion}" (fail closed).`);

  const iv = base64ToBytes(envelope.iv);
  const ct = base64ToBytes(envelope.ciphertext);
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
 * Derive a 32-byte AES-256 key from a KEK secret via a single SHA-256. Deterministic (same secret
 * → same key), which the rotation/migration path depends on — DO NOT change this derivation, or
 * every existing envelope (stamped by content-addressed label over these exact bytes) becomes
 * undecryptable.
 *
 * M-8: this is UNSALTED, SINGLE-ITERATION. That is cryptographically fine IFF `secret` is a
 * high-entropy CSPRNG value (e.g. `openssl rand -base64 32`). A low-entropy passphrase is
 * offline-guessable (~1 SHA-256 + 1 AES-GCM/candidate, no salt → amortizes across deployments) if
 * envelopes ever leak. We do not stretch (changing it breaks existing envelopes) — instead callers
 * WARN on weak-looking secrets at startup (warnIfWeakSecret) and the docs mandate CSPRNG secrets.
 */
export async function deriveKeyBytes(secret: string): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(secret) as BufferSource);
  return new Uint8Array(digest);
}

/** Heuristic (M-8): does `secret` look like a CSPRNG-generated key of >=32 bytes — base64/base64url
 *  (>=43 chars) or hex (>=64 chars)? Used only to WARN; never to gate (a hard reject would brick an
 *  existing deployment that uses a passphrase). */
export function looksLikeStrongSecret(secret: string): boolean {
  const s = secret.trim();
  const base64ish = /^[A-Za-z0-9+/_-]+={0,2}$/.test(s) && s.replace(/=+$/, "").length >= 43;
  const hexish = /^[0-9a-fA-F]+$/.test(s) && s.length >= 64;
  return base64ish || hexish;
}

/** WARN (structured, alertable; never throw) when a KEK/HMAC secret does not look CSPRNG-strong
 *  (M-8). Call once at startup per secret — never per-request (log spam). */
export function warnIfWeakSecret(name: string, secret: string): void {
  if (secret && !looksLikeStrongSecret(secret)) {
    console.warn(
      JSON.stringify({
        event: "weak_secret_warning",
        secret: name,
        note: "value does not look like a CSPRNG 32-byte key; derivation is unsalted SHA-256, so a low-entropy secret is offline-guessable if envelopes leak (M-8). Generate with `openssl rand -base64 32`.",
      }),
    );
  }
}

/** Per-isolate dedup of {@link warnIfWeakSecret} by secret name. */
const warnedSecretNames = new Set<string>();

/**
 * Startup-once weak-secret warning for call sites on the PER-REQUEST path (e.g. buildHandlers,
 * which runs inside fetch). `warnIfWeakSecret` must not be called per-request (log spam, M-1a);
 * this fires at most once per secret name per isolate. The first call decides — subsequent calls
 * (strong or weak) are silent, matching the "warn at startup, never per-request" contract.
 */
export function warnIfWeakSecretOnce(name: string, secret: string): void {
  if (warnedSecretNames.has(name)) return;
  warnedSecretNames.add(name);
  warnIfWeakSecret(name, secret);
}

/**
 * Content-addressed KEK version label: `kek-${hex(sha256(keyBytes)).slice(0,8)}`. Distinct
 * keys are overwhelmingly unlikely to share a label (32-bit content address), which avoids
 * the constant-"current" same-label collision that defeated rotation before P3. A label
 * collision is harmless: GCM authentication — not the label — decides decryption, so a wrong
 * key can never produce a valid open().
 * The label is stable across deploys for a given passphrase (P3).
 */
async function kekLabel(keyBytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", keyBytes as BufferSource));
  return `kek-${bytesToHex(digest).slice(0, 8)}`;
}

/**
 * Build a rotation-capable KEK ring from a current passphrase (+ optional previous) using
 * content-addressed version labels (P3). Reused for BOTH the token ring (wired now) and the
 * snapshot ring (P4 consumes this same helper). Fails closed if no current secret is given.
 */
export async function buildKekRing(currentSecret: string, prevSecret?: string): Promise<KekRing> {
  if (!currentSecret) throw new Error("KEK ring requires a current secret (fail closed).");
  warnIfWeakSecret("KEK (current)", currentSecret); // M-8: startup-only weak-secret warning
  const currentBytes = await deriveKeyBytes(currentSecret);
  const ring: KekRing = { current: { version: await kekLabel(currentBytes), keyBytes: currentBytes } };
  if (prevSecret) {
    warnIfWeakSecret("KEK (previous)", prevSecret);
    const prevBytes = await deriveKeyBytes(prevSecret);
    ring.previous = { version: await kekLabel(prevBytes), keyBytes: prevBytes };
  }
  return ring;
}
