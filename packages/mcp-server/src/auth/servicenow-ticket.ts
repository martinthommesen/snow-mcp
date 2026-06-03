// Opaque reauth ticket (plan §6b) — the identity bridge from an authenticated /mcp
// request to the UNauthenticated /servicenow/authorize route (which has no ctx.props).
//
// Inside /mcp, where ctx.props.userId EXISTS, the host mints an encrypted ticket {userId,
// actorEmail?, instanceHost, nonce, exp} under a HOST secret (OAUTH_PROVIDER_SECRET,
// domain-separated as AES-GCM AAD). This ticket string is the `authorizeUrl` the
// reauth_required carries (P2 detail channel). At /servicenow/authorize the host decrypts and
// verifies exp — it is the route's ONLY identity authority; nothing client-supplied at that route
// is trusted. The browser URL carries only opaque ciphertext, not readable user claims.
//
// The secret is derived to 32 raw bytes via SHA-256 (auth/crypto.ts deriveKeyBytes), matching the
// token-store KEK derivation model.

import { deriveKeyBytes } from "./crypto.js";
import { base64UrlToBytes, bytesToBase64Url } from "./encoding.js";

/** Domain-separation prefix so this signature can never be confused with another use of the
 *  same host secret (e.g. Alchemy state, OAuthProvider internals). */
const TICKET_CONTEXT = "sn-oauth-reauth-ticket\n";
const TICKET_VERSION = "v2";

export interface ReauthTicket {
  userId: string;
  actorEmail?: string;
  instanceHost: string;
  nonce: string;
  expectedSnSysId?: string;
  exp: number; // epoch ms
}

const enc = new TextEncoder();
const dec = new TextDecoder();

async function ticketKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", await deriveKeyBytes(secret) as BufferSource, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

export function normalizeIdentityEmail(value: unknown): string {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

/**
 * Mint an opaque ticket string `v2.<iv>.<ciphertext>` (base64url parts). `secret` is the host
 * OAUTH_PROVIDER_SECRET. Returns the opaque token only — the caller builds the full
 * `${origin}/servicenow/authorize?ticket=…` URL.
 */
export async function mintTicket(ticket: ReauthTicket, secret: string): Promise<string> {
  const actorEmail = normalizeIdentityEmail(ticket.actorEmail);
  const normalized = {
    userId: ticket.userId,
    ...(actorEmail ? { actorEmail } : {}),
    instanceHost: ticket.instanceHost,
    nonce: ticket.nonce,
    ...(ticket.expectedSnSysId?.trim() ? { expectedSnSysId: ticket.expectedSnSysId.trim() } : {}),
    exp: ticket.exp,
  } satisfies ReauthTicket;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv as BufferSource, additionalData: enc.encode(TICKET_CONTEXT) as BufferSource },
      await ticketKey(secret),
      enc.encode(JSON.stringify(normalized)) as BufferSource,
    ),
  );
  return `${TICKET_VERSION}.${bytesToBase64Url(iv)}.${bytesToBase64Url(ciphertext)}`;
}

/**
 * Verify a ticket string against the host secret + expiry. Returns the ticket on success, or
 * null on ANY failure (malformed, tampered, wrong secret, expired) — the caller fails closed. `now` is
 * injected for testability.
 */
export async function verifyTicket(token: string, secret: string, now: number): Promise<ReauthTicket | null> {
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== TICKET_VERSION) return null;
  let ticket: ReauthTicket;
  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: base64UrlToBytes(parts[1]!) as BufferSource,
        additionalData: enc.encode(TICKET_CONTEXT) as BufferSource,
      },
      await ticketKey(secret),
      base64UrlToBytes(parts[2]!) as BufferSource,
    );
    ticket = JSON.parse(dec.decode(plaintext)) as ReauthTicket;
  } catch {
    return null;
  }
  if (typeof ticket.exp !== "number" || now > ticket.exp) return null;
  if (
    typeof ticket.userId !== "string" ||
    typeof ticket.instanceHost !== "string" ||
    typeof ticket.nonce !== "string"
  ) return null;
  if (!ticket.userId || !ticket.instanceHost || !ticket.nonce) return null;
  if (ticket.actorEmail !== undefined && (typeof ticket.actorEmail !== "string" || !normalizeIdentityEmail(ticket.actorEmail))) return null;
  if (ticket.expectedSnSysId !== undefined && (typeof ticket.expectedSnSysId !== "string" || ticket.expectedSnSysId.trim() === "")) return null;
  return ticket;
}
