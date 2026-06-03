// Host-HMAC reauth ticket (plan §6b) — the identity bridge from an authenticated /mcp
// request to the UNauthenticated /servicenow/authorize route (which has no ctx.props).
//
// Inside /mcp, where ctx.props.userId EXISTS, the host mints a ticket {userId, actorEmail?,
// instanceHost, nonce, exp} signed with a HOST secret (OAUTH_PROVIDER_SECRET, domain-separated).
// This ticket string is the `authorizeUrl` the reauth_required carries (P2 detail channel). At
// /servicenow/authorize the host VERIFIES this signature + exp — it is the route's ONLY identity
// authority; nothing client-supplied at that route is trusted.
//
// Reuses the HMAC-SHA256 primitive from auth/actor.ts. The secret is derived to 32 raw bytes
// via SHA-256 (auth/crypto.ts deriveKeyBytes), so any passphrase works as the HMAC key.

import { hmacSha256Base64 } from "./actor.js";
import { deriveKeyBytes } from "./crypto.js";
import { base64UrlToString, bytesToBase64Url, constantTimeEqualAscii } from "./encoding.js";

/** Domain-separation prefix so this signature can never be confused with another use of the
 *  same host secret (e.g. Alchemy state, OAuthProvider internals). */
const TICKET_CONTEXT = "sn-oauth-reauth-ticket\n";

export interface ReauthTicket {
  userId: string;
  actorEmail?: string;
  instanceHost: string;
  nonce: string;
  expectedSnSysId?: string;
  exp: number; // epoch ms
}

const enc = new TextEncoder();

export function normalizeIdentityEmail(value: unknown): string {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

/** The canonical bytes that get HMAC'd: a domain prefix + the base64url JSON payload. */
function canonical(payloadB64Url: string): string {
  return TICKET_CONTEXT + payloadB64Url;
}

/**
 * Mint a signed ticket string `<payload>.<sig>` (both base64url). `secret` is the host
 * OAUTH_PROVIDER_SECRET. Returns the opaque token only — the caller builds the full
 * `${origin}/servicenow/authorize?ticket=…` URL.
 */
export async function mintTicket(ticket: ReauthTicket, secret: string): Promise<string> {
  const keyBytes = await deriveKeyBytes(secret);
  const actorEmail = normalizeIdentityEmail(ticket.actorEmail);
  const normalized = {
    userId: ticket.userId,
    ...(actorEmail ? { actorEmail } : {}),
    instanceHost: ticket.instanceHost,
    nonce: ticket.nonce,
    ...(ticket.expectedSnSysId?.trim() ? { expectedSnSysId: ticket.expectedSnSysId.trim() } : {}),
    exp: ticket.exp,
  } satisfies ReauthTicket;
  const payloadB64Url = bytesToBase64Url(enc.encode(JSON.stringify(normalized)));
  const sig = await hmacSha256Base64(canonical(payloadB64Url), keyBytes);
  return `${payloadB64Url}.${bytesToBase64Url(enc.encode(sig))}`;
}

/**
 * Verify a ticket string against the host secret + expiry. Returns the ticket on success, or
 * null on ANY failure (malformed, bad signature, expired) — the caller fails closed. `now` is
 * injected for testability.
 */
export async function verifyTicket(token: string, secret: string, now: number): Promise<ReauthTicket | null> {
  const dot = token.indexOf(".");
  if (dot <= 0) return null;
  const payloadB64Url = token.slice(0, dot);
  const sigPart = token.slice(dot + 1);
  const keyBytes = await deriveKeyBytes(secret);
  const expectedSig = await hmacSha256Base64(canonical(payloadB64Url), keyBytes);
  let presentedSig: string;
  try {
    presentedSig = base64UrlToString(sigPart);
  } catch {
    return null;
  }
  // Constant-time-ish compare of the base64 signatures.
  if (!constantTimeEqualAscii(presentedSig, expectedSig)) return null;
  let ticket: ReauthTicket;
  try {
    ticket = JSON.parse(base64UrlToString(payloadB64Url)) as ReauthTicket;
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
