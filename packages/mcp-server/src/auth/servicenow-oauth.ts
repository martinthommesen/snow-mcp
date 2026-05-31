// ServiceNow OAuth token grant/refresh (plan §2.8, §7.5). Proven live (B9). The Worker
// holds a confidential ServiceNow OAuth client; it exchanges credentials for ServiceNow
// access+refresh tokens, which are stored encrypted per user in TokenStoreDO (§2.7).
// `getServiceNowBearer` mints on first use, refreshes when expired, and persists rotations.

import type { SnTokens, TokenStore } from "./token-store.js";
import { McpToolError } from "../sn/errors.js";

/** Which ServiceNow credential model the bearer is sourced from (P3 corrupt/missing branch). */
export type CredentialMode = "per_user_oauth" | "integration_user";

export interface SnOAuthConfig {
  instanceHost: string;
  clientId: string;
  clientSecret: string;
  /** ROPC (dev/CI, MFA-exempt) creds. Production uses Authorization Code + PKCE upstream. */
  ropcUsername?: string;
  ropcPassword?: string;
  fetchImpl?: typeof fetch;
}

interface TokenResponse {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  error?: string;
  error_description?: string;
}

async function tokenRequest(cfg: SnOAuthConfig, params: Record<string, string>, now: number): Promise<SnTokens> {
  const fetchImpl = cfg.fetchImpl ?? fetch;
  // cfg.instanceHost is the canonical, allowlisted host (canonicalized once in buildHandlers,
  // §6a), so this POST can never send the client secret off-allowlist.
  const res = await fetchImpl(`https://${cfg.instanceHost}/oauth_token.do`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams({ client_id: cfg.clientId, client_secret: cfg.clientSecret, ...params }).toString(),
  });
  const j = (await res.json().catch(() => ({}))) as TokenResponse;
  if (!j.access_token) throw new Error(`servicenow_oauth_failed: ${j.error ?? res.status} ${j.error_description ?? ""}`.trim());
  const tokens: SnTokens = { access_token: j.access_token };
  if (j.refresh_token) tokens.refresh_token = j.refresh_token;
  if (j.expires_in) tokens.expires_at = now + (j.expires_in - 60) * 1000; // refresh 60s early
  return tokens;
}

/** ROPC grant (grant_type=password) — MFA-exempt dev/CI path, integration_user ONLY (§2.8). */
export function ropcGrant(cfg: SnOAuthConfig, now: number): Promise<SnTokens> {
  return tokenRequest(cfg, { grant_type: "password", username: cfg.ropcUsername ?? "", password: cfg.ropcPassword ?? "" }, now);
}

/** Refresh grant. NOTE (B9 finding): this client type does NOT rotate the refresh token. */
export function refreshGrant(cfg: SnOAuthConfig, refreshToken: string, now: number): Promise<SnTokens> {
  return tokenRequest(cfg, { grant_type: "refresh_token", refresh_token: refreshToken }, now);
}

/**
 * Authorization-Code + PKCE exchange (§6b) — the per-user OAuth path. Exchanges the upstream
 * `code` (from /servicenow/callback) for ServiceNow tokens, presenting the stored PKCE verifier
 * + the exact `redirect_uri` used at /authorize. cfg.instanceHost is canonical/allowlisted.
 */
export function authorizationCodeGrant(
  cfg: SnOAuthConfig,
  code: string,
  pkceVerifier: string,
  redirectUri: string,
  now: number,
): Promise<SnTokens> {
  return tokenRequest(
    cfg,
    { grant_type: "authorization_code", code, code_verifier: pkceVerifier, redirect_uri: redirectUri },
    now,
  );
}

const enc = new TextEncoder();

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Generate a PKCE verifier (high-entropy) + its S256 challenge (§6b). */
export async function generatePkce(): Promise<{ verifier: string; challenge: string }> {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(verifier) as BufferSource));
  return { verifier, challenge: b64url(digest) };
}

/** The ServiceNow principal (sys_id + roles) for the authenticated user (§6b). */
export interface SnPrincipal {
  sys_id: string;
  roles: string[];
}

/**
 * Resolve the SN principal for a freshly-minted bearer: the current user's sys_id + roles.
 * Best-effort — on any failure the caller persists the token WITHOUT a principal (admin_script
 * then falls back to the empty effective sys_id, never blocking a read/write). `fetchImpl`/
 * `instanceHost` come from cfg.
 *
 * "Who am I" is resolved via `GET /api/now/ui/user/current_user`, which returns
 * `{result:{user_sys_id, user_name, ...}}` for the AUTHENTICATED bearer — it is scoped to the
 * caller by the session/token and cannot depend on table order. We deliberately do NOT use an
 * unfiltered `sys_user?sysparm_limit=1` query: ServiceNow applies sysparm_limit BEFORE ACL
 * evaluation and returns rows in TABLE ORDER, so limit=1 yields the first table row (commonly
 * admin/guest/system), NOT the authenticated user.
 *
 * P8: confirm `/api/now/ui/user/current_user` is reachable under the registered SN OAuth app's
 * granted scope on the live PDI (and that `result.user_sys_id` is the field name). Unit tests
 * mock this boundary and cannot prove the live endpoint shape.
 */
export async function resolveSnPrincipal(cfg: SnOAuthConfig, accessToken: string): Promise<SnPrincipal | null> {
  const fetchImpl = cfg.fetchImpl ?? fetch;
  const auth = { authorization: `Bearer ${accessToken}`, accept: "application/json" };
  try {
    const meRes = await fetchImpl(
      `https://${cfg.instanceHost}/api/now/ui/user/current_user`,
      { headers: auth },
    );
    const me = (await meRes.json().catch(() => ({}))) as { result?: { user_sys_id?: string } };
    const sys_id = me.result?.user_sys_id;
    if (!sys_id) return null;
    const roleRes = await fetchImpl(
      `https://${cfg.instanceHost}/api/now/table/sys_user_has_role?sysparm_query=user=${encodeURIComponent(sys_id)}&sysparm_fields=role.name&sysparm_limit=200`,
      { headers: auth },
    );
    const rolesJson = (await roleRes.json().catch(() => ({}))) as { result?: Record<string, unknown>[] };
    const roles = (rolesJson.result ?? [])
      .map((r) => String(r["role.name"] ?? ""))
      .filter(Boolean);
    return { sys_id, roles };
  } catch {
    return null; // principal resolution is best-effort; token is still usable.
  }
}

/** Raise `reauth_required`, attaching the host-HMAC ticket URL (P2 detail channel) when one
 *  is available so run_code / the discovery tools can surface a click-through reauth link. */
function reauthRequired(message: string, authorizeUrl?: string): McpToolError {
  return new McpToolError("reauth_required", message, authorizeUrl ? { authorizeUrl } : undefined);
}

/**
 * Return a valid ServiceNow Bearer access token for `store`'s (user, instance): reuse the
 * stored token, refresh it if expired (persisting the rotation, carrying the principal forward),
 * or — for `integration_user` only — mint via ROPC if none.
 *
 * Mode-split (§6b):
 *  - `integration_user` (default): reuse → refresh → ROPC mint (shared credential, no per-user
 *    principal). An undecryptable token is re-minted via ROPC (P3 fail-closed, no throw).
 *  - `per_user_oauth`: reuse → refresh → else `reauth_required` (NEVER ROPC). A missing,
 *    expired-unrefreshable, or undecryptable token raises `reauth_required` carrying
 *    `authorizeUrl` (the host-HMAC ticket URL). This closes the unconditional missing-token
 *    ROPC fall-through P3 left in place.
 */
export async function getServiceNowBearer(
  cfg: SnOAuthConfig,
  store: TokenStore,
  now: number,
  mode: CredentialMode = "integration_user",
  authorizeUrl?: string,
): Promise<string> {
  // Fail-closed: an undecryptable stored token (e.g. after a botched KEK rotation) must not
  // propagate past recovery. Treat a decrypt failure as "no usable token".
  let existing: SnTokens | null;
  try {
    existing = await store.get("servicenow");
  } catch (e) {
    // Observability (P3 review): the catch covers EVERY store.get() failure, not only a
    // botched-rotation decrypt — open() raises an AAD mismatch FIRST (crypto.ts), which is
    // the tamper / cross-user-misroute signal. integration_user recovery re-mints and
    // overwrites, so without this line that signal would vanish silently. The message
    // carries only GCM/AAD error text — no token plaintext or key material.
    console.error("getServiceNowBearer: stored token unreadable, recovering per mode:", e instanceof Error ? e.message : String(e));
    if (mode === "per_user_oauth") {
      throw reauthRequired("ServiceNow token could not be decrypted — re-authenticate.", authorizeUrl);
    }
    existing = null; // integration_user: fall through to a fresh ROPC mint.
  }
  if (existing && (existing.expires_at === undefined || existing.expires_at > now)) {
    return existing.access_token;
  }
  if (existing?.refresh_token) {
    try {
      const refreshed = await refreshGrant(cfg, existing.refresh_token, now);
      // Carry forward the refresh token if the server didn't return a new one (B9), and the
      // resolved principal (sys_id/roles) so a refresh never drops the effective user.
      if (!refreshed.refresh_token && existing.refresh_token) refreshed.refresh_token = existing.refresh_token;
      if (existing.sys_id) refreshed.sys_id = existing.sys_id;
      if (existing.roles) refreshed.roles = existing.roles;
      await store.rotate("servicenow", refreshed);
      return refreshed.access_token;
    } catch {
      /* refresh failed — fall through (integration_user re-mints; per_user reauths) */
    }
  }
  // No usable token. per_user_oauth NEVER mints via ROPC (no shared credential exists for a
  // real human) — it must complete the Authorization-Code flow at /servicenow/authorize.
  if (mode === "per_user_oauth") {
    throw reauthRequired("No ServiceNow token for this user — re-authenticate.", authorizeUrl);
  }
  const minted = await ropcGrant(cfg, now);
  await store.put("servicenow", minted);
  return minted.access_token;
}

/**
 * Pre-sandbox reauth check (§6b): is a usable per-user token present WITHOUT minting? Called
 * before run_code creates the (billable) executor. In `per_user_oauth` a missing/corrupt token
 * short-circuits with host-attested `reauth_required` (+authorizeUrl) BEFORE any Worker spins.
 * A present-but-expired token is allowed through: the refresh happens at use time, and the P2
 * mid-run host signal covers a refresh that fails during the run. In `integration_user` there
 * is nothing to preflight (ROPC mints on demand) — this is a no-op.
 */
export async function preflightAuth(
  store: TokenStore,
  mode: CredentialMode,
  authorizeUrl?: string,
): Promise<void> {
  if (mode !== "per_user_oauth") return;
  let existing: SnTokens | null;
  try {
    existing = await store.get("servicenow");
  } catch {
    throw reauthRequired("ServiceNow token could not be decrypted — re-authenticate.", authorizeUrl);
  }
  // No token at all, or expired with no refresh token to redeem → reauth before the sandbox.
  if (!existing) {
    throw reauthRequired("No ServiceNow token for this user — re-authenticate.", authorizeUrl);
  }
  const expired = existing.expires_at !== undefined && existing.expires_at <= Date.now();
  if (expired && !existing.refresh_token) {
    throw reauthRequired("ServiceNow token expired — re-authenticate.", authorizeUrl);
  }
}
