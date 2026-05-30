// ServiceNow OAuth token grant/refresh (plan §2.8, §7.5). Proven live (B9). The Worker
// holds a confidential ServiceNow OAuth client; it exchanges credentials for ServiceNow
// access+refresh tokens, which are stored encrypted per user in TokenStoreDO (§2.7).
// `getServiceNowBearer` mints on first use, refreshes when expired, and persists rotations.

import type { SnTokens, TokenStore } from "./token-store.js";

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

/** ROPC grant (grant_type=password) — MFA-exempt dev/CI path (§2.8). */
export function ropcGrant(cfg: SnOAuthConfig, now: number): Promise<SnTokens> {
  return tokenRequest(cfg, { grant_type: "password", username: cfg.ropcUsername ?? "", password: cfg.ropcPassword ?? "" }, now);
}

/** Refresh grant. NOTE (B9 finding): this client type does NOT rotate the refresh token. */
export function refreshGrant(cfg: SnOAuthConfig, refreshToken: string, now: number): Promise<SnTokens> {
  return tokenRequest(cfg, { grant_type: "refresh_token", refresh_token: refreshToken }, now);
}

/**
 * Return a valid ServiceNow Bearer access token for `store`'s (user, instance): reuse the
 * stored token, refresh it if expired (persisting the rotation), or mint via ROPC if none.
 */
export async function getServiceNowBearer(cfg: SnOAuthConfig, store: TokenStore, now: number): Promise<string> {
  const existing = await store.get("servicenow");
  if (existing && (existing.expires_at === undefined || existing.expires_at > now)) {
    return existing.access_token;
  }
  if (existing?.refresh_token) {
    try {
      const refreshed = await refreshGrant(cfg, existing.refresh_token, now);
      // Carry forward the refresh token if the server didn't return a new one (B9).
      if (!refreshed.refresh_token && existing.refresh_token) refreshed.refresh_token = existing.refresh_token;
      await store.rotate("servicenow", refreshed);
      return refreshed.access_token;
    } catch {
      /* fall through to a fresh grant */
    }
  }
  const minted = await ropcGrant(cfg, now);
  await store.put("servicenow", minted);
  return minted.access_token;
}
