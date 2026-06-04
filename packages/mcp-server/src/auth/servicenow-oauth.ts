// ServiceNow OAuth token grant/refresh (plan §2.8, §7.5). Proven live (B9). The Worker
// holds a confidential ServiceNow OAuth client; it exchanges credentials for ServiceNow
// access+refresh tokens, which are stored encrypted per user in TokenStoreDO (§2.7).
// `getServiceNowBearer` mints on first use, refreshes when expired, and persists rotations.

import type { SnTokens, TokenStore } from "./token-store.js";
import { McpToolError } from "../sn/errors.js";
import { bytesToBase64Url } from "./encoding.js";
import { utf8Len } from "../sandbox/serialize.js";
import type { ServiceNowRequestBudget } from "../sn/run-budget.js";

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
  httpTimeoutMs?: number;
}

/** Re-resolve ServiceNow sys_id/roles periodically so cached schema and signed actors do not
 *  trust role/principal metadata indefinitely after OAuth callback. */
export const SN_PRINCIPAL_TTL_MS = 5 * 60 * 1000;
export const DEFAULT_SN_OAUTH_HTTP_TIMEOUT_MS = 30_000;

interface TokenResponse {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  error?: string;
  error_description?: string;
}

function snOAuthHttpTimeoutMs(cfg: SnOAuthConfig): number {
  return Number.isInteger(cfg.httpTimeoutMs) && cfg.httpTimeoutMs! > 0
    ? cfg.httpTimeoutMs!
    : DEFAULT_SN_OAUTH_HTTP_TIMEOUT_MS;
}

async function fetchWithTimeout(cfg: SnOAuthConfig, input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error("servicenow_oauth_timeout")), snOAuthHttpTimeoutMs(cfg));
  const upstreamSignal = init.signal;
  const abort = () => controller.abort(upstreamSignal?.reason ?? new Error("servicenow_oauth_aborted"));
  if (upstreamSignal) {
    if (upstreamSignal.aborted) abort();
    else upstreamSignal.addEventListener("abort", abort, { once: true });
  }
  try {
    return await (cfg.fetchImpl ?? fetch)(input, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
    upstreamSignal?.removeEventListener("abort", abort);
  }
}

function accountHostServiceNowFetch(budget: ServiceNowRequestBudget | undefined, outboundBytes = 0): void {
  if (!budget) return;
  if (outboundBytes > 0) budget.countOutboundBytes(outboundBytes);
  budget.countServiceNowRequest();
}

async function tokenRequest(
  cfg: SnOAuthConfig,
  params: Record<string, string>,
  now: number,
  budget?: ServiceNowRequestBudget,
): Promise<SnTokens> {
  // cfg.instanceHost is the canonical, allowlisted host (canonicalized once in buildHandlers,
  // §6a), so this POST can never send the client secret off-allowlist.
  const body = new URLSearchParams({ client_id: cfg.clientId, client_secret: cfg.clientSecret, ...params }).toString();
  accountHostServiceNowFetch(budget, utf8Len(body));
  const res = await fetchWithTimeout(cfg, `https://${cfg.instanceHost}/oauth_token.do`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body,
    redirect: "manual",
  });
  if (res.status >= 300 && res.status < 400) {
    throw new Error(`servicenow_oauth_failed: refusing to follow ${res.status} redirect from oauth_token.do`);
  }
  const j = (await res.json().catch(() => ({}))) as TokenResponse;
  if (!j.access_token) throw new Error(`servicenow_oauth_failed: ${j.error ?? res.status} ${j.error_description ?? ""}`.trim());
  const tokens: SnTokens = { access_token: j.access_token };
  if (j.refresh_token) tokens.refresh_token = j.refresh_token;
  if (j.expires_in) tokens.expires_at = now + (j.expires_in - 60) * 1000; // refresh 60s early
  return tokens;
}

/** ROPC grant (grant_type=password) — MFA-exempt dev/CI path, integration_user ONLY (§2.8). */
export function ropcGrant(cfg: SnOAuthConfig, now: number, budget?: ServiceNowRequestBudget): Promise<SnTokens> {
  if (!cfg.ropcUsername || !cfg.ropcPassword) {
    throw reauthRequired("ServiceNow ROPC is disabled or not configured.");
  }
  return tokenRequest(cfg, { grant_type: "password", username: cfg.ropcUsername ?? "", password: cfg.ropcPassword ?? "" }, now, budget);
}

/** Refresh grant. NOTE (B9 finding): this client type does NOT rotate the refresh token. */
export function refreshGrant(cfg: SnOAuthConfig, refreshToken: string, now: number, budget?: ServiceNowRequestBudget): Promise<SnTokens> {
  return tokenRequest(cfg, { grant_type: "refresh_token", refresh_token: refreshToken }, now, budget);
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
  budget?: ServiceNowRequestBudget,
): Promise<SnTokens> {
  return tokenRequest(
    cfg,
    { grant_type: "authorization_code", code, code_verifier: pkceVerifier, redirect_uri: redirectUri },
    now,
    budget,
  );
}

const enc = new TextEncoder();

/** Generate a PKCE verifier (high-entropy) + its S256 challenge (§6b). */
export async function generatePkce(): Promise<{ verifier: string; challenge: string }> {
  const verifier = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(verifier) as BufferSource));
  return { verifier, challenge: bytesToBase64Url(digest) };
}

/** The ServiceNow principal (sys_id + roles) for the authenticated user (§6b). */
export interface SnPrincipal {
  sys_id: string;
  roles: string[];
  user_name?: string;
  email?: string;
}

function hasFreshPrincipal(tokens: SnTokens | null, now: number): tokens is SnTokens & { sys_id: string } {
  return Boolean(
    tokens?.sys_id &&
      tokens.principal_resolved_at !== undefined &&
      tokens.principal_resolved_at <= now &&
      now - tokens.principal_resolved_at <= SN_PRINCIPAL_TTL_MS,
  );
}

function stampPrincipal(tokens: SnTokens, principal: SnPrincipal, now: number): void {
  tokens.sys_id = principal.sys_id;
  tokens.roles = principal.roles;
  copyPrincipalIdentity(tokens, principal);
  tokens.principal_resolved_at = now;
}

function stringClaim(record: Record<string, unknown> | undefined, keys: string[]): string | undefined {
  for (const key of keys) {
    const value = record?.[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return undefined;
}

function copyPrincipalIdentity(target: Pick<SnTokens, "user_name" | "email">, source: Pick<SnPrincipal, "user_name" | "email">): void {
  if (source.user_name) target.user_name = source.user_name;
  if (source.email) target.email = source.email;
}

function buildPrincipal(sys_id: string, roles: string[], identity: Pick<SnPrincipal, "user_name" | "email"> = {}): SnPrincipal {
  return {
    sys_id,
    roles,
    ...(identity.user_name ? { user_name: identity.user_name } : {}),
    ...(identity.email ? { email: identity.email } : {}),
  };
}

function carryForwardPrincipal(target: SnTokens, source: SnTokens): void {
  if (source.sys_id) target.sys_id = source.sys_id;
  if (source.roles) target.roles = source.roles;
  copyPrincipalIdentity(target, source);
  if (source.principal_resolved_at !== undefined) target.principal_resolved_at = source.principal_resolved_at;
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
export async function resolveSnPrincipal(
  cfg: SnOAuthConfig,
  accessToken: string,
  opts: { budget?: ServiceNowRequestBudget } = {},
): Promise<SnPrincipal | null> {
  const auth = { authorization: `Bearer ${accessToken}`, accept: "application/json" };
  try {
    accountHostServiceNowFetch(opts.budget);
    const meRes = await fetchWithTimeout(
      cfg,
      `https://${cfg.instanceHost}/api/now/ui/user/current_user`,
      { headers: auth, redirect: "manual" },
    );
    if (meRes.status >= 300 && meRes.status < 400) return null;
    const me = (await meRes.json().catch(() => ({}))) as { result?: Record<string, unknown> };
    const sys_id = stringClaim(me.result, ["user_sys_id", "sys_id"]);
    if (!sys_id) return null;
    const user_name = stringClaim(me.result, ["user_name"]);
    const email = stringClaim(me.result, ["email", "user_email"]);
    const rolesQuery = `sysparm_query=user=${encodeURIComponent(sys_id)}&sysparm_fields=role.name&sysparm_limit=200`;
    accountHostServiceNowFetch(opts.budget, utf8Len(rolesQuery));
    const roleRes = await fetchWithTimeout(
      cfg,
      `https://${cfg.instanceHost}/api/now/table/sys_user_has_role?${rolesQuery}`,
      { headers: auth, redirect: "manual" },
    );
    if (roleRes.status >= 300 && roleRes.status < 400) return buildPrincipal(sys_id, [], { user_name, email });
    const rolesJson = (await roleRes.json().catch(() => ({}))) as { result?: Record<string, unknown>[] };
    const roles = (rolesJson.result ?? [])
      .map((r) => String(r["role.name"] ?? ""))
      .filter(Boolean);
    return buildPrincipal(sys_id, roles, { user_name, email });
  } catch {
    return null; // principal resolution is best-effort; token is still usable.
  }
}

/**
 * Return the stored per-user principal only while it is fresh; otherwise resolve it live with a
 * current bearer and merge the sys_id/roles onto the latest stored token bundle. A failed live
 * resolution returns null so callers can fail closed or bypass ACL-sensitive caches.
 */
export async function resolveStoredSnPrincipal(
  cfg: SnOAuthConfig,
  store: TokenStore,
  now: number,
  opts: { accessToken?: string; authorizeUrl?: string; budget?: ServiceNowRequestBudget } = {},
): Promise<SnPrincipal | null> {
  const existing = await store.get("servicenow").catch(() => null);
  if (hasFreshPrincipal(existing, now)) {
    return buildPrincipal(existing.sys_id, existing.roles ?? [], existing);
  }

  const accessToken = opts.accessToken ?? await getServiceNowBearer(cfg, store, now, "per_user_oauth", opts.authorizeUrl, opts.budget);
  const principal = await resolveSnPrincipal(cfg, accessToken, { budget: opts.budget });
  if (!principal) return null;

  // Re-read before persisting so a concurrent refresh cannot be clobbered by stale token data.
  const latest = await store.get("servicenow").catch(() => null);
  if (latest) {
    stampPrincipal(latest, principal, now);
    await store.rotate("servicenow", latest);
  }
  return principal;
}

/** Return only a still-fresh stored principal. Never refreshes tokens or calls ServiceNow. */
export async function resolveFreshStoredSnPrincipal(store: TokenStore, now: number): Promise<SnPrincipal | null> {
  const existing = await store.get("servicenow").catch(() => null);
  return hasFreshPrincipal(existing, now) ? buildPrincipal(existing.sys_id, existing.roles ?? [], existing) : null;
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
 *  - `integration_user`: reuse → refresh → ROPC mint (shared credential, no per-user
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
  mode: CredentialMode,
  authorizeUrl?: string,
  budget?: ServiceNowRequestBudget,
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
      const refreshed = await refreshGrant(cfg, existing.refresh_token, now, budget);
      // Carry forward the refresh token if the server didn't return a new one (B9), and the
      // resolved principal (sys_id/roles) so a refresh never drops the effective user.
      if (!refreshed.refresh_token && existing.refresh_token) refreshed.refresh_token = existing.refresh_token;
      carryForwardPrincipal(refreshed, existing);
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
  const minted = await ropcGrant(cfg, now, budget);
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
