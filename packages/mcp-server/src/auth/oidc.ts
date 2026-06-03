import { OAuthError } from "@cloudflare/workers-oauth-provider";
import {
  createRemoteJWKSet,
  customFetch,
  jwtVerify,
  type JWTPayload,
} from "jose";
import { isValidMode, modeRisk, type Mode } from "@servicenow-codemode/shared";
import { generatePkce } from "./servicenow-oauth.js";
import { canonicalPublicOrigin } from "./public-origin.js";
import { maxModeFromScopes } from "./mcp-scopes.js";
import { minByRisk } from "../authz/effective-mode.js";

export type AuthMode = "operator_secret" | "oidc";

export interface OidcEnv {
  AUTH_MODE?: string;
  WORKER_PUBLIC_ORIGIN?: string;
  OIDC_ISSUER?: string;
  OIDC_CLIENT_ID?: string;
  OIDC_CLIENT_SECRET?: string;
  OIDC_SCOPES?: string;
  OIDC_GROUP_CLAIM?: string;
  OIDC_GROUP_POLICY_MAP?: string;
  OIDC_DEFAULT_POLICY_NAME?: string;
  OIDC_HTTP_TIMEOUT_MS?: string;
  fetchImpl?: typeof fetch;
}

export interface OidcDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  userinfo_endpoint?: string;
}

export interface OidcTokens {
  id_token?: string;
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  token_type?: string;
}

interface GroupPolicy {
  maxMode: Mode;
  policyName: string;
}

interface PropsResult {
  grantProps: Record<string, unknown>;
  accessTokenProps: Record<string, unknown>;
}

const DEFAULT_OIDC_SCOPES = "openid profile email offline_access";
const DEFAULT_GROUP_CLAIM = "groups";
const OIDC_STATE_TTL_MS = 10 * 60 * 1000;
const DEFAULT_OIDC_HTTP_TIMEOUT_MS = 10_000;
const discoveryCache = new WeakMap<OidcEnv, Map<string, Promise<OidcDiscovery>>>();
const jwksCache = new WeakMap<OidcEnv, Map<string, ReturnType<typeof createRemoteJWKSet>>>();

export function parseAuthMode(value: string | undefined): AuthMode {
  return value === "oidc" ? "oidc" : "operator_secret";
}

export function oidcEnabled(env: OidcEnv): boolean {
  return parseAuthMode(env.AUTH_MODE) === "oidc";
}

export function oidcRedirectUri(env: OidcEnv): string | undefined {
  const origin = canonicalPublicOrigin(env.WORKER_PUBLIC_ORIGIN);
  return origin ? `${origin}/oidc/callback` : undefined;
}

export function oidcStateTtlMs(): number {
  return OIDC_STATE_TTL_MS;
}

function fetchImpl(env: OidcEnv): typeof fetch {
  return env.fetchImpl ?? fetch;
}

function oidcHttpTimeoutMs(env: OidcEnv): number {
  const configured = Number(env.OIDC_HTTP_TIMEOUT_MS);
  return Number.isInteger(configured) && configured > 0 ? configured : DEFAULT_OIDC_HTTP_TIMEOUT_MS;
}

async function fetchWithTimeout(env: OidcEnv, input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort("oidc_timeout"), oidcHttpTimeoutMs(env));
  const upstreamSignal = init.signal;
  const abort = () => controller.abort(upstreamSignal?.reason);
  if (upstreamSignal) {
    if (upstreamSignal.aborted) abort();
    else upstreamSignal.addEventListener("abort", abort, { once: true });
  }
  try {
    return await fetchImpl(env)(input, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
    upstreamSignal?.removeEventListener("abort", abort);
  }
}

function requireText(name: string, value: string | undefined): string {
  const trimmed = value?.trim();
  if (!trimmed) throw new Error(`${name} is required for AUTH_MODE=oidc.`);
  return trimmed;
}

function requireHttpsUrl(name: string, value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be an HTTPS URL.`);
  }
  if (url.protocol !== "https:") throw new Error(`${name} must be an HTTPS URL.`);
  return url.toString().replace(/\/+$/, "");
}

export function assertOidcConfigured(env: OidcEnv): void {
  requireText("OIDC_ISSUER", env.OIDC_ISSUER);
  requireText("OIDC_CLIENT_ID", env.OIDC_CLIENT_ID);
  requireText("OIDC_CLIENT_SECRET", env.OIDC_CLIENT_SECRET);
  if (!oidcRedirectUri(env)) throw new Error("WORKER_PUBLIC_ORIGIN is required for AUTH_MODE=oidc.");
}

async function fetchJson<T>(env: OidcEnv, url: string, init?: RequestInit): Promise<T> {
  const res = await fetchWithTimeout(env, url, init);
  if (!res.ok) throw new Error(`OIDC HTTP ${res.status} from ${url}`);
  return (await res.json()) as T;
}

export async function discoverOidc(env: OidcEnv): Promise<OidcDiscovery> {
  assertOidcConfigured(env);
  const issuer = requireHttpsUrl("OIDC_ISSUER", requireText("OIDC_ISSUER", env.OIDC_ISSUER));
  let byIssuer = discoveryCache.get(env);
  if (!byIssuer) {
    byIssuer = new Map<string, Promise<OidcDiscovery>>();
    discoveryCache.set(env, byIssuer);
  }
  let cached = byIssuer.get(issuer);
  if (!cached) {
    cached = fetchJson<OidcDiscovery>(env, `${issuer}/.well-known/openid-configuration`)
      .then((discovery) => {
        if (discovery.issuer !== issuer) throw new Error("OIDC discovery issuer mismatch.");
        for (const key of ["authorization_endpoint", "token_endpoint", "jwks_uri"] as const) {
          if (!discovery[key]) throw new Error(`OIDC discovery missing ${key}.`);
          requireHttpsUrl(`OIDC discovery ${key}`, discovery[key]);
        }
        if (discovery.userinfo_endpoint) {
          requireHttpsUrl("OIDC discovery userinfo_endpoint", discovery.userinfo_endpoint);
        }
        return discovery;
      })
      .catch((e) => {
        byIssuer.delete(issuer);
        throw e;
      });
    byIssuer.set(issuer, cached);
  }
  const discovery = await cached;
  if (discovery.issuer !== issuer) throw new Error("OIDC discovery issuer mismatch.");
  return discovery;
}

export async function buildOidcAuthorize(env: OidcEnv, state: string, nonce: string): Promise<{ url: string; verifier: string }> {
  const discovery = await discoverOidc(env);
  const { verifier, challenge } = await generatePkce();
  const url = new URL(discovery.authorization_endpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", requireText("OIDC_CLIENT_ID", env.OIDC_CLIENT_ID));
  url.searchParams.set("redirect_uri", oidcRedirectUri(env)!);
  url.searchParams.set("scope", env.OIDC_SCOPES?.trim() || DEFAULT_OIDC_SCOPES);
  url.searchParams.set("state", state);
  url.searchParams.set("nonce", nonce);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  return { url: url.toString(), verifier };
}

async function exchangeToken(env: OidcEnv, body: URLSearchParams): Promise<OidcTokens> {
  const discovery = await discoverOidc(env);
  body.set("client_id", requireText("OIDC_CLIENT_ID", env.OIDC_CLIENT_ID));
  body.set("client_secret", requireText("OIDC_CLIENT_SECRET", env.OIDC_CLIENT_SECRET));
  const res = await fetchWithTimeout(env, discovery.token_endpoint, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: body.toString(),
  });
  const json = await res.json().catch(() => null) as OidcTokens | { error?: string; error_description?: string } | null;
  if (!res.ok) {
    const desc = json && "error_description" in json ? json.error_description : `OIDC token endpoint returned ${res.status}`;
    throw new OAuthError("invalid_grant", { description: desc ?? "OIDC token exchange failed" });
  }
  return json as OidcTokens;
}

export async function exchangeOidcCode(env: OidcEnv, code: string, pkceVerifier: string): Promise<OidcTokens> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: oidcRedirectUri(env)!,
    code_verifier: pkceVerifier,
  });
  return exchangeToken(env, body);
}

async function validateIdToken(env: OidcEnv, idToken: string, expectedNonce?: string): Promise<JWTPayload> {
  const discovery = await discoverOidc(env);
  let byUri = jwksCache.get(env);
  if (!byUri) {
    byUri = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
    jwksCache.set(env, byUri);
  }
  let jwks = byUri.get(discovery.jwks_uri);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(discovery.jwks_uri), {
      [customFetch]: (url, options) => fetchWithTimeout(env, url, options),
    });
    byUri.set(discovery.jwks_uri, jwks);
  }
  const { payload } = await jwtVerify(idToken, jwks, {
    issuer: discovery.issuer,
    audience: requireText("OIDC_CLIENT_ID", env.OIDC_CLIENT_ID),
    algorithms: ["RS256", "ES256"],
    clockTolerance: 60,
  });
  if (expectedNonce !== undefined && payload.nonce !== expectedNonce) {
    throw new OAuthError("invalid_grant", { description: "OIDC nonce mismatch" });
  }
  return payload;
}

function groupsFromClaims(env: OidcEnv, claims: JWTPayload): string[] {
  const claim = env.OIDC_GROUP_CLAIM?.trim() || DEFAULT_GROUP_CLAIM;
  const value = claims[claim];
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === "string" && v.trim() !== "");
  if (typeof value === "string" && value.trim()) return [value];
  return [];
}

function parseGroupPolicyMap(env: OidcEnv): Record<string, GroupPolicy> {
  const raw = env.OIDC_GROUP_POLICY_MAP?.trim();
  if (!raw) return Object.create(null) as Record<string, GroupPolicy>;
  const parsed = JSON.parse(raw) as Record<string, { maxMode?: unknown; policy?: unknown } | string>;
  const out = Object.create(null) as Record<string, GroupPolicy>;
  const defaultPolicyName = env.OIDC_DEFAULT_POLICY_NAME?.trim() || "default";
  for (const [group, entry] of Object.entries(parsed)) {
    if (typeof entry !== "string" && (!entry || typeof entry !== "object" || Array.isArray(entry))) {
      throw new Error(`OIDC_GROUP_POLICY_MAP.${group} must be a mode string or JSON object.`);
    }
    const maxMode = typeof entry === "string" ? entry : entry.maxMode;
    if (!isValidMode(maxMode)) throw new Error(`OIDC_GROUP_POLICY_MAP.${group}.maxMode must be read_only, write, or admin_script.`);
    const policyName = typeof entry === "string"
      ? defaultPolicyName
      : typeof entry.policy === "string" && entry.policy.trim()
        ? entry.policy.trim()
        : defaultPolicyName;
    out[group] = { maxMode, policyName };
  }
  return out;
}

function bestGroupPolicy(env: OidcEnv, groups: string[]): GroupPolicy {
  const map = parseGroupPolicyMap(env);
  let best: GroupPolicy | undefined;
  for (const group of groups) {
    if (!Object.prototype.hasOwnProperty.call(map, group)) continue;
    const entry = map[group];
    if (!entry || !isValidMode(entry.maxMode)) continue;
    if (!best || modeRisk(entry.maxMode) > modeRisk(best.maxMode)) {
      best = entry;
      continue;
    }
    if (modeRisk(entry.maxMode) === modeRisk(best.maxMode) && entry.policyName !== best.policyName) {
      throw new OAuthError("invalid_grant", {
        description: "OIDC group policy map is ambiguous for equally privileged groups; configure one policy per risk level.",
      });
    }
  }
  return best ?? { maxMode: "read_only", policyName: env.OIDC_DEFAULT_POLICY_NAME?.trim() || "default" };
}

function oidcProviderUserId(subject: string): string {
  return `oidc-${encodeURIComponent(subject)}`;
}

export function oidcPropsFromClaims(env: OidcEnv, claims: JWTPayload, grantedScopes: readonly string[], refreshToken?: string): PropsResult {
  const sub = typeof claims.sub === "string" && claims.sub.trim() ? claims.sub : "";
  if (!sub) throw new OAuthError("invalid_grant", { description: "OIDC ID token missing sub" });
  const groups = groupsFromClaims(env, claims);
  const groupPolicy = bestGroupPolicy(env, groups);
  const scopeMaxMode = maxModeFromScopes(grantedScopes);
  const maxMode = minByRisk(scopeMaxMode, groupPolicy.maxMode);
  const email = typeof claims.email === "string" && claims.email_verified === true ? claims.email : undefined;
  const grantProps: Record<string, unknown> = {
    userId: oidcProviderUserId(sub),
    oidcSubject: sub,
    scopes: [...grantedScopes],
    maxMode,
    actorPolicyName: groupPolicy.policyName,
    authMode: "oidc",
    oidcGroups: groups,
    ...(email ? { email } : {}),
    ...(refreshToken ? { oidcRefreshToken: refreshToken } : {}),
  };
  return { grantProps, accessTokenProps: stripOidcSecrets(grantProps) };
}

export function stripOidcSecrets(props: Record<string, unknown>): Record<string, unknown> {
  const { oidcRefreshToken: _refresh, ...safe } = props;
  return safe;
}

export function oidcAccessTokenProps(props: Record<string, unknown>, requestedScopes: readonly string[]): Record<string, unknown> {
  const grantMaxMode: Mode = isValidMode(props.maxMode) ? props.maxMode : "read_only";
  const requestedMaxMode = maxModeFromScopes(requestedScopes);
  return {
    ...stripOidcSecrets(props),
    scopes: [...requestedScopes],
    maxMode: minByRisk(grantMaxMode, requestedMaxMode),
  };
}

export function oidcAuthorizationCodeTokenResult(props: Record<string, unknown>, requestedScopes: readonly string[]): {
  accessTokenProps: Record<string, unknown>;
  refreshTokenTTL?: number;
} {
  const result: { accessTokenProps: Record<string, unknown>; refreshTokenTTL?: number } = {
    accessTokenProps: oidcAccessTokenProps(props, requestedScopes),
  };
  if (typeof props.oidcRefreshToken !== "string" || props.oidcRefreshToken.trim() === "") {
    result.refreshTokenTTL = 0;
  }
  return result;
}

export async function oidcPropsFromCode(env: OidcEnv, code: string, pkceVerifier: string, nonce: string, grantedScopes: readonly string[]): Promise<PropsResult> {
  const tokens = await exchangeOidcCode(env, code, pkceVerifier);
  if (!tokens.id_token) throw new OAuthError("invalid_grant", { description: "OIDC token response missing id_token" });
  const claims = await validateIdToken(env, tokens.id_token, nonce);
  return oidcPropsFromClaims(env, claims, grantedScopes, tokens.refresh_token);
}

export async function refreshOidcGrantProps(env: OidcEnv, props: Record<string, unknown>, grantedScopes: readonly string[]): Promise<PropsResult | undefined> {
  if (props.authMode !== "oidc") return undefined;
  const refreshToken = typeof props.oidcRefreshToken === "string" ? props.oidcRefreshToken : "";
  if (!refreshToken) throw new OAuthError("invalid_grant", { description: "OIDC grant has no refresh token" });
  const tokens = await exchangeToken(env, new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken }));
  if (!tokens.id_token) throw new OAuthError("invalid_grant", { description: "OIDC refresh returned no signed id_token" });
  const claims = await validateIdToken(env, tokens.id_token);
  if (claims.sub !== props.oidcSubject) throw new OAuthError("invalid_grant", { description: "OIDC refresh subject changed" });
  return oidcPropsFromClaims(env, claims, grantedScopes, tokens.refresh_token ?? refreshToken);
}
