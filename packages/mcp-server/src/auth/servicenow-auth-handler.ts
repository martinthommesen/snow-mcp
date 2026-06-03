// MCP-client OAuth consent handler (plan §2.4, §1.1). The OAuthProvider routes all
// non-/mcp requests here. We implement /authorize as a single-operator consent: the
// operator proves identity with a pre-shared secret (MCP_OPERATOR_SECRET), and the
// granted OAuth scopes (servicenow:read|write|admin_script) become props.maxMode, which
// the authorization cap (§2.0.1) enforces. /health is served here too.
//
// This secures the endpoint (no valid token -> the provider returns 401 on /mcp) and is
// scriptable for verification (the consent is a form POST, not a mandatory browser UI).

import { constantTimeEqualAscii } from "./encoding.js";
import { buildKekRing, open, seal, type TokenEnvelope } from "./crypto.js";
import { requireOAuthKv } from "./oauth-kv.js";
import { sourceIpRateLimited, type ConsentRateNamespace } from "./rate-limit.js";
import { grantScopes, maxModeFromScopes } from "./mcp-scopes.js";
import {
  buildOidcAuthorize,
  oidcEnabled,
  oidcPropsFromCode,
  oidcStateTtlMs,
  type OidcEnv,
} from "./oidc.js";
import type {
  OidcAuthRequestInfo as AuthRequestInfo,
  OidcConsentRecord,
  OidcCorrelationRecord,
} from "../do/auth-correlation.js";

interface OAuthHelpersLike {
  parseAuthRequest(request: Request): Promise<AuthRequestInfo>;
  lookupClient(clientId: string): Promise<{ clientName?: string } | null>;
  completeAuthorization(opts: {
    request: AuthRequestInfo;
    userId: string;
    metadata: unknown;
    scope: string[];
    props: unknown;
  }): Promise<{ redirectTo: string }>;
}

// Inherits the OIDC fields (AUTH_MODE, WORKER_PUBLIC_ORIGIN, OIDC_*, fetchImpl) from OidcEnv so
// the handler can be passed straight to the oidc.ts helpers without re-declaring them or casting.
interface HandlerEnv extends OidcEnv {
  OAUTH_PROVIDER: OAuthHelpersLike;
  AUTH_DO?: AuthCorrelationNamespace;
  MCP_OPERATOR_SECRET?: string;
  MCP_OPERATOR_USER_ID?: string;
  MCP_OPERATOR_EMAIL?: string;
  MCP_OPERATOR_ACCESS_GROUPS?: string;
  OAUTH_PROVIDER_SECRET?: string;
  OAUTH_KV?: KVNamespace;
  // Consent-write rate limiter (finding 4); missing binding fails closed.
  CONSENT_RATE_DO?: ConsentRateNamespace;
}

interface AuthCorrelationStub {
  createOidcRecord(state: string, record: OidcCorrelationRecord): Promise<void>;
  consumeOidcRecord(state: string): Promise<OidcCorrelationRecord | null>;
  createOidcConsentRecord(nonce: string, record: OidcConsentRecord): Promise<void>;
  consumeOidcConsentRecord(nonce: string): Promise<OidcConsentRecord | null>;
}

interface AuthCorrelationNamespace {
  idFromName(name: string): DurableObjectId;
  get(id: DurableObjectId): AuthCorrelationStub;
}

/** Server-side consent state lives in OAUTH_KV under this prefix, keyed by a server-minted
 *  nonce. Short TTL: a consent flow that isn't completed promptly is abandoned (plan §P6a). */
const CONSENT_KEY_PREFIX = "consent:";
const CONSENT_TTL_SECONDS = 600; // 10 minutes to complete the operator-secret consent.
const CONSENT_HTML_HEADERS = {
  "content-type": "text/html; charset=utf-8",
  "content-security-policy": "frame-ancestors 'none'",
  "x-frame-options": "DENY",
};

function unsupportedScopesResponse(): Response {
  return new Response("No supported ServiceNow OAuth scopes requested.", { status: 400 });
}

function requireS256Pkce(oauth: AuthRequestInfo): Response | undefined {
  if (oauth.codeChallengeMethod !== "S256" || !oauth.codeChallenge?.trim()) {
    return new Response("PKCE S256 code_challenge is required.", { status: 400 });
  }
  return undefined;
}

async function consentRateLimitResponse(request: Request, env: HandlerEnv): Promise<Response | undefined> {
  if (!(await sourceIpRateLimited(request, env.CONSENT_RATE_DO, "consent-rate"))) return undefined;
  return new Response("Too many authorization requests; try again shortly.", { status: 429 });
}

interface PreparedAuthorizationRequest {
  oauth: AuthRequestInfo;
  scope: string[];
  clientName: string;
}

async function prepareAuthorizationRequest(
  request: Request,
  env: HandlerEnv,
): Promise<PreparedAuthorizationRequest | Response> {
  const oauth = await env.OAUTH_PROVIDER.parseAuthRequest(request);
  const scope = grantScopes(oauth.scope);
  if (scope.length === 0) return unsupportedScopesResponse();
  const pkceDenied = requireS256Pkce(oauth);
  if (pkceDenied) return pkceDenied;

  // Admission cap (finding 4): reject unknown clients, then bound writes per SOURCE IP per
  // window before any consent state is minted. Key by IP, not client_id; dynamic client
  // registration makes client_id-keyed limits bypassable and unbounded in memory.
  const client = await env.OAUTH_PROVIDER.lookupClient(oauth.clientId);
  if (!client) return new Response("Unknown OAuth client.", { status: 400 });
  const limited = await consentRateLimitResponse(request, env);
  if (limited) return limited;

  return { oauth, scope, clientName: client.clientName ?? "" };
}

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

function requireOidcConsentSealSecret(env: HandlerEnv): string {
  const secret = env.OAUTH_PROVIDER_SECRET?.trim();
  if (!secret) throw new Error("OAUTH_PROVIDER_SECRET is required for OIDC consent sealing.");
  return secret;
}

function oidcConsentRefreshAad(userId: string, nonce: string): string {
  return `oidc-consent-refresh|${userId}|${nonce}`;
}

async function sealOidcGrantProps(
  env: HandlerEnv,
  userId: string,
  nonce: string,
  grantProps: Record<string, unknown>,
): Promise<{ grantProps: Record<string, unknown>; sealedOidcRefreshToken?: TokenEnvelope }> {
  const { oidcRefreshToken, ...safeGrantProps } = grantProps;
  if (typeof oidcRefreshToken !== "string" || !oidcRefreshToken.trim()) {
    return { grantProps: safeGrantProps };
  }
  const ring = await buildKekRing(requireOidcConsentSealSecret(env));
  return {
    grantProps: safeGrantProps,
    sealedOidcRefreshToken: await seal(oidcRefreshToken, oidcConsentRefreshAad(userId, nonce), ring),
  };
}

async function unsealOidcGrantProps(env: HandlerEnv, nonce: string, record: OidcConsentRecord): Promise<Record<string, unknown>> {
  if (!record.sealedOidcRefreshToken) return record.grantProps;
  const ring = await buildKekRing(requireOidcConsentSealSecret(env));
  const oidcRefreshToken = await open(record.sealedOidcRefreshToken, oidcConsentRefreshAad(record.userId, nonce), ring);
  return { ...record.grantProps, oidcRefreshToken };
}

/** Render the consent page. The hidden field carries ONLY the server-minted `nonce` — the
 *  authoritative auth-request (scope/redirect/state) lives in OAUTH_KV under that nonce and
 *  is never round-tripped through the client (plan §P6a, finding 22). `oauth` is read from
 *  server state purely to DISPLAY the scopes being granted. */
function consentPage(oauth: AuthRequestInfo, clientName: string, nonce: string, error?: string): Response {
  const scopes = grantScopes(oauth.scope);
  const html = `<!doctype html><meta charset="utf-8"><title>Authorize MCP client</title>
<style>body{font:15px system-ui;max-width:34rem;margin:3rem auto;padding:0 1rem}
.s{background:#f4f4f5;border-radius:6px;padding:.5rem .75rem;margin:.25rem 0;font-family:monospace}
button{font:inherit;padding:.6rem 1rem;border:0;border-radius:6px;background:#2563eb;color:#fff;cursor:pointer}
.err{color:#b91c1c}</style>
<h2>Authorize MCP client</h2>
<p><b>${esc(clientName || oauth.clientId)}</b> is requesting access to the ServiceNow Code Mode MCP server.</p>
<p>Scopes to grant:</p>
${scopes.map((s) => `<div class="s">${esc(s)}</div>`).join("")}
${error ? `<p class="err">${esc(error)}</p>` : ""}
<form method="POST" action="/authorize">
  <input type="hidden" name="consent" value="${esc(nonce)}">
  <p><label>Operator secret<br><input type="password" name="operator_secret" autocomplete="off" style="width:100%;padding:.5rem"></label></p>
  <button type="submit">Approve</button>
</form>`;
  return new Response(html, { status: error ? 401 : 200, headers: CONSENT_HTML_HEADERS });
}

function oidcConsentPage(record: OidcConsentRecord, nonce: string): Response {
  const subject =
    typeof record.grantProps.email === "string" && record.grantProps.email.trim()
      ? record.grantProps.email.trim()
      : record.userId;
  const html = `<!doctype html><meta charset="utf-8"><title>Authorize MCP client</title>
<style>body{font:15px system-ui;max-width:34rem;margin:3rem auto;padding:0 1rem}
.s{background:#f4f4f5;border-radius:6px;padding:.5rem .75rem;margin:.25rem 0;font-family:monospace}
button{font:inherit;padding:.6rem 1rem;border:0;border-radius:6px;background:#2563eb;color:#fff;cursor:pointer}</style>
<h2>Authorize MCP client</h2>
<p><b>${esc(record.clientName || record.authRequest.clientId)}</b> is requesting access to the ServiceNow Code Mode MCP server as <b>${esc(subject)}</b>.</p>
<p>Scopes to grant:</p>
${record.grantedScopes.map((s) => `<div class="s">${esc(s)}</div>`).join("")}
<form method="POST" action="/oidc/consent">
  <input type="hidden" name="oidc_consent" value="${esc(nonce)}">
  <button type="submit">Approve</button>
</form>`;
  return new Response(html, { status: 200, headers: CONSENT_HTML_HEADERS });
}

async function handleOidcAuthorize(request: Request, env: HandlerEnv): Promise<Response> {
  if (!env.AUTH_DO) return new Response("AUTH_DO is required for OIDC authorization.", { status: 500 });
  const prepared = await prepareAuthorizationRequest(request, env);
  if (prepared instanceof Response) return prepared;
  const { oauth, scope } = prepared;

  const state = crypto.randomUUID() + crypto.randomUUID().replace(/-/g, "");
  const nonce = crypto.randomUUID() + crypto.randomUUID().replace(/-/g, "");
  const { url, verifier } = await buildOidcAuthorize(env, state, nonce);
  const record: OidcCorrelationRecord = {
    authRequest: oauth,
    grantedScopes: scope,
    nonce,
    pkceVerifier: verifier,
    expiresAt: Date.now() + oidcStateTtlMs(),
  };
  await env.AUTH_DO.get(env.AUTH_DO.idFromName(`oidc:${state}`)).createOidcRecord(state, record);
  return Response.redirect(url, 302);
}

async function handleOidcCallback(request: Request, env: HandlerEnv): Promise<Response> {
  if (!oidcEnabled(env)) return new Response("Not found", { status: 404 });
  if (!env.AUTH_DO) return new Response("AUTH_DO is required for OIDC authorization.", { status: 500 });
  const url = new URL(request.url);
  const code = url.searchParams.get("code") ?? "";
  const state = url.searchParams.get("state") ?? "";
  if (!code || !state) return new Response("Missing code or state.", { status: 400 });
  const record = await env.AUTH_DO.get(env.AUTH_DO.idFromName(`oidc:${state}`)).consumeOidcRecord(state);
  if (!record) return new Response("Invalid or already-used OIDC state.", { status: 400 });
  if (Date.now() > record.expiresAt) return new Response("OIDC state expired.", { status: 400 });
  const { grantProps } = await oidcPropsFromCode(
    env,
    code,
    record.pkceVerifier,
    record.nonce,
    record.grantedScopes,
  );
  const userId = typeof grantProps.userId === "string" ? grantProps.userId : "";
  if (!userId) return new Response("OIDC subject is missing.", { status: 400 });
  const client = await env.OAUTH_PROVIDER.lookupClient(record.authRequest.clientId);
  if (!client) return new Response("Unknown OAuth client.", { status: 400 });
  const consentNonce = crypto.randomUUID() + crypto.randomUUID().replace(/-/g, "");
  const sealed = await sealOidcGrantProps(env, userId, consentNonce, grantProps);
  const consent: OidcConsentRecord = {
    authRequest: record.authRequest,
    grantedScopes: record.grantedScopes,
    grantProps: sealed.grantProps,
    ...(sealed.sealedOidcRefreshToken ? { sealedOidcRefreshToken: sealed.sealedOidcRefreshToken } : {}),
    userId,
    ...(client.clientName ? { clientName: client.clientName } : {}),
    expiresAt: Date.now() + oidcStateTtlMs(),
  };
  await env.AUTH_DO.get(env.AUTH_DO.idFromName(`oidc-consent:${consentNonce}`)).createOidcConsentRecord(consentNonce, consent);
  return oidcConsentPage(consent, consentNonce);
}

async function handleOidcConsent(request: Request, env: HandlerEnv): Promise<Response> {
  if (!oidcEnabled(env)) return new Response("Not found", { status: 404 });
  if (!env.AUTH_DO) return new Response("AUTH_DO is required for OIDC authorization.", { status: 500 });
  if (request.method !== "POST") return new Response("Method not allowed.", { status: 405 });
  const form = await request.formData();
  const nonce = String(form.get("oidc_consent") ?? "");
  const record = nonce
    ? await env.AUTH_DO.get(env.AUTH_DO.idFromName(`oidc-consent:${nonce}`)).consumeOidcConsentRecord(nonce)
    : null;
  if (!record) return new Response("Invalid or expired OIDC consent request.", { status: 400 });
  if (Date.now() > record.expiresAt) return new Response("OIDC consent expired.", { status: 400 });
  const grantProps = await unsealOidcGrantProps(env, nonce, record);
  const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
    request: record.authRequest,
    userId: record.userId,
    metadata: { via: "oidc", issuer: env.OIDC_ISSUER },
    scope: record.grantedScopes,
    props: grantProps,
  });
  return Response.redirect(redirectTo, 302);
}

export const serviceNowAuthHandler = {
  async fetch(request: Request, env: HandlerEnv): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return Response.json({ ok: true, service: "servicenow-codemode-mcp" });
    }

    if (url.pathname === "/oidc/callback" && request.method === "GET") {
      return handleOidcCallback(request, env);
    }

    if (url.pathname === "/oidc/consent") {
      return handleOidcConsent(request, env);
    }

    if (url.pathname === "/authorize") {
      if (oidcEnabled(env)) {
        if (request.method === "GET") return handleOidcAuthorize(request, env);
        return new Response("OIDC authorization uses a redirect flow.", { status: 405 });
      }
      // OAUTH_KV holds the server-side consent state; a missing binding fails CLOSED here
      // (plan §P6a) rather than silently re-parsing a client-controlled field.
      const kv = requireOAuthKv(env);

      if (request.method === "GET") {
        const prepared = await prepareAuthorizationRequest(request, env);
        if (prepared instanceof Response) return prepared;
        const { oauth, clientName } = prepared;
        // Bind the authoritative auth-request to server-side state under a server-minted nonce;
        // only the nonce is ever sent to the client. Scope can no longer be tampered between
        // GET (display/validate) and POST (grant) — the POST reads the stored object wholesale.
        const nonce = crypto.randomUUID();
        await kv.put(CONSENT_KEY_PREFIX + nonce, JSON.stringify(oauth), { expirationTtl: CONSENT_TTL_SECONDS });
        return consentPage(oauth, clientName, nonce);
      }
      if (request.method === "POST") {
        const form = await request.formData();
        const nonce = String(form.get("consent") ?? "");
        // Look up the server-side state; a missing/expired/forged nonce fails CLOSED (never
        // trust a client-supplied auth-request). The stored object is the sole authority.
        const stored = nonce ? await kv.get(CONSENT_KEY_PREFIX + nonce) : null;
        if (!stored) return new Response("Invalid or expired consent request.", { status: 400 });
        const oauth = JSON.parse(stored) as AuthRequestInfo;
        const scope = grantScopes(oauth.scope);
        if (scope.length === 0) return unsupportedScopesResponse();

        const limited = await consentRateLimitResponse(request, env);
        if (limited) return limited;

        const secret = String(form.get("operator_secret") ?? "");
        const expected = env.MCP_OPERATOR_SECRET ?? "";
        // Fail closed: no configured secret => never authorize. On a wrong secret, re-render
        // with the SAME nonce (do NOT delete the entry — its TTL keeps the retry valid).
        if (!expected || secret.length !== expected.length || !constantTimeEqualAscii(secret, expected)) {
          return consentPage(oauth, "", nonce, "Invalid operator secret.");
        }
        // Single-use on success: burn the consent nonce so the grant can't be replayed.
        await kv.delete(CONSENT_KEY_PREFIX + nonce);
        const operatorUserId = env.MCP_OPERATOR_USER_ID?.trim();
        if (!operatorUserId) {
          return new Response("MCP_OPERATOR_USER_ID is required.", { status: 500 });
        }
        const operatorEmail = env.MCP_OPERATOR_EMAIL?.trim();
        const props = {
          userId: operatorUserId,
          scopes: scope,
          maxMode: maxModeFromScopes(scope),
          ...(operatorEmail ? { email: operatorEmail } : {}),
        };
        const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
          request: oauth,
          userId: operatorUserId,
          metadata: { via: "operator-secret" },
          scope,
          props,
        });
        return Response.redirect(redirectTo, 302);
      }
    }

    return new Response("Not found", { status: 404 });
  },
};
