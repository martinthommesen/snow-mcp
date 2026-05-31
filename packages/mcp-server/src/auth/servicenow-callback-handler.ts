// Per-user ServiceNow OAuth — authorize + callback routes (plan §6b).
//
// These routes live OUTSIDE /mcp, so they have NO ctx.props: identity is CARRIED IN via the
// host-HMAC ticket (servicenow-ticket.ts), never assumed from a request param. The top-level
// fetch wrapper (index.ts) already origin-guards the /servicenow/* prefix, so these handlers
// land behind that guard.
//
//   GET /servicenow/authorize?ticket=…
//     VERIFY the host-HMAC ticket (its only authority) + exp → generate PKCE → create a
//     single-use AuthCorrelationDO record {userId, instanceHost, pkceVerifier,
//     expiresAt} keyed by an opaque random `state` → 302 to the instance OAuth authorize
//     endpoint (response_type=code, PKCE S256, state).
//
//   GET /servicenow/callback?code&state
//     Look up the record by `state` and ATOMICALLY CONSUME-ONCE (read-and-delete) → check TTL
//     + that record.instanceHost matches the configured canonical instance → exchange the code
//     at oauth_token.do with the stored verifier + redirect_uri → resolve the SN principal →
//     store the token (+ principal) in TokenStoreDO under record.userId. ANY failure
//     (bad/replayed/wrong-instance state, expired, exchange error) → 4xx, never issue a token.

import { canonicalizeInstanceHost } from "../sn/url-allowlist.js";
import { DEFAULT_ALLOWED_HOST_SUFFIXES } from "../config.js";
import { verifyTicket } from "./servicenow-ticket.js";
import {
  authorizationCodeGrant,
  generatePkce,
  resolveSnPrincipal,
  type SnOAuthConfig,
} from "./servicenow-oauth.js";
import { TokenStore } from "./token-store.js";
import { buildKekRing } from "./crypto.js";
import { redactString } from "../observability/redact.js";
import type { AuthCorrelationRecord } from "../do/auth-correlation.js";

/** Minimal DO surface the routes need (test-injectable; real DOs satisfy these structurally). */
interface AuthCorrelationStub {
  createRecord(state: string, record: AuthCorrelationRecord): Promise<void>;
  consumeRecord(state: string): Promise<AuthCorrelationRecord | null>;
}
interface TokenStoreStub {
  putToken(tokenType: string, opaque: string): Promise<void>;
  getToken(tokenType: string): Promise<string | undefined>;
  revokeAll(): Promise<void>;
}
interface AuthCorrelationNamespace {
  idFromName(name: string): DurableObjectId;
  newUniqueId(): DurableObjectId;
  get(id: DurableObjectId): AuthCorrelationStub;
}
interface TokenStoreNamespace {
  idFromName(name: string): DurableObjectId;
  get(id: DurableObjectId): TokenStoreStub;
}

/** Env-like param for the routes (mirrors the auth-surface handler shape so it is unit-testable
 *  with real DO namespaces from `cloudflare:test` + an injectable `fetchImpl`). */
export interface CallbackHandlerEnv {
  AUTH_DO: AuthCorrelationNamespace;
  TOKEN_DO: TokenStoreNamespace;
  // I-1: configured public origin for the OAuth redirect_uri. Optional — when unset, the
  // request-derived origin is used (unchanged behavior). When set, the redirect_uri no longer
  // depends on the spoofable request Host.
  WORKER_PUBLIC_ORIGIN?: string;
  SNOW_INSTANCE_HOST?: string;
  SNOW_OAUTH_CLIENT_ID?: string;
  SNOW_OAUTH_CLIENT_SECRET?: string;
  TOKEN_KEK_CURRENT?: string;
  TOKEN_KEK?: string;
  TOKEN_KEK_PREV?: string;
  OAUTH_PROVIDER_SECRET?: string;
  SERVICENOW_CREDENTIAL_MODE?: "per_user_oauth" | "integration_user";
  /** Injected in tests to mock the upstream SN token exchange + current_user principal fetch. */
  fetchImpl?: typeof fetch;
}

/** TTL for an in-flight authorize→callback correlation (a started-but-unfinished flow). */
const CORRELATION_TTL_MS = 10 * 60 * 1000; // 10 minutes
const SCOPE = "useraccount";

function canonicalHost(env: CallbackHandlerEnv): string {
  return canonicalizeInstanceHost(env.SNOW_INSTANCE_HOST!, { allowedHostSuffixes: [...DEFAULT_ALLOWED_HOST_SUFFIXES] });
}

function oauthConfig(env: CallbackHandlerEnv, instanceHost: string): SnOAuthConfig {
  return {
    instanceHost,
    clientId: env.SNOW_OAUTH_CLIENT_ID!,
    clientSecret: env.SNOW_OAUTH_CLIENT_SECRET!,
    ...(env.fetchImpl ? { fetchImpl: env.fetchImpl } : {}),
  };
}

/** Is the per-user OAuth path fully configured? A missing piece fails closed (400). */
function configured(env: CallbackHandlerEnv): boolean {
  return Boolean(
    env.SNOW_INSTANCE_HOST &&
      env.SNOW_OAUTH_CLIENT_ID &&
      env.SNOW_OAUTH_CLIENT_SECRET &&
      env.OAUTH_PROVIDER_SECRET &&
      (env.TOKEN_KEK_CURRENT ?? env.TOKEN_KEK),
  );
}

function redirectUri(origin: string): string {
  return `${origin}/servicenow/callback`;
}

async function handleAuthorize(request: Request, env: CallbackHandlerEnv): Promise<Response> {
  if (!configured(env)) return new Response("ServiceNow OAuth is not configured.", { status: 400 });
  const url = new URL(request.url);
  const ticketStr = url.searchParams.get("ticket") ?? "";
  // The host-HMAC ticket is the ONLY identity authority here — verify it (signature + exp).
  const ticket = await verifyTicket(ticketStr, env.OAUTH_PROVIDER_SECRET!, Date.now());
  if (!ticket) return new Response("Invalid or expired authorization ticket.", { status: 401 });

  const instanceHost = canonicalHost(env);
  // The ticket's instanceHost must match this worker's configured instance — a ticket minted
  // for another instance must not start a flow against this one.
  if (ticket.instanceHost !== instanceHost) {
    return new Response("Ticket instance mismatch.", { status: 400 });
  }

  const { verifier, challenge } = await generatePkce();
  // Opaque, high-entropy OAuth `state` = the single-use DO record key. Identity (userId,
  // instanceHost) lives in the record, NOT in any client-visible param.
  const state = crypto.randomUUID() + crypto.randomUUID().replace(/-/g, "");
  const record: AuthCorrelationRecord = {
    userId: ticket.userId,
    instanceHost,
    pkceVerifier: verifier,
    expiresAt: Date.now() + CORRELATION_TTL_MS,
  };
  const ns = env.AUTH_DO;
  await ns.get(ns.idFromName(`state:${state}`)).createRecord(state, record);

  const authorize = new URL(`https://${instanceHost}/oauth_auth.do`);
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("client_id", env.SNOW_OAUTH_CLIENT_ID!);
  authorize.searchParams.set("redirect_uri", redirectUri(env.WORKER_PUBLIC_ORIGIN ?? url.origin));
  authorize.searchParams.set("scope", SCOPE);
  authorize.searchParams.set("state", state);
  authorize.searchParams.set("code_challenge", challenge);
  authorize.searchParams.set("code_challenge_method", "S256");
  return Response.redirect(authorize.toString(), 302);
}

async function handleCallback(request: Request, env: CallbackHandlerEnv): Promise<Response> {
  if (!configured(env)) return new Response("ServiceNow OAuth is not configured.", { status: 400 });
  const url = new URL(request.url);
  const code = url.searchParams.get("code") ?? "";
  const state = url.searchParams.get("state") ?? "";
  if (!code || !state) return new Response("Missing code or state.", { status: 400 });

  // ATOMIC consume-once: read-and-delete inside the DO input gate. A replayed callback for the
  // same state sees the deletion and gets null → rejected. The record is the SOLE authority for
  // userId/instanceHost — never a request param (this is what makes the cross-user test pass).
  const ns = env.AUTH_DO;
  const record = await ns.get(ns.idFromName(`state:${state}`)).consumeRecord(state);
  if (!record) return new Response("Invalid or already-used authorization state.", { status: 400 });
  if (Date.now() > record.expiresAt) return new Response("Authorization state expired.", { status: 400 });

  const instanceHost = canonicalHost(env);
  // The record's instance must match this worker's configured instance (cross-instance reject).
  if (record.instanceHost !== instanceHost) return new Response("Authorization instance mismatch.", { status: 400 });

  const cfg = oauthConfig(env, instanceHost);
  let tokens;
  try {
    tokens = await authorizationCodeGrant(cfg, code, record.pkceVerifier, redirectUri(env.WORKER_PUBLIC_ORIGIN ?? url.origin), Date.now());
  } catch (e) {
    console.error("servicenow callback: code exchange failed:", redactString(e instanceof Error ? e.message : String(e)));
    return new Response("ServiceNow token exchange failed.", { status: 400 });
  }

  // Resolve + persist the SN principal alongside the token (best-effort; a null principal still
  // stores a usable token — admin_script then falls back to the empty effective sys_id).
  const principal = await resolveSnPrincipal(cfg, tokens.access_token);
  if (principal) {
    tokens.sys_id = principal.sys_id;
    tokens.roles = principal.roles;
  }

  const ring = await buildKekRing((env.TOKEN_KEK_CURRENT ?? env.TOKEN_KEK)!, env.TOKEN_KEK_PREV);
  const tokStub = env.TOKEN_DO.get(env.TOKEN_DO.idFromName(`${record.userId}|${instanceHost}`));
  const store = new TokenStore(tokStub, ring, record.userId, instanceHost);
  await store.put("servicenow", tokens);

  return new Response("ServiceNow authorization complete. You may close this window.", {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

/** Route the /servicenow/* surface. Returns null when the path is not one of ours (so the
 *  caller can fall through to the OAuthProvider / 404). */
export async function serviceNowCallbackHandler(request: Request, env: CallbackHandlerEnv): Promise<Response | null> {
  const pathname = new URL(request.url).pathname;
  if (request.method === "GET" && pathname === "/servicenow/authorize") return handleAuthorize(request, env);
  if (request.method === "GET" && pathname === "/servicenow/callback") return handleCallback(request, env);
  return null;
}
