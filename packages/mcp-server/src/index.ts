import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { createMcpHandler } from "agents/mcp";
import { createServer } from "./server.js";
import { buildHandlers, resolveSchemaIdentity } from "./tools/handlers.js";
import { serviceNowAuthHandler } from "./auth/servicenow-auth-handler.js";
import { isOriginAllowed, originDeniedResponse, type OriginConfig } from "./observability/origin.js";
import { serviceNowCallbackHandler } from "./auth/servicenow-callback-handler.js";
import { canonicalPublicOrigin } from "./auth/public-origin.js";
import type { Mode } from "@servicenow-codemode/shared";
import { parseScopeMaxMode } from "@servicenow-codemode/shared";
import { redactString } from "./observability/redact.js";
import {
  assertProductionPostureOnce,
  collectPostureViolations,
  parseDeploymentProfile,
  ProductionPostureError,
  type PostureEnv,
} from "./authz/production-posture-core.js";
import { oidcAccessTokenProps, oidcAuthorizationCodeTokenResult, refreshOidcGrantProps } from "./auth/oidc.js";
import { SUPPORTED_SCOPES } from "./auth/mcp-scopes.js";
import { sourceIpRateLimited, type ConsentRateNamespace } from "./auth/rate-limit.js";

// Durable Objects must be exported from the entry module (plan §2.10).
export { AuthCorrelationDO } from "./do/auth-correlation.js";
export { TokenStoreDO } from "./do/token-store.js";
export { BudgetDO } from "./do/budget.js";
export { MutationLedgerDO } from "./do/mutation-ledger.js";
export { ConsentRateDO } from "./do/consent-rate.js";
export { McpAdmissionDO } from "./do/mcp-admission.js";

export interface Env {
  LOADER: WorkerLoader;
  SCHEMA_KV: KVNamespace;
  OAUTH_KV: KVNamespace;
  // Host audit trail (§7.2) + recovery snapshots (§7.7). Declared optional in P0;
  // consumed once their flows are wired (P4). Worker treats absence as "not durable".
  AUDIT_KV?: KVNamespace;
  SNAPSHOT_KV?: KVNamespace;
  AUTH_DO: DurableObjectNamespace;
  TOKEN_DO: DurableObjectNamespace;
  BUDGET_DO: DurableObjectNamespace;
  LEDGER_DO: DurableObjectNamespace;
  // Consent-write rate limiter (finding 4). Missing binding fails closed on consent/registration.
  CONSENT_RATE_DO?: ConsentRateNamespace;
  // Authenticated /mcp admission limiter. Missing/unreachable binding fails closed.
  MCP_ADMISSION_DO?: DurableObjectNamespace;
  ALLOWED_ORIGINS?: string;
  // I-1: pin the worker's public origin for OAuth redirect_uri / reauth URLs instead of deriving
  // it from the request Host. Required when SERVICENOW_CREDENTIAL_MODE=per_user_oauth.
  WORKER_PUBLIC_ORIGIN?: string;
  MCP_OPERATOR_SECRET?: string;
  MCP_OPERATOR_USER_ID?: string;
  MCP_OPERATOR_EMAIL?: string;
  MCP_OPERATOR_ACCESS_GROUPS?: string;
  AUTH_MODE?: string;
  SNOW_INSTANCE_HOST?: string;
  SNOW_DEV_ROPC?: string;
  SNOW_DEV_ROPC_USERNAME?: string;
  SNOW_DEV_ROPC_PASSWORD?: string;
  SNOW_OAUTH_CLIENT_ID?: string;
  SNOW_OAUTH_CLIENT_SECRET?: string;
  SNOW_EXECUTOR_PATH?: string;
  X_MCP_EXECUTOR_HMAC_KEY?: string;
  OAUTH_PROVIDER_SECRET?: string;
  // Versioned KEK ring (P3): current + optional previous, for both token + snapshot stores.
  TOKEN_KEK_CURRENT?: string;
  TOKEN_KEK_PREV?: string;
  SNAPSHOT_KEK_CURRENT?: string;
  SNAPSHOT_KEK_PREV?: string;
  // Credential mode (P6) + ceilings (P5) + origin gate (P6a). All optional in P0.
  SERVICENOW_CREDENTIAL_MODE?: string;
  DEPLOYMENT_PROFILE?: string;
  ALLOW_ADMIN_SCRIPT_CEILING?: string;
  SNOW_EXECUTOR_VERIFIER_ATTESTED?: string;
  AUDIT_SIEM_ATTESTED?: string;
  MUTATION_FREEZE?: string;
  ALLOW_LOCALHOST?: string;
  TENANT_MAX_MODE?: Mode;
  INSTANCE_MAX_MODE?: Mode;
  // Recovery-snapshot config (§7.7) + second-approval policy (§7.9). Empty approval
  // settings deny admin_script; configure allowlist + token/group to permit it.
  SNAPSHOT_ENABLED_TABLES?: string;
  ADMIN_SCRIPT_ALLOWLIST?: string;
  ADMIN_SCRIPT_APPROVAL_TOKENS?: string;
  ADMIN_SCRIPT_REQUIRED_GROUP?: string;
  // Restrictive ActorPolicy (§6b). With none set the policy denies all tables; configure
  // allowlists, field masks, row filters, and per-run ceilings before connecting ServiceNow.
  ACTOR_POLICY_TABLE_ALLOWLIST?: string;
  ACTOR_POLICY_FIELD_MASKS?: string;
  ACTOR_POLICY_ROW_FILTERS?: string;
  ACTOR_POLICY_MAX_ROWS_PER_RUN?: string;
  ACTOR_POLICY_MAX_BYTES_PER_RUN?: string;
  ACTOR_POLICY_MAX_MODE?: Mode;
  ACTOR_POLICIES_JSON?: string;
  OIDC_ISSUER?: string;
  OIDC_CLIENT_ID?: string;
  OIDC_CLIENT_SECRET?: string;
  OIDC_SCOPES?: string;
  OIDC_GROUP_CLAIM?: string;
  OIDC_GROUP_POLICY_MAP?: string;
  OIDC_DEFAULT_POLICY_NAME?: string;
  GIT_COMMIT_SHA?: string;
  BUILD_TIMESTAMP?: string;
}

function originConfig(env: Env): OriginConfig {
  const allowedOrigins = (env.ALLOWED_ORIGINS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  // Env-gate localhost (plan §P6a, finding 20): default FALSE in prod so a forged
  // `http://localhost` Origin no longer passes; operators opt in for local dev only.
  return { allowedOrigins, allowLocalhost: env.ALLOW_LOCALHOST === "true" };
}

// Auth-surface paths the OAuthProvider routes BEFORE apiHandler — so the only origin check
// (inside apiHandler, /mcp) never covers them. The top-level wrapper below applies the SAME
// originConfig to these (plan §P6a, finding 32). `/servicenow/*` lands in P6b but the wrapper
// covers it now so the per-user OAuth callback is guarded from the start. NOT guarded:
// `/.well-known/*` (public metadata), `/health`, and `/mcp` (defense-in-depth check stays in
// apiHandler). An absent Origin (non-browser client) is allowed by isOriginAllowed.
function isAuthSurfacePath(pathname: string): boolean {
  return (
    pathname === "/authorize" ||
    pathname === "/oauth/token" ||
    pathname === "/oauth/register" ||
    pathname.startsWith("/oidc/") ||
    pathname.startsWith("/servicenow/")
  );
}

function oauthAuthorizationServerMetadataRequest(request: Request): Request {
  const url = new URL(request.url);
  url.pathname = "/.well-known/oauth-authorization-server";
  return new Request(url, request);
}

const serviceName = "servicenow-codemode-mcp";
const appVersion = "0.1.0";
const workerCompatibilityDate = "2026-05-13";

function healthLive(): Response {
  return Response.json({ ok: true, service: serviceName });
}

function healthReady(env: Env): Response {
  const violations = collectPostureViolations(env as PostureEnv);
  const ok = violations.length === 0;
  return Response.json(
    {
      ok,
      service: serviceName,
      profile: parseDeploymentProfile(env.DEPLOYMENT_PROFILE) ?? "invalid",
      ...(ok ? { violations: [] } : { violationCount: violations.length }),
    },
    { status: ok ? 200 : 503 },
  );
}

function productionPostureResponse(error: ProductionPostureError, includeViolations: boolean): Response {
  return Response.json(
    {
      error: "production_posture",
      ...(includeViolations ? { violations: error.violations } : { violationCount: error.violations.length }),
    },
    { status: 503 },
  );
}

export interface AdmissionStub {
  admit(now?: number): Promise<{ ok: true; leaseId: string } | { ok: false; reason: "rate" | "concurrency"; retryAfterMs: number }>;
  release(leaseId: string): Promise<void>;
}

export type AdmissionLease = { stub: AdmissionStub; leaseId: string };

function retryAfterSeconds(ms: number): string {
  return String(Math.max(1, Math.ceil(ms / 1000)));
}

async function admitMcpRequest(env: Env, userId: string): Promise<AdmissionLease | Response> {
  if (!env.MCP_ADMISSION_DO) {
    return Response.json({ error: "admission_unavailable" }, { status: 503 });
  }
  try {
    const ns = env.MCP_ADMISSION_DO;
    const stub = ns.get(ns.idFromName(userId)) as unknown as AdmissionStub;
    const admitted = await stub.admit(Date.now());
    if (!admitted.ok) {
      return Response.json(
        { error: admitted.reason === "rate" ? "rate_limited" : "too_many_in_flight" },
        { status: 429, headers: { "Retry-After": retryAfterSeconds(admitted.retryAfterMs) } },
      );
    }
    return { stub, leaseId: admitted.leaseId };
  } catch (e) {
    console.error("mcp admission failed:", redactString(e instanceof Error ? e.message : String(e)));
    return Response.json({ error: "admission_unavailable" }, { status: 503 });
  }
}

async function releaseMcpAdmission(lease: AdmissionLease): Promise<void> {
  try {
    await lease.stub.release(lease.leaseId);
  } catch (e) {
    console.error("mcp admission release failed:", redactString(e instanceof Error ? e.message : String(e)));
  }
}

export function responseWithAdmissionRelease(response: Response, lease: AdmissionLease, ctx: ExecutionContext): Response {
  if (!response.body) {
    ctx.waitUntil(releaseMcpAdmission(lease));
    return response;
  }
  const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>();
  const pump = response.body
    .pipeTo(writable)
    .catch(() => {
      // Client cancellation or stream errors should still release the lease.
    })
    .finally(() => releaseMcpAdmission(lease));
  ctx.waitUntil(pump);
  return new Response(readable, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
}

function healthVersion(env: Env): Response {
  return Response.json({
    ok: true,
    service: serviceName,
    appVersion,
    compatibilityDate: workerCompatibilityDate,
    commitSha: env.GIT_COMMIT_SHA ?? null,
    buildTimestamp: env.BUILD_TIMESTAMP ?? null,
  });
}

async function registrationRateLimitResponse(request: Request, env: Env): Promise<Response | undefined> {
  if (!(await sourceIpRateLimited(request, env.CONSENT_RATE_DO, "registration-rate"))) return undefined;
  return Response.json({ error: "rate_limited" }, { status: 429 });
}

export function authenticatedUserId(props: Record<string, unknown>): string | undefined {
  const userId = props.userId;
  return typeof userId === "string" && userId.trim() ? userId : undefined;
}

export function authenticatedGrantAllowedForDeploymentProfile(env: Pick<Env, "DEPLOYMENT_PROFILE">, props: Record<string, unknown>): boolean {
  if (parseDeploymentProfile(env.DEPLOYMENT_PROFILE) !== "production") return true;
  return props.authMode === "oidc" && typeof props.oidcSubject === "string" && props.oidcSubject.trim() !== "";
}

/** Authenticated MCP API handler. Reached ONLY after the OAuthProvider validates the
 *  client token; `ctx.props` carries the grant props (userId, scopes, maxMode). */
const apiHandler = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      if (!isOriginAllowed(request, originConfig(env))) return originDeniedResponse();
      assertProductionPostureOnce(env as PostureEnv);
      const props = ((ctx as { props?: unknown }).props as Record<string, unknown>) ?? {};
      if (!authenticatedGrantAllowedForDeploymentProfile(env, props)) {
        return Response.json({ error: "invalid_auth_context" }, { status: 401 });
      }
      // I-3: validate (not just null-coalesce) — a set-but-invalid maxMode falls back to read_only,
      // consistent with parseMaxMode/loadActorPolicy. modeRisk would already block escalation, but
      // this keeps the fail-closed posture uniform across every ceiling input.
      const scopeMaxMode: Mode = parseScopeMaxMode(props.maxMode);
      const userId = authenticatedUserId(props);
      if (!userId) return Response.json({ error: "invalid_auth_context" }, { status: 401 });
      const workerOrigin = canonicalPublicOrigin(env.WORKER_PUBLIC_ORIGIN);
      if (env.SERVICENOW_CREDENTIAL_MODE === "per_user_oauth" && !workerOrigin) {
        return Response.json({ error: "public_origin_required" }, { status: 500 });
      }
      const admission = await admitMcpRequest(env, userId);
      if (admission instanceof Response) return admission;
      try {
        // Per-request server (§2.3); auth props flow to tools via getMcpAuthContext().
        const response = await createMcpHandler(createServer(buildHandlers(env, {
          userId,
          scopeMaxMode,
          props,
          ...(workerOrigin ? { workerOrigin } : {}),
          schemaIdentityResolver: (budget) => resolveSchemaIdentity(env, userId, { budget }),
          schemaIdentityFreshResolver: () => resolveSchemaIdentity(env, userId, { freshOnly: true }),
        })), {
          authContext: { props },
        })(request, env, ctx);
        return responseWithAdmissionRelease(response, admission, ctx);
      } catch (e) {
        await releaseMcpAdmission(admission);
        throw e;
      }
    } catch (e) {
      if (e instanceof ProductionPostureError) {
        return productionPostureResponse(e, true);
      }
      // Fail closed with a generic message (never leak internals); detail to the log only.
      // I-5: redact the logged message (matches sn/errors.ts) so a secret-bearing error can't reach
      // server logs unscrubbed.
      console.error("apiHandler error:", redactString(e instanceof Error ? e.message : String(e)));
      return Response.json({ error: "internal_error" }, { status: 500 });
    }
  },
};

// Memoized per `env` (i.e. per isolate): the provider is built inside fetch() only so
// tokenExchangeCallback can close over `env`, but its config is otherwise constant — so cache it
// rather than reconstruct on every request. (Same WeakMap-per-env pattern as assertProductionPostureOnce.)
const providerCache = new WeakMap<Env, OAuthProvider<Env>>();

function providerForEnv(env: Env): OAuthProvider<Env> {
  const cached = providerCache.get(env);
  if (cached) return cached;
  // The OAuthProvider wraps the Worker: it implements /authorize metadata, /oauth/token,
  // /oauth/register, validates tokens on /mcp, and routes everything else to the consent/OIDC
  // handler. No valid token on /mcp -> 401 (plan §2.4, §7.8; closes the open-endpoint gap).
  const provider = new OAuthProvider<Env>({
    apiRoute: "/mcp",
    apiHandler,
    defaultHandler: serviceNowAuthHandler as never,
    authorizeEndpoint: "/authorize",
    tokenEndpoint: "/oauth/token",
    clientRegistrationEndpoint: "/oauth/register",
    scopesSupported: [...SUPPORTED_SCOPES],
    allowPlainPKCE: false,
    tokenExchangeCallback: async (options: { grantType: string; scope: string[]; requestedScope?: string[]; props: unknown }) => {
      const props = (options.props && typeof options.props === "object" ? options.props : {}) as Record<string, unknown>;
      if (props.authMode !== "oidc") return undefined;
      const requestedScope = options.requestedScope ?? options.scope;
      if (options.grantType === "authorization_code") {
        return oidcAuthorizationCodeTokenResult(props, requestedScope);
      }
      if (options.grantType === "refresh_token") {
        const refreshed = await refreshOidcGrantProps(env, props, options.scope);
        return refreshed ? { newProps: refreshed.grantProps, accessTokenProps: oidcAccessTokenProps(refreshed.grantProps, requestedScope) } : undefined;
      }
      return undefined;
    },
  });
  providerCache.set(env, provider);
  return provider;
}

// Top-level fetch wrapper (plan §P6a, finding 32): run the Origin guard on the auth-surface
// paths (which OAuthProvider routes BEFORE apiHandler, so they would otherwise be unchecked)
// using the SAME OriginConfig as the /mcp check, THEN delegate to the provider. /mcp keeps its
// own check inside apiHandler (defense in depth, same config).
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      // A denied origin returns 403 (a return, not a throw) and skips the provider. A thrown
      // MissingOAuthKvError (unbound OAUTH_KV) from provider.fetch is caught below -> 500,
      // mirroring apiHandler's catch (plan §P6a, finding 36).
      const url = new URL(request.url);
      if (url.pathname === "/health" || url.pathname === "/health/live") return healthLive();
      if (url.pathname === "/health/ready") return healthReady(env);
      if (url.pathname === "/health/version") return healthVersion(env);
      const provider = providerForEnv(env);
      // Some MCP clients discover OAuth authorization-server metadata at the path-scoped
      // RFC 8414 URL for the protected resource (`/.well-known/oauth-authorization-server/mcp`).
      // workers-oauth-provider serves the root metadata URL; delegate there so both forms match.
      if (url.pathname === "/.well-known/oauth-authorization-server/mcp") {
        return await provider.fetch(oauthAuthorizationServerMetadataRequest(request), env, ctx);
      }
      if (url.pathname !== "/mcp") assertProductionPostureOnce(env as PostureEnv);
      if (isAuthSurfacePath(url.pathname) && !isOriginAllowed(request, originConfig(env))) {
        return originDeniedResponse();
      }
      if (url.pathname === "/oauth/register" && request.method === "POST") {
        const limited = await registrationRateLimitResponse(request, env);
        if (limited) return limited;
      }
      // Per-user ServiceNow OAuth routes (§6b) live OUTSIDE /mcp and are NOT served by the
      // OAuthProvider's defaultHandler — route them here (behind the origin guard above), and
      // fall through to the provider for everything else. Identity is carried in via the
      // host-HMAC ticket, never assumed (the routes have no ctx.props).
      if (url.pathname.startsWith("/servicenow/")) {
        const snRoute = await serviceNowCallbackHandler(request, env as unknown as Parameters<typeof serviceNowCallbackHandler>[1]);
        if (snRoute) return snRoute;
      }
      return await provider.fetch(request, env, ctx);
    } catch (e) {
      if (e instanceof ProductionPostureError) {
        return productionPostureResponse(e, false);
      }
      console.error("top-level fetch error:", redactString(e instanceof Error ? e.message : String(e)));
      return Response.json({ error: "internal_error" }, { status: 500 });
    }
  },
};
