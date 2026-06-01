import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { createMcpHandler } from "agents/mcp";
import { createServer } from "./server.js";
import { buildHandlers, resolveSchemaIdentity } from "./tools/handlers.js";
import { serviceNowAuthHandler } from "./auth/servicenow-auth-handler.js";
import { isOriginAllowed, originDeniedResponse, type OriginConfig } from "./observability/origin.js";
import { serviceNowCallbackHandler } from "./auth/servicenow-callback-handler.js";
import { canonicalPublicOrigin } from "./auth/public-origin.js";
import type { Mode } from "@servicenow-codemode/shared";
import { isValidMode } from "@servicenow-codemode/shared";
import { redactString } from "./observability/redact.js";

// Durable Objects must be exported from the entry module (plan §2.10).
export { AuthCorrelationDO } from "./do/auth-correlation.js";
export { TokenStoreDO } from "./do/token-store.js";
export { BudgetDO } from "./do/budget.js";
export { MutationLedgerDO } from "./do/mutation-ledger.js";
export { ConsentRateDO } from "./do/consent-rate.js";

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
  // Consent-write rate limiter (finding 4). Optional: when unbound (older config/tests), the
  // GET /authorize admission check is skipped — wire it in wrangler.jsonc to enable.
  CONSENT_RATE_DO?: DurableObjectNamespace<import("./do/consent-rate.js").ConsentRateDO>;
  ALLOWED_ORIGINS?: string;
  // I-1: pin the worker's public origin for OAuth redirect_uri / reauth URLs instead of deriving
  // it from the request Host. Required when SERVICENOW_CREDENTIAL_MODE=per_user_oauth.
  WORKER_PUBLIC_ORIGIN?: string;
  MCP_OPERATOR_SECRET?: string;
  MCP_OPERATOR_USER_ID?: string;
  MCP_OPERATOR_EMAIL?: string;
  MCP_OPERATOR_ACCESS_GROUPS?: string;
  SNOW_INSTANCE_HOST?: string;
  SNOW_DEV_ROPC?: string;
  SNOW_DEV_ROPC_USERNAME?: string;
  SNOW_DEV_ROPC_PASSWORD?: string;
  SNOW_OAUTH_CLIENT_ID?: string;
  SNOW_OAUTH_CLIENT_SECRET?: string;
  X_MCP_EXECUTOR_HMAC_KEY?: string;
  TOKEN_KEK?: string; // one-release alias for TOKEN_KEK_CURRENT (P3 migration)
  OAUTH_PROVIDER_SECRET?: string;
  SNAPSHOT_KEK?: string; // one-release alias for SNAPSHOT_KEK_CURRENT (P3 migration)
  // Versioned KEK ring (P3): current + optional previous, for both token + snapshot stores.
  TOKEN_KEK_CURRENT?: string;
  TOKEN_KEK_PREV?: string;
  SNAPSHOT_KEK_CURRENT?: string;
  SNAPSHOT_KEK_PREV?: string;
  // Credential mode (P6) + ceilings (P5) + origin gate (P6a). All optional in P0.
  SERVICENOW_CREDENTIAL_MODE?: string;
  ALLOW_LOCALHOST?: string;
  TENANT_MAX_MODE?: Mode;
  INSTANCE_MAX_MODE?: Mode;
  // Recovery-snapshot config (§7.7) + second-approval policy (§7.9). Empty approval
  // settings deny admin_script; configure allowlist + token/group to permit it.
  SNAPSHOT_ENABLED_TABLES?: string;
  ADMIN_SCRIPT_ALLOWLIST?: string;
  ADMIN_SCRIPT_APPROVAL_TOKENS?: string;
  ADMIN_SCRIPT_REQUIRED_GROUP?: string;
  // Restrictive ActorPolicy (§6b). All optional: with NONE set the policy falls back to the
  // permissive single-operator default (live deployment unchanged); set ANY to build a
  // restrictive policy (table allowlist + field masks + row filters + per-run ceilings).
  ACTOR_POLICY_TABLE_ALLOWLIST?: string;
  ACTOR_POLICY_FIELD_MASKS?: string;
  ACTOR_POLICY_ROW_FILTERS?: string;
  ACTOR_POLICY_MAX_ROWS_PER_RUN?: string;
  ACTOR_POLICY_MAX_BYTES_PER_RUN?: string;
  ACTOR_POLICY_MAX_MODE?: Mode;
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
    pathname.startsWith("/servicenow/")
  );
}

export function authenticatedUserId(props: Record<string, unknown>): string | undefined {
  const userId = props.userId;
  return typeof userId === "string" && userId.trim() ? userId : undefined;
}

/** Authenticated MCP API handler. Reached ONLY after the OAuthProvider validates the
 *  client token; `ctx.props` carries the grant props (userId, scopes, maxMode). */
const apiHandler = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      if (!isOriginAllowed(request, originConfig(env))) return originDeniedResponse();
      const props = ((ctx as { props?: unknown }).props as Record<string, unknown>) ?? {};
      // I-3: validate (not just null-coalesce) — a set-but-invalid maxMode falls back to read_only,
      // consistent with parseMaxMode/loadActorPolicy. modeRisk would already block escalation, but
      // this keeps the fail-closed posture uniform across every ceiling input.
      const scopeMaxMode: Mode = isValidMode(props.maxMode) ? props.maxMode : "read_only";
      const userId = authenticatedUserId(props);
      if (!userId) return Response.json({ error: "invalid_auth_context" }, { status: 401 });
      const workerOrigin = canonicalPublicOrigin(env.WORKER_PUBLIC_ORIGIN);
      if (env.SERVICENOW_CREDENTIAL_MODE === "per_user_oauth" && !workerOrigin) {
        return Response.json({ error: "public_origin_required" }, { status: 500 });
      }
      // Per-request server (§2.3); auth props flow to tools via getMcpAuthContext().
      return await createMcpHandler(createServer(buildHandlers(env, {
        userId,
        scopeMaxMode,
        props,
        ...(workerOrigin ? { workerOrigin } : {}),
        schemaIdentityResolver: () => resolveSchemaIdentity(env, userId),
      })), {
        authContext: { props },
      })(request, env, ctx);
    } catch (e) {
      // Fail closed with a generic message (never leak internals); detail to the log only.
      // I-5: redact the logged message (matches sn/errors.ts) so a secret-bearing error can't reach
      // server logs unscrubbed.
      console.error("apiHandler error:", redactString(e instanceof Error ? e.message : String(e)));
      return Response.json({ error: "internal_error" }, { status: 500 });
    }
  },
};

// The OAuthProvider wraps the Worker: it implements /authorize metadata, /oauth/token,
// /oauth/register, validates tokens on /mcp, and routes everything else to the consent
// handler. No valid token on /mcp -> 401 (plan §2.4, §7.8; closes the open-endpoint gap).
const provider = new OAuthProvider({
  apiRoute: "/mcp",
  apiHandler,
  defaultHandler: serviceNowAuthHandler as never,
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/oauth/token",
  clientRegistrationEndpoint: "/oauth/register",
  scopesSupported: ["servicenow:read", "servicenow:write", "servicenow:admin_script"],
  allowPlainPKCE: false,
});

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
      if (isAuthSurfacePath(url.pathname) && !isOriginAllowed(request, originConfig(env))) {
        return originDeniedResponse();
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
      console.error("top-level fetch error:", redactString(e instanceof Error ? e.message : String(e)));
      return Response.json({ error: "internal_error" }, { status: 500 });
    }
  },
};
