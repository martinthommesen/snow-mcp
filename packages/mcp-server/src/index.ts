import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { createMcpHandler } from "agents/mcp";
import { createServer } from "./server.js";
import { buildHandlers } from "./tools/handlers.js";
import { serviceNowAuthHandler } from "./auth/servicenow-auth-handler.js";
import { isOriginAllowed, originDeniedResponse, type OriginConfig } from "./observability/origin.js";
import type { Mode } from "@servicenow-codemode/shared";

// Durable Objects must be exported from the entry module (plan §2.10).
export { AuthCorrelationDO } from "./do/auth-correlation.js";
export { TokenStoreDO } from "./do/token-store.js";
export { BudgetDO } from "./do/budget.js";
export { MutationLedgerDO } from "./do/mutation-ledger.js";

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
  ALLOWED_ORIGINS?: string;
  MCP_OPERATOR_SECRET?: string;
  SNOW_INSTANCE_HOST?: string;
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
  SERVICENOW_CREDENTIAL_MODE?: "per_user_oauth" | "integration_user";
  ALLOW_LOCALHOST?: string;
  TENANT_MAX_MODE?: Mode;
  INSTANCE_MAX_MODE?: Mode;
  // Recovery-snapshot config (§7.7) + second-approval policy (§7.9). All optional (P4);
  // an unset approval policy SKIPS the gate (single-operator default keeps working).
  SNAPSHOT_ENABLED_TABLES?: string;
  ADMIN_SCRIPT_ALLOWLIST?: string;
  ADMIN_SCRIPT_APPROVAL_TOKENS?: string;
  ADMIN_SCRIPT_REQUIRED_GROUP?: string;
}

function originConfig(env: Env): OriginConfig {
  const allowedOrigins = (env.ALLOWED_ORIGINS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  return { allowedOrigins, allowLocalhost: true };
}

/** Authenticated MCP API handler. Reached ONLY after the OAuthProvider validates the
 *  client token; `ctx.props` carries the grant props (userId, scopes, maxMode). */
const apiHandler = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      if (!isOriginAllowed(request, originConfig(env))) return originDeniedResponse();
      const props = ((ctx as { props?: unknown }).props as Record<string, unknown>) ?? {};
      const scopeMaxMode = (props.maxMode as Mode) ?? "read_only";
      // Per-request server (§2.3); auth props flow to tools via getMcpAuthContext().
      return await createMcpHandler(createServer(buildHandlers(env, { scopeMaxMode, props })), {
        authContext: { props },
      })(request, env, ctx);
    } catch (e) {
      // Fail closed with a generic message (never leak internals); detail to the log only.
      console.error("apiHandler error:", e instanceof Error ? e.message : String(e));
      return Response.json({ error: "internal_error" }, { status: 500 });
    }
  },
};

// The OAuthProvider wraps the Worker: it implements /authorize metadata, /oauth/token,
// /oauth/register, validates tokens on /mcp, and routes everything else to the consent
// handler. No valid token on /mcp -> 401 (plan §2.4, §7.8; closes the open-endpoint gap).
export default new OAuthProvider({
  apiRoute: "/mcp",
  apiHandler,
  defaultHandler: serviceNowAuthHandler as never,
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/oauth/token",
  clientRegistrationEndpoint: "/oauth/register",
  scopesSupported: ["servicenow:read", "servicenow:write", "servicenow:admin_script"],
  allowPlainPKCE: false,
});
