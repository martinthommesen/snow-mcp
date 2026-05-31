// Builds the injected ServerHandlers (plan §3.2).
//
// Two modes:
//  - CONNECTED dev path: when Basic-Auth dev creds are present, run_code reaches the
//    real instance via ServiceNowRPC and describe_table/list_tables use the discovery
//    module. (OAuth consent/PKCE is the production path; not wired yet.)
//  - NOT-CONNECTED: fail closed with `reauth_required` until creds exist.

import type { ServerHandlers, ToolTextResult } from "../server.js";
import { runCode, type RunCodeDeps } from "./run_code.js";
import { ServiceNowRPC } from "../sn/rpc.js";
import { SnFetchClient, type SnHttpClient } from "../sn/http.js";
import { describeTable, listTables, type DiscoveryDeps } from "../sn/discovery.js";
import { permissivePolicy, type ActorPolicy } from "../authz/actor-policy.js";
import { McpToolError, toToolResult } from "../sn/errors.js";
import { RunBudget } from "../sn/run-budget.js";
import { DEFAULT_ALLOWED_HOST_SUFFIXES } from "../config.js";
import { SchemaCache } from "../cache/schema.js";
import { TokenStore } from "../auth/token-store.js";
import { getServiceNowBearer, type SnOAuthConfig } from "../auth/servicenow-oauth.js";
import { buildKekRing } from "../auth/crypto.js";
import type { Mode } from "@servicenow-codemode/shared";

class NotConnectedHttpClient implements SnHttpClient {
  async request(): Promise<never> {
    throw new McpToolError("reauth_required", "Not connected to ServiceNow — complete OAuth (Phase 1) first.");
  }
}

export interface HandlerEnv {
  LOADER: WorkerLoader;
  BUDGET_DO?: DurableObjectNamespace;
  SCHEMA_KV?: KVNamespace;
  // Host audit (§7.2) + recovery snapshots (§7.7). Declared in P0; consumed in P4.
  AUDIT_KV?: KVNamespace;
  SNAPSHOT_KV?: KVNamespace;
  SNOW_INSTANCE_HOST?: string;
  // Per-user ServiceNow OAuth path (preferred): tokens stored encrypted in TokenStoreDO.
  SNOW_OAUTH_CLIENT_ID?: string;
  SNOW_OAUTH_CLIENT_SECRET?: string;
  TOKEN_DO?: DurableObjectNamespace;
  TOKEN_KEK?: string; // one-release alias for TOKEN_KEK_CURRENT (P3 migration)
  // Versioned KEK ring (P3): current + optional previous, for token + snapshot stores.
  TOKEN_KEK_CURRENT?: string;
  TOKEN_KEK_PREV?: string;
  SNAPSHOT_KEK_CURRENT?: string;
  SNAPSHOT_KEK_PREV?: string;
  // Credential mode (P6) + mode ceilings (P5). All optional in P0.
  SERVICENOW_CREDENTIAL_MODE?: "per_user_oauth" | "integration_user";
  TENANT_MAX_MODE?: Mode;
  INSTANCE_MAX_MODE?: Mode;
  // Dev Basic-Auth fallback (mirrors .dev.vars) + ROPC creds reused by the OAuth path.
  SNOW_DEV_ROPC_USERNAME?: string;
  SNOW_DEV_ROPC_PASSWORD?: string;
  // Executor (runServerScript / admin_script): HMAC signing key + endpoint path (§2.0, §5.6).
  X_MCP_EXECUTOR_HMAC_KEY?: string;
  SNOW_EXECUTOR_PATH?: string;
}

function b64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function utcDateKey(): string {
  return new Date().toISOString().slice(0, 10);
}

export interface AuthContext {
  /** Highest mode the client's OAuth scope permits (auth.props.maxMode, §2.0.1/§2.4). */
  scopeMaxMode: Mode;
  props?: Record<string, unknown>;
}

export function buildHandlers(env: HandlerEnv, auth?: AuthContext): ServerHandlers {
  const scopeMaxMode: Mode = auth?.scopeMaxMode ?? "read_only";
  const instanceHost = env.SNOW_INSTANCE_HOST ?? "unconfigured.invalid";
  const userId = (auth?.props?.userId as string) ?? "operator";
  const policy: ActorPolicy = permissivePolicy([instanceHost]); // single-operator dev default

  // Authorization header strategy (preference order):
  //  1. Per-user ServiceNow OAuth Bearer — tokens minted/refreshed and stored encrypted in
  //     TokenStoreDO (§2.7, §7.5). Preferred.
  //  2. Dev Basic-Auth fallback.
  //  3. Not connected -> fail closed.
  // TOKEN_KEK is a one-release alias for TOKEN_KEK_CURRENT (P3 migration).
  const tokenKekSecret = env.TOKEN_KEK_CURRENT ?? env.TOKEN_KEK;
  const credentialMode = env.SERVICENOW_CREDENTIAL_MODE ?? "integration_user";
  const oauthReady = Boolean(env.SNOW_OAUTH_CLIENT_ID && env.SNOW_OAUTH_CLIENT_SECRET && env.TOKEN_DO && tokenKekSecret && env.SNOW_INSTANCE_HOST);
  const devConnected = Boolean(env.SNOW_INSTANCE_HOST && env.SNOW_DEV_ROPC_USERNAME && env.SNOW_DEV_ROPC_PASSWORD);

  let http: SnHttpClient;
  if (oauthReady) {
    const stub = env.TOKEN_DO!.get(env.TOKEN_DO!.idFromName(`${userId}|${instanceHost}`)) as unknown as {
      putToken(t: string, v: string): Promise<void>; getToken(t: string): Promise<string | undefined>; revokeAll(): Promise<void>;
    };
    const cfg: SnOAuthConfig = {
      instanceHost, clientId: env.SNOW_OAUTH_CLIENT_ID!, clientSecret: env.SNOW_OAUTH_CLIENT_SECRET!,
      ...(env.SNOW_DEV_ROPC_USERNAME ? { ropcUsername: env.SNOW_DEV_ROPC_USERNAME } : {}),
      ...(env.SNOW_DEV_ROPC_PASSWORD ? { ropcPassword: env.SNOW_DEV_ROPC_PASSWORD } : {}),
    };
    http = new SnFetchClient({
      instanceHost, allowlist: { allowedHostSuffixes: [...DEFAULT_ALLOWED_HOST_SUFFIXES] },
      getAuthorization: async () => {
        // Versioned, content-addressed KEK ring (P3): TOKEN_KEK_CURRENT (+ optional
        // TOKEN_KEK_PREV) so a key rotation never bricks stored tokens. P4 will build the
        // snapshot ring the same way: buildKekRing(env.SNAPSHOT_KEK_CURRENT ?? env.SNAPSHOT_KEK, env.SNAPSHOT_KEK_PREV).
        const ring = await buildKekRing(tokenKekSecret!, env.TOKEN_KEK_PREV);
        const store = new TokenStore(stub, ring, userId, instanceHost);
        return "Bearer " + (await getServiceNowBearer(cfg, store, Date.now(), credentialMode));
      },
    });
  } else if (devConnected) {
    http = new SnFetchClient({
      instanceHost, allowlist: { allowedHostSuffixes: [...DEFAULT_ALLOWED_HOST_SUFFIXES] },
      getAuthorization: async () => "Basic " + btoa(`${env.SNOW_DEV_ROPC_USERNAME}:${env.SNOW_DEV_ROPC_PASSWORD}`),
    });
  } else {
    http = new NotConnectedHttpClient();
  }

  const reserveDailyBudget = env.BUDGET_DO
    ? async (): Promise<{ ok: boolean; dimension?: string }> => {
        const ns = env.BUDGET_DO!;
        const obj = ns.get(ns.idFromName(utcDateKey())) as unknown as {
          reserve: (req: Record<string, number>) => Promise<{ ok: boolean; dimension?: string }>;
        };
        return obj.reserve({ uniqueWorkers: 1 });
      }
    : undefined;

  // Executor signing (§2.0): host HMAC-signs the actor payload the x_mcp executor verifies.
  const executorReady = Boolean(env.X_MCP_EXECUTOR_HMAC_KEY && env.SNOW_EXECUTOR_PATH);
  const signing = executorReady
    ? {
        claims: {
          mcp_actor_user_id: (auth?.props?.userId as string) ?? "operator",
          mcp_actor_email: (auth?.props?.email as string) ?? "",
          snow_effective_user_sys_id: "",
          instance: instanceHost,
          request_id: crypto.randomUUID(),
        },
        hmacKey: b64ToBytes(env.X_MCP_EXECUTOR_HMAC_KEY!),
        nonce: () => crypto.randomUUID(),
        now: () => Date.now(),
      }
    : undefined;

  const runCodeDeps: RunCodeDeps = {
    loader: env.LOADER,
    scopeMaxMode, // from the client's OAuth scope (§2.0.1)
    tenantMaxMode: "admin_script", // no tenant ceiling configured; scope is the cap
    instanceMaxMode: "admin_script",
    buildRpc: (effectiveMode: Mode, runBudget: RunBudget) =>
      new ServiceNowRPC({
        http, instanceHost, effectiveMode, actorPolicy: policy, runBudget,
        ...(signing ? { signing, executorPath: env.SNOW_EXECUTOR_PATH! } : {}),
      }),
    ...(reserveDailyBudget ? { reserveDailyBudget } : {}),
  };

  function discoveryDeps(): DiscoveryDeps {
    return { http, instanceHost, effectiveMode: "read_only", actorPolicy: policy, runBudget: new RunBudget() };
  }

  // User-aware schema cache (§2.6) when SCHEMA_KV is bound. Keyed by the authenticated
  // user so ACL-filtered field visibility never leaks across users (S6).
  const cache = env.SCHEMA_KV ? new SchemaCache(env.SCHEMA_KV, { instanceHost, userId, roleHash: "default" }) : undefined;

  return {
    runCode: (input) => runCode(input, runCodeDeps),
    describeTable: async ({ table }): Promise<ToolTextResult> => {
      try {
        const fetcher = () => describeTable(discoveryDeps(), table);
        const { fields, cached } = cache ? await cache.describeTable(table, fetcher) : { fields: await fetcher(), cached: false };
        return { content: [{ type: "text", text: JSON.stringify({ table, fields }) }], isError: false, structuredContent: { table, fieldCount: fields.length, cached } };
      } catch (e) {
        return toToolResult(e);
      }
    },
    listTables: async ({ filter }): Promise<ToolTextResult> => {
      try {
        const fetcher = () => listTables(discoveryDeps(), filter);
        const { tables, cached } = cache ? await cache.listTables(filter, fetcher) : { tables: await fetcher(), cached: false };
        return { content: [{ type: "text", text: JSON.stringify({ tables }) }], isError: false, structuredContent: { count: tables.length, cached } };
      } catch (e) {
        return toToolResult(e);
      }
    },
  };
}
