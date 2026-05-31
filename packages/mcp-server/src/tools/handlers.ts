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
import { canonicalizeInstanceHost } from "../sn/url-allowlist.js";
import { describeTable, listTables, type DiscoveryDeps } from "../sn/discovery.js";
import { permissivePolicy, type ActorPolicy } from "../authz/actor-policy.js";
import { McpToolError, toToolResult } from "../sn/errors.js";
import { RunBudget } from "../sn/run-budget.js";
import { BUDGETS, DEFAULT_ALLOWED_HOST_SUFFIXES } from "../config.js";
import { MODE_RISK } from "@servicenow-codemode/shared";
import { SchemaCache } from "../cache/schema.js";
import { TokenStore } from "../auth/token-store.js";
import { getServiceNowBearer, type SnOAuthConfig } from "../auth/servicenow-oauth.js";
import { buildKekRing } from "../auth/crypto.js";
import type { MutationDeps } from "../sn/rpc.js";
import { auditKey, type RunContext, type AuditIdentity, type LedgerHandle } from "../sn/mutation-guard.js";
import type { AuditRecord } from "../observability/audit.js";
import { takeSnapshot, type SnapshotConfig } from "../recovery/snapshots.js";
import type { ApprovalContext } from "../authz/approval.js";
import type { Mode } from "@servicenow-codemode/shared";

/** Durable-store retention for audit + snapshot KV keys (§7.7/§10): 30 days, auto-expire. */
const RETENTION_TTL_SECONDS = 30 * 24 * 60 * 60;

class NotConnectedHttpClient implements SnHttpClient {
  async request(): Promise<never> {
    throw new McpToolError("reauth_required", "Not connected to ServiceNow — complete OAuth (Phase 1) first.");
  }
}

export interface HandlerEnv {
  LOADER: WorkerLoader;
  BUDGET_DO?: DurableObjectNamespace;
  // Idempotency ledger (§7.3) — declared optional; wired into the mutating path in P4.
  LEDGER_DO?: DurableObjectNamespace;
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
  SNAPSHOT_KEK?: string; // one-release alias for SNAPSHOT_KEK_CURRENT (P3 migration)
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
  // Recovery-snapshot config (§7.7): the snapshot ring uses SNAPSHOT_KEK_CURRENT/_PREV
  // (declared above) via buildKekRing (same scheme as the token ring, P3).
  SNAPSHOT_ENABLED_TABLES?: string; // comma-separated tables that get before/after snapshots.
  SNAPSHOT_OPT_OUT?: string; // "true" disables snapshots for this tenant (claim narrowed).
  // Second-approval policy (§7.9). All optional: when NONE is set the gate is SKIPPED,
  // preserving single-operator behavior. When ANY is set the gate ENFORCES (P4).
  ADMIN_SCRIPT_ALLOWLIST?: string; // comma-separated actor userIds permitted admin_script.
  ADMIN_SCRIPT_APPROVAL_TOKENS?: string; // comma-separated valid approval tokens.
  ADMIN_SCRIPT_REQUIRED_GROUP?: string; // required access-group name (token OR group).
}

function b64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function utcDateKey(): string {
  return new Date().toISOString().slice(0, 10);
}

/**
 * Parse an env-supplied mode ceiling (§P5). An UNSET var defaults to `admin_script` to
 * preserve today's behavior (no tenant/instance ceiling configured → scope is the cap). But a
 * value that IS SET yet is not a valid Mode FAILS CLOSED to `read_only` (the most restrictive
 * ceiling): an operator typo on a security ceiling must visibly lock the instance down, never
 * silently grant the widest access. A minimal, safe membership check; the formal unknown-mode
 * validator lands in P6a (effective-mode.ts).
 */
function parseMaxMode(value: string | undefined): Mode {
  if (value === undefined) return "admin_script"; // unset → scope is the cap (no ceiling configured)
  // OWN-property check (not `in`, which would let prototype keys like "toString" through).
  // Set-but-invalid → fail closed to the most restrictive ceiling (loud operator typo, not silent widen).
  return Object.prototype.hasOwnProperty.call(MODE_RISK, value) ? (value as Mode) : "read_only";
}

export interface AuthContext {
  /** Highest mode the client's OAuth scope permits (auth.props.maxMode, §2.0.1/§2.4). */
  scopeMaxMode: Mode;
  props?: Record<string, unknown>;
}

export function buildHandlers(env: HandlerEnv, auth?: AuthContext): ServerHandlers {
  const scopeMaxMode: Mode = auth?.scopeMaxMode ?? "read_only";
  // Canonicalize + allowlist the configured instance host ONCE here (plan §P6a, finding "OAuth
  // token off-allowlist"), then thread the canonical value to BOTH SnFetchClient AND the
  // SnOAuthConfig. tokenRequest() POSTs https://${instanceHost}/oauth_token.do with the client
  // secret + ROPC creds; sharing the already-allowlisted host means a bad SNOW_INSTANCE_HOST
  // binding can never send credentials off-allowlist. When the host is unset we keep the
  // sentinel (no connection is attempted — devConnected/oauthReady both require the host).
  const instanceHost = env.SNOW_INSTANCE_HOST
    ? canonicalizeInstanceHost(env.SNOW_INSTANCE_HOST, { allowedHostSuffixes: [...DEFAULT_ALLOWED_HOST_SUFFIXES] })
    : "unconfigured.invalid";
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

  // BudgetDO accessor — ONE object per UTC day (global cap; §2.10/§P5). The per-user view is
  // updated in the same input gate by passing `userId` to reserve()/increment().
  const budgetObj = env.BUDGET_DO
    ? () => {
        const ns = env.BUDGET_DO!;
        return ns.get(ns.idFromName(utcDateKey())) as unknown as {
          reserve: (req: Record<string, number>, capOverride?: Record<string, number>, userId?: string) => Promise<{ ok: boolean; dimension?: string }>;
          increment: (req: Record<string, number>, userId?: string) => Promise<void>;
        };
      }
    : undefined;

  // PRE-RUN reserve (§P5 tier 1): reserve a unique Worker AND one ServiceNow request slot,
  // plus the daily rows/bytes ADMISSION check (BudgetDO denies the next run when the day is
  // already over the rows/bytes cap). Per-user tally updated in the same gate via `userId`.
  const reserveDailyBudget = budgetObj
    ? async (): Promise<{ ok: boolean; dimension?: string }> =>
        budgetObj().reserve({ uniqueWorkers: 1, serviceNowRequests: 1 }, undefined, userId)
    : undefined;

  // POST-RUN accrual (§P5 tier 3): fold the per-run actuals into the daily global + per-user
  // counters. Called on every run_code exit path. The dimension names map RunBudget.snapshot()
  // onto BudgetDimension; uniqueWorkers was already reserved pre-run (not re-accrued here).
  const accrueDailyBudget = budgetObj
    ? async (snapshot: Record<string, number>): Promise<void> => {
        await budgetObj().increment(
          {
            sandboxRpcCalls: snapshot.rpcCalls ?? 0,
            // reserveDailyBudget pre-committed serviceNowRequests:1; the snapshot already
            // includes that slot, so accrue only the EXCESS to avoid double-counting (mirrors
            // uniqueWorkers, which is reserved pre-run and excluded from accrual entirely).
            serviceNowRequests: Math.max(0, (snapshot.serviceNowRequests ?? 0) - 1),
            rowsReturned: snapshot.rowsReturned ?? 0,
            bytesReturned: snapshot.bytesReturned ?? 0,
          },
          userId,
        );
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

  // ── Live mutating/executor safety wiring (plan §P4) ──
  // Capture the durable safety layers in closures so the per-call buildRpc can attach them
  // (with the host-authoritative per-run context) to ServiceNowRPC. The audit attribution
  // identity is the authenticated actor (no secrets); snowEffectiveUser is wired in P6b.
  const identity: AuditIdentity = {
    mcpActorUserId: userId,
    ...(auth?.props?.email ? { mcpActorEmail: auth.props.email as string } : {}),
  };

  // Idempotency ledger (§7.3): one DO per (userId|instanceHost|runKey:ordinal).
  const ledgerFactory = env.LEDGER_DO
    ? (runKey: string) =>
        (ordinal: number): LedgerHandle => {
          const ns = env.LEDGER_DO!;
          return ns.get(ns.idFromName(`${userId}|${instanceHost}|${runKey}:${ordinal}`)) as unknown as LedgerHandle;
        }
    : undefined;

  // Durable host audit (§7.2): AUDIT_KV, keyed `${utcDateKey}/${requestId}/${ordinal}` so
  // each mutation/denial gets its own key (intent then result for one ordinal share the key,
  // so the result row supersedes the intent — "audit-before-effect then update"). 30-day
  // auto-expiry: KV expires the key, so no separate purge job is needed here.
  const auditSink = env.AUDIT_KV
    ? async (record: AuditRecord): Promise<void> => {
        await env.AUDIT_KV!.put(
          auditKey(utcDateKey(), record.requestId, record.ordinal ?? 0),
          JSON.stringify(record),
          { expirationTtl: RETENTION_TTL_SECONDS },
        );
      }
    : undefined;

  // Recovery snapshots (§7.7): encrypt under the SNAPSHOT_KEK ring (same buildKekRing scheme
  // as the token ring, P3) and persist to SNAPSHOT_KV with a 30-day TTL. Honor the tenant
  // opt-out (no enabled tables => no snapshots, recovery claim narrowed). The integration
  // user never decrypts (the KEK lives only host-side). The ring is built lazily + cached.
  const snapshotKekSecret = env.SNAPSHOT_KEK_CURRENT ?? env.SNAPSHOT_KEK;
  const snapshotEnabledTables = (env.SNAPSHOT_ENABLED_TABLES ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const snapshotReady = Boolean(env.SNAPSHOT_KV && snapshotKekSecret && snapshotEnabledTables.length > 0);
  const snapshotConfig: SnapshotConfig = { enabledTables: snapshotEnabledTables, retentionMs: RETENTION_TTL_SECONDS * 1000 };
  let snapshotRing: Promise<Awaited<ReturnType<typeof buildKekRing>>> | undefined;
  const captureSnapshot = snapshotReady
    ? async (input: {
        requestId: string; ordinal: number; table: string; sysId: string;
        before: Record<string, unknown>; after: Record<string, unknown>; takenAt: number;
      }): Promise<boolean> => {
        snapshotRing ??= buildKekRing(snapshotKekSecret!, env.SNAPSHOT_KEK_PREV);
        const ring = await snapshotRing;
        const snap = await takeSnapshot(snapshotConfig, ring, {
          table: input.table, sysId: input.sysId, takenAt: input.takenAt,
          before: input.before, after: input.after,
        });
        if (!snap) return false; // table opted out — recovery claim narrowed.
        await env.SNAPSHOT_KV!.put(
          `${input.requestId}/${input.ordinal}/${input.table}/${input.sysId}`,
          JSON.stringify(snap),
          { expirationTtl: RETENTION_TTL_SECONDS },
        );
        return true;
      }
    : undefined;

  // Second-approval policy (§7.9): present ONLY when a tenant configures it. When none of
  // the three knobs is set the gate is SKIPPED (single-operator default keeps working);
  // when ANY is set it ENFORCES (admin_script without a valid token/group is denied).
  const adminScriptAllowlist = (env.ADMIN_SCRIPT_ALLOWLIST ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const validApprovalTokens = (env.ADMIN_SCRIPT_APPROVAL_TOKENS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const requiredAccessGroup = env.ADMIN_SCRIPT_REQUIRED_GROUP?.trim();
  const approvalConfigured = adminScriptAllowlist.length > 0 || validApprovalTokens.length > 0 || Boolean(requiredAccessGroup);
  const approval: Omit<ApprovalContext, "mode" | "actorUserId" | "reason"> | undefined = approvalConfigured
    ? {
        adminScriptAllowlist,
        ...(validApprovalTokens.length > 0 ? { validApprovalTokens: new Set(validApprovalTokens) } : {}),
        ...(requiredAccessGroup ? { requiredAccessGroup } : {}),
        ...(auth?.props?.accessGroups ? { actorAccessGroups: auth.props.accessGroups as string[] } : {}),
      }
    : undefined;

  function buildMutationDeps(runContext: RunContext): MutationDeps {
    return {
      runContext,
      identity,
      now: () => Date.now(),
      ...(ledgerFactory && runContext.runKey ? { ledger: ledgerFactory(runContext.runKey) } : {}),
      ...(auditSink ? { audit: auditSink } : {}),
      ...(captureSnapshot ? { captureSnapshot, snapshotEnabledTables } : {}),
      ...(approval ? { approval } : {}),
    };
  }

  const runCodeDeps: RunCodeDeps = {
    loader: env.LOADER,
    scopeMaxMode, // from the client's OAuth scope (§2.0.1)
    // Mode ceilings (§P5): env-configurable. UNSET defaults to admin_script (preserves today's
    // "scope is the cap" behavior); a SET-but-invalid value fails closed to read_only — never
    // widens the ceiling (parseMaxMode).
    tenantMaxMode: parseMaxMode(env.TENANT_MAX_MODE),
    instanceMaxMode: parseMaxMode(env.INSTANCE_MAX_MODE),
    // Per-run budget meter carrying the actor's row/byte caps (§P5). The dead
    // maxRowsPerRun/maxBytesPerRun policy fields now BITE here (permissivePolicy =
    // MAX_SAFE_INTEGER, so they only bite under a restrictive policy — P6b).
    makeRunBudget: () => new RunBudget(BUDGETS.perRun, { maxRows: policy.maxRowsPerRun, maxBytes: policy.maxBytesPerRun }),
    buildRpc: (effectiveMode: Mode, runBudget: RunBudget, runContext: RunContext) =>
      new ServiceNowRPC({
        http, instanceHost, effectiveMode, actorPolicy: policy, runBudget,
        ...(signing ? { signing, executorPath: env.SNOW_EXECUTOR_PATH! } : {}),
        mutation: buildMutationDeps(runContext),
      }),
    ...(reserveDailyBudget ? { reserveDailyBudget } : {}),
    ...(accrueDailyBudget ? { accrueDailyBudget } : {}),
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
