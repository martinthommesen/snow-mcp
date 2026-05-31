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
import { loadActorPolicy, type ActorPolicy, type PolicyEnv } from "../authz/actor-policy.js";
import { McpToolError, toToolResult } from "../sn/errors.js";
import { RunBudget } from "../sn/run-budget.js";
import { BUDGETS, DEFAULT_ALLOWED_HOST_SUFFIXES } from "../config.js";
import { MODE_RISK } from "@servicenow-codemode/shared";
import { SchemaCache, roleHash } from "../cache/schema.js";
import { TokenStore } from "../auth/token-store.js";
import { getServiceNowBearer, preflightAuth, resolveSnPrincipal, type SnOAuthConfig } from "../auth/servicenow-oauth.js";
import { mintTicket } from "../auth/servicenow-ticket.js";
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

export interface HandlerEnv extends PolicyEnv {
  LOADER: WorkerLoader;
  BUDGET_DO?: DurableObjectNamespace;
  // Idempotency ledger (§7.3). Optional HERE BY DESIGN — read-only and test deployments omit it —
  // but the worker `Env` (index.ts) requires it, and a mutation-capable deployment MUST bind it
  // (buildHandlers warns once if absent; L-4). Present in the committed wrangler.jsonc.
  LEDGER_DO?: DurableObjectNamespace;
  SCHEMA_KV?: KVNamespace;
  // Host audit (§7.2) + recovery snapshots (§7.7). AUDIT_KV optional by design (read-only/test);
  // a mutation-capable deployment MUST bind it for audit-before-effect (L-4 warn covers absence).
  AUDIT_KV?: KVNamespace;
  SNAPSHOT_KV?: KVNamespace;
  SNOW_INSTANCE_HOST?: string;
  // Per-user ServiceNow OAuth path (preferred): tokens stored encrypted in TokenStoreDO.
  SNOW_OAUTH_CLIENT_ID?: string;
  SNOW_OAUTH_CLIENT_SECRET?: string;
  TOKEN_DO?: DurableObjectNamespace;
  // Host secret for the per-user OAuth reauth ticket (§6b). Reused (not a new required secret);
  // also the OAuthProvider state secret. Optional: absent + per_user_oauth ⇒ no ticket minted.
  OAUTH_PROVIDER_SECRET?: string;
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
  /** The worker's own public origin (request-derived in apiHandler), used to build the §6b
   *  reauth ticket URL `${origin}/servicenow/authorize?ticket=…`. Absent in non-HTTP callers. */
  workerOrigin?: string;
  /** Hash of the per-user SN principal's roles (§6b) for the SchemaCache identity, so a role
   *  change busts the cache. Computed async in apiHandler (roleHash() is SHA-256; buildHandlers
   *  is sync). Absent ⇒ shared "default" — the role-change cache-bust applies ONLY to
   *  per_user_oauth (integration_user has no per-user principal). */
  roleHash?: string;
}

// L-4: fire the missing-durability warning at most once per isolate (buildHandlers runs per
// request, so an unconditional warn would spam and a hard throw would break read-only/test deploys
// that legitimately omit the ledger/audit bindings).
let warnedMissingDurability = false;

export function buildHandlers(env: HandlerEnv, auth?: AuthContext): ServerHandlers {
  const scopeMaxMode: Mode = auth?.scopeMaxMode ?? "read_only";
  // L-4: a mutation-capable deployment (tenant/instance ceiling above read_only) MUST bind both the
  // idempotency ledger and the durable audit sink; without them, mutations still run (the mandatory
  // runKey gate is independent) but replay-dedup and audit-before-effect silently degrade. Warn
  // once so a misconfigured deploy is detectable. (The committed wrangler.jsonc binds both.)
  if (!warnedMissingDurability) {
    const mutationCapable = parseMaxMode(env.TENANT_MAX_MODE) !== "read_only" && parseMaxMode(env.INSTANCE_MAX_MODE) !== "read_only";
    if (mutationCapable && (!env.LEDGER_DO || !env.AUDIT_KV)) {
      warnedMissingDurability = true;
      console.warn(
        JSON.stringify({
          event: "missing_durability_bindings",
          severity: "warn",
          note: "mutation-capable deployment is missing LEDGER_DO and/or AUDIT_KV; idempotency replay-dedup and/or audit-before-effect are disabled (mutations still gated by the mandatory idempotencyKey).",
          ledger: Boolean(env.LEDGER_DO),
          audit: Boolean(env.AUDIT_KV),
        }),
      );
    }
  }
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
  // §6b: configurable RESTRICTIVE ActorPolicy. NON-BREAKING — with NO policy config set this
  // returns the permissive single-operator policy (live deployment unchanged). When policy vars
  // ARE set it builds a restrictive policy (table allowlist + field masks + row filters + per-run
  // row/byte ceilings) and validates the configured rowFilters at load (fail-closed). The dead
  // maxRowsPerRun/maxBytesPerRun fields now bite via makeRunBudget below under a restrictive policy.
  const policy: ActorPolicy = loadActorPolicy(env, instanceHost);

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

  // §6b reauth ticket: in per_user_oauth, a missing/corrupt token must surface a click-through
  // reauth link (the host-HMAC ticket URL = `${workerOrigin}/servicenow/authorize?ticket=…`).
  // Minting is async + memoized (one per buildHandlers); the ticket carries the userId from the
  // authenticated /mcp request. Absent secret/origin (or integration_user) ⇒ undefined URL (the
  // reauth_required still fires, just without a link). The ticket is short-lived (10 min).
  let authorizeUrlPromise: Promise<string | undefined> | undefined;
  const reauthAuthorizeUrl = (): Promise<string | undefined> => {
    if (credentialMode !== "per_user_oauth" || !auth?.workerOrigin || !env.OAUTH_PROVIDER_SECRET) {
      return Promise.resolve(undefined);
    }
    authorizeUrlPromise ??= (async () => {
      const ticket = await mintTicket(
        { userId, instanceHost, nonce: crypto.randomUUID(), exp: Date.now() + 10 * 60 * 1000 },
        env.OAUTH_PROVIDER_SECRET!,
      );
      return `${auth.workerOrigin}/servicenow/authorize?ticket=${encodeURIComponent(ticket)}`;
    })();
    return authorizeUrlPromise;
  };

  let http: SnHttpClient;
  let oauthStore: (() => Promise<TokenStore>) | undefined;
  let oauthCfg: SnOAuthConfig | undefined;
  if (oauthReady) {
    const stub = env.TOKEN_DO!.get(env.TOKEN_DO!.idFromName(`${userId}|${instanceHost}`)) as unknown as {
      putToken(t: string, v: string): Promise<void>; getToken(t: string): Promise<string | undefined>; revokeAll(): Promise<void>;
    };
    const cfg: SnOAuthConfig = {
      instanceHost, clientId: env.SNOW_OAUTH_CLIENT_ID!, clientSecret: env.SNOW_OAUTH_CLIENT_SECRET!,
      ...(env.SNOW_DEV_ROPC_USERNAME ? { ropcUsername: env.SNOW_DEV_ROPC_USERNAME } : {}),
      ...(env.SNOW_DEV_ROPC_PASSWORD ? { ropcPassword: env.SNOW_DEV_ROPC_PASSWORD } : {}),
    };
    oauthCfg = cfg;
    // Versioned, content-addressed KEK ring (P3): TOKEN_KEK_CURRENT (+ optional TOKEN_KEK_PREV)
    // so a key rotation never bricks stored tokens. Built lazily + reused per call.
    oauthStore = async () => new TokenStore(stub, await buildKekRing(tokenKekSecret!, env.TOKEN_KEK_PREV), userId, instanceHost);
    http = new SnFetchClient({
      instanceHost, allowlist: { allowedHostSuffixes: [...DEFAULT_ALLOWED_HOST_SUFFIXES] },
      getAuthorization: async () => {
        const store = await oauthStore!();
        // per_user_oauth: missing/corrupt token ⇒ reauth_required (+authorizeUrl), never ROPC.
        return "Bearer " + (await getServiceNowBearer(cfg, store, Date.now(), credentialMode, await reauthAuthorizeUrl()));
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

  // §6b — resolve the per-user SN principal's sys_id, lazily, at runServerScript sign time
  // (option (b): the sys_id is consumed ONLY by the signed `snow_effective_user_sys_id` claim,
  // so resolving it here avoids a per-/mcp-request decrypt for reads/writes that never sign).
  // Reads the principal stored alongside the token (persisted by the §6b callback / a prior
  // resolve); if absent, resolves it live with the current bearer and persists it. Only in
  // per_user_oauth — integration_user has no per-user principal (stays "").
  const resolveEffectiveSysId = oauthReady && oauthStore && oauthCfg && credentialMode === "per_user_oauth"
    ? async (): Promise<string> => {
        const store = await oauthStore!();
        const tokens = await store.get("servicenow").catch(() => null);
        if (!tokens) return "";
        if (tokens.sys_id) return tokens.sys_id;
        const principal = await resolveSnPrincipal(oauthCfg!, tokens.access_token);
        if (!principal) return "";
        // Compare-and-merge (P6b-1 FIX 2): re-read immediately before rotate and merge ONLY
        // sys_id/roles onto the LATEST stored value. A concurrent getAuthorization() refresh may
        // have rotated access_token between our read and here; writing back the token we first
        // read would clobber that fresher access_token (last-writer-wins). If the re-read returns
        // null (token revoked mid-flight) we skip the rotate and just return the resolved sys_id.
        const latest = await store.get("servicenow").catch(() => null);
        if (latest) {
          latest.sys_id = principal.sys_id;
          latest.roles = principal.roles;
          await store.rotate("servicenow", latest);
        }
        return principal.sys_id;
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
        // §6b: resolve the effective user's sys_id at sign time (per_user_oauth only).
        ...(resolveEffectiveSysId ? { resolveEffectiveUserSysId: resolveEffectiveSysId } : {}),
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
          // L-2: prefer the intent-stamped dateKey so intent + outcome share a key across a UTC
          // midnight boundary; fall back to the wall-clock date for standalone rows (denials).
          auditKey(record.dateKey ?? utcDateKey(), record.requestId, record.ordinal ?? 0),
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

  // §6b pre-sandbox reauth preflight: in per_user_oauth, short-circuit with host-attested
  // reauth_required (+authorizeUrl) BEFORE the billable Worker when no usable token exists.
  // No-op in integration_user / non-OAuth boots (oauthStore absent).
  const preflightAuthDep = oauthStore
    ? async (): Promise<void> => preflightAuth(await oauthStore!(), credentialMode, await reauthAuthorizeUrl())
    : undefined;

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
    ...(preflightAuthDep ? { preflightAuth: preflightAuthDep } : {}),
    ...(reserveDailyBudget ? { reserveDailyBudget } : {}),
    ...(accrueDailyBudget ? { accrueDailyBudget } : {}),
  };

  function discoveryDeps(): DiscoveryDeps {
    return { http, instanceHost, effectiveMode: "read_only", actorPolicy: policy, runBudget: new RunBudget() };
  }

  // User-aware schema cache (§2.6) when SCHEMA_KV is bound. Keyed by the authenticated user so
  // ACL-filtered field visibility never leaks across users (S6). §6b: the roleHash comes from the
  // per-user SN principal's roles (computed async in apiHandler, threaded via auth.roleHash) so a
  // role change busts the cache; it falls back to the shared "default" in integration_user (no
  // per-user principal) or any non-HTTP caller that did not resolve it.
  const cache = env.SCHEMA_KV
    ? new SchemaCache(env.SCHEMA_KV, { instanceHost, userId, roleHash: auth?.roleHash ?? "default" })
    : undefined;

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

/**
 * Resolve the SchemaCache `roleHash` for a /mcp request (§6b). roleHash() is async (SHA-256) but
 * buildHandlers is sync, so apiHandler computes the hash here and threads it via AuthContext.roleHash.
 *
 * Returns the shared `"default"` (no extra work, no decrypt) UNLESS the deployment is in
 * per_user_oauth mode with the OAuth path fully configured — so the live integration_user
 * deployment is completely untouched (no second TokenStore read). In per_user_oauth this is a
 * second TokenStore decrypt per /mcp request (the price of keeping buildHandlers sync); flagged
 * for the reviewer. BEST-EFFORT: any failure (missing/undecryptable token, no resolved roles)
 * falls back to `"default"` — it NEVER throws, so it cannot block the reauth_required path.
 */
export async function resolveRoleHash(env: HandlerEnv, userId: string): Promise<string> {
  const tokenKekSecret = env.TOKEN_KEK_CURRENT ?? env.TOKEN_KEK;
  const credentialMode = env.SERVICENOW_CREDENTIAL_MODE ?? "integration_user";
  const oauthReady = Boolean(
    env.SNOW_OAUTH_CLIENT_ID && env.SNOW_OAUTH_CLIENT_SECRET && env.TOKEN_DO && tokenKekSecret && env.SNOW_INSTANCE_HOST,
  );
  if (credentialMode !== "per_user_oauth" || !oauthReady) return "default";
  try {
    const instanceHost = canonicalizeInstanceHost(env.SNOW_INSTANCE_HOST!, {
      allowedHostSuffixes: [...DEFAULT_ALLOWED_HOST_SUFFIXES],
    });
    const stub = env.TOKEN_DO!.get(env.TOKEN_DO!.idFromName(`${userId}|${instanceHost}`)) as unknown as {
      putToken(t: string, v: string): Promise<void>; getToken(t: string): Promise<string | undefined>; revokeAll(): Promise<void>;
    };
    const store = new TokenStore(stub, await buildKekRing(tokenKekSecret!, env.TOKEN_KEK_PREV), userId, instanceHost);
    const tokens = await store.get("servicenow").catch(() => null);
    const roles = tokens?.roles;
    if (!roles || roles.length === 0) return "default";
    return await roleHash(roles);
  } catch (e) {
    // Best-effort: a role-hash failure must NEVER block the request (no throw). But a transient
    // TokenStore decrypt/read failure silently stops busting the SchemaCache, so ACL-filtered
    // visibility can go stale for up to the 24h TTL (userId stays in the key — no cross-user
    // leak). Log so a PERSISTENT degrade is observable; the error object only (no token/key data).
    console.error("resolveRoleHash failed; SchemaCache not busted on role change", e);
    return "default";
  }
}
