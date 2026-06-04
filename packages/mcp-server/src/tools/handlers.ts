// Builds the injected ServerHandlers (plan §3.2).
//
// Two modes:
//  - CONNECTED path: run_code reaches the real instance via ServiceNowRPC and
//    describe_table/list_tables use the discovery module. ServiceNow credentials
//    come from per-user OAuth or the explicit dev ROPC path.
//  - NOT-CONNECTED: fail closed with `reauth_required` until creds exist.

import type { ServerHandlers, ToolTextResult } from "../server.js";
import { runCode, type RunCodeDeps } from "./run_code.js";
import { ServiceNowRPC } from "../sn/rpc.js";
import { SnFetchClient, type SnHttpClient } from "../sn/http.js";
import { canonicalizeInstanceHost, type InstanceAllowlist } from "../sn/url-allowlist.js";
import { describeTable, listTables, type DiscoveryDeps } from "../sn/discovery.js";
import {
  actorPolicyHash,
  denyAllPolicy,
  loadNamedActorPolicies,
  type ActorPolicy,
  type PolicyEnv,
} from "../authz/actor-policy.js";
import { McpToolError, toToolResult } from "../sn/errors.js";
import { RunBudget } from "../sn/run-budget.js";
import { BUDGETS, DEFAULT_ALLOWED_HOST_SUFFIXES } from "../config.js";
import { SchemaCache, roleHash, type SchemaCachePrincipalIdentity } from "../cache/schema.js";
import { TokenStore } from "../auth/token-store.js";
import {
  getServiceNowBearer,
  preflightAuth,
  resolveFreshStoredSnPrincipal,
  resolveStoredSnPrincipal,
  type CredentialMode,
  type SnOAuthConfig,
} from "../auth/servicenow-oauth.js";
import { mintTicket, normalizeIdentityEmail } from "../auth/servicenow-ticket.js";
import { buildKekRing, warnIfWeakSecretOnce } from "../auth/crypto.js";
import { decodeFixedBase64Secret } from "../auth/encoding.js";
import type { MutationDeps } from "../sn/rpc.js";
import { auditKey, mutationLedgerObjectName, type RunContext, type AuditIdentity, type LedgerHandle } from "../sn/mutation-guard.js";
import type { AuditRecord } from "../observability/audit.js";
import { takeSnapshot, type SnapshotConfig } from "../recovery/snapshots.js";
import type { ApprovalContext } from "../authz/approval.js";
import type { Mode } from "@servicenow-codemode/shared";
import { parseMaxMode } from "../authz/effective-mode.js";

/** Durable-store retention for audit + snapshot KV keys (§7.7/§10): 30 days, auto-expire. */
const RETENTION_TTL_SECONDS = 30 * 24 * 60 * 60;

class NotConnectedHttpClient implements SnHttpClient {
  constructor(private readonly message = "Not connected to ServiceNow — complete OAuth (Phase 1) first.") {}

  async request(): Promise<never> {
    throw new McpToolError("reauth_required", this.message);
  }
}

export interface HandlerEnv extends PolicyEnv {
  LOADER: WorkerLoader;
  BUDGET_DO?: DurableObjectNamespace;
  // Idempotency ledger (§7.3). Optional at the env type boundary for read-only/test boots; live
  // mutating/executor calls fail closed if it is absent.
  LEDGER_DO?: DurableObjectNamespace;
  SCHEMA_KV?: KVNamespace;
  // Host audit (§7.2) + recovery snapshots (§7.7). AUDIT_KV is optional at boot, but required
  // before live mutation effects.
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
  // Versioned KEK ring (P3): current + optional previous, for token + snapshot stores.
  TOKEN_KEK_CURRENT?: string;
  TOKEN_KEK_PREV?: string;
  SNAPSHOT_KEK_CURRENT?: string;
  SNAPSHOT_KEK_PREV?: string;
  // Credential mode (P6) + mode ceilings (P5).
  SERVICENOW_CREDENTIAL_MODE?: string;
  DEPLOYMENT_PROFILE?: string;
  TENANT_MAX_MODE?: Mode;
  INSTANCE_MAX_MODE?: Mode;
  // Dev Basic-Auth/ROPC path, enabled only by explicit SNOW_DEV_ROPC=1.
  SNOW_DEV_ROPC?: string;
  SNOW_DEV_ROPC_USERNAME?: string;
  SNOW_DEV_ROPC_PASSWORD?: string;
  // Executor (runServerScript / admin_script): HMAC signing key + endpoint path (§2.0, §5.6).
  X_MCP_EXECUTOR_HMAC_KEY?: string;
  SNOW_EXECUTOR_PATH?: string;
  // Recovery-snapshot config (§7.7): the snapshot ring uses SNAPSHOT_KEK_CURRENT/_PREV
  // (declared above) via buildKekRing (same scheme as the token ring, P3).
  SNAPSHOT_ENABLED_TABLES?: string; // comma-separated tables that get before/after snapshots.
  // Second-approval policy (§7.9). admin_script is DEFAULT-DENY (P4, assertAdminScriptApproved):
  // an empty/unset ADMIN_SCRIPT_ALLOWLIST denies every admin_script request, so a live
  // deployment must set it to permit specific actors. ADMIN_SCRIPT_APPROVAL_TOKENS /
  // ADMIN_SCRIPT_REQUIRED_GROUP are the optional SECOND factor (token OR group) layered on top.
  // (read_only / write are unaffected.)
  ADMIN_SCRIPT_ALLOWLIST?: string; // comma-separated actor userIds permitted admin_script.
  ADMIN_SCRIPT_APPROVAL_TOKENS?: string; // comma-separated valid approval tokens.
  ADMIN_SCRIPT_REQUIRED_GROUP?: string; // required access-group name (token OR group).
  MCP_OPERATOR_ACCESS_GROUPS?: string; // current operator groups for group-based second approval.
}

function csv(value: string | undefined): string[] {
  return (value ?? "").split(",").map((s) => s.trim()).filter(Boolean);
}

function stringArrayProp(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string" && v.trim() !== "") : [];
}

function utcDateKey(): string {
  return new Date().toISOString().slice(0, 10);
}

type ParsedCredentialMode = CredentialMode | "invalid";

function parseCredentialMode(value: string | undefined): ParsedCredentialMode {
  if (value === undefined || value.trim() === "") return "invalid";
  if (value === "integration_user" || value === "per_user_oauth") return value;
  return "invalid";
}

function selectedCredentialMode(value: ParsedCredentialMode): CredentialMode | undefined {
  return value === "invalid" ? undefined : value;
}

const defaultInstanceAllowlist = { allowedHostSuffixes: DEFAULT_ALLOWED_HOST_SUFFIXES } satisfies InstanceAllowlist;

function instanceAllowlistForProfile(env: Pick<HandlerEnv, "DEPLOYMENT_PROFILE">, instanceHost: string): InstanceAllowlist {
  return env.DEPLOYMENT_PROFILE === "production"
    ? { allowedHostSuffixes: [instanceHost] }
    : defaultInstanceAllowlist;
}

export interface AuthContext {
  /** Authenticated MCP actor identity, validated once by apiHandler. */
  userId: string;
  /** Highest mode the client's OAuth scope permits (auth.props.maxMode, §2.0.1/§2.4). */
  scopeMaxMode: Mode;
  props: Record<string, unknown>;
  /** The worker's configured public origin, used to build the §6b reauth ticket URL
   *  `${origin}/servicenow/authorize?ticket=…`. Required for per_user_oauth. */
  workerOrigin?: string;
  /** ServiceNow principal identity for the SchemaCache key (§6b). */
  schemaIdentity?: SchemaCachePrincipalIdentity;
  /** Lazy schema identity resolver. Non-schema calls should not pay a TokenStore read. */
  schemaIdentityResolver?: () => Promise<SchemaCachePrincipalIdentity | undefined>;
  /** Lazy, zero-network resolver used to check SchemaCache hits before spending discovery budget. */
  schemaIdentityFreshResolver?: () => Promise<SchemaCachePrincipalIdentity | undefined>;
}

export function buildHandlers(env: HandlerEnv, auth: AuthContext): ServerHandlers {
  const scopeMaxMode: Mode = auth.scopeMaxMode;
  // M-1a: OAUTH_PROVIDER_SECRET is the reauth-ticket HMAC key (auth/servicenow-ticket.ts),
  // derived unsalted like the KEK — warn if it is not CSPRNG-strong, matching the KEK guard.
  // buildHandlers runs per-request, so the warning is deduped to once-per-isolate.
  if (env.OAUTH_PROVIDER_SECRET) warnIfWeakSecretOnce("OAUTH_PROVIDER_SECRET", env.OAUTH_PROVIDER_SECRET);
  // Canonicalize + allowlist the configured instance host ONCE here (plan §P6a, finding "OAuth
  // token off-allowlist"), then thread the canonical value to BOTH SnFetchClient AND the
  // SnOAuthConfig. tokenRequest() POSTs https://${instanceHost}/oauth_token.do with the client
  // secret + ROPC creds; sharing the already-allowlisted host means a bad SNOW_INSTANCE_HOST
  // binding can never send credentials off-allowlist. When the host is unset we keep the
  // sentinel (no connection is attempted — devConnected/oauthReady both require the host).
  const instanceHost = env.SNOW_INSTANCE_HOST
    ? canonicalizeInstanceHost(env.SNOW_INSTANCE_HOST, defaultInstanceAllowlist)
    : "unconfigured.invalid";
  const instanceAllowlist = instanceAllowlistForProfile(env, instanceHost);
  const userId = auth.userId;
  // §6b: configurable restrictive ActorPolicy. With no policy config the default policy denies
  // all tables; configured policies add allowlists, masks, row filters, and per-run ceilings.
  const actorPolicies = loadNamedActorPolicies(env, instanceHost);
  const requestedPolicyName = typeof auth.props.actorPolicyName === "string" ? auth.props.actorPolicyName : "default";
  const selectedPolicy = actorPolicies.get(requestedPolicyName);
  if (!selectedPolicy) {
    console.warn(JSON.stringify({
      event: "actor_policy_missing",
      requestedPolicyName,
      userId,
      availablePolicyNames: [...actorPolicies.keys()],
    }));
  }
  const policy: ActorPolicy = selectedPolicy ?? denyAllPolicy(instanceHost);
  const actorEmail = normalizeIdentityEmail(auth.props.email);

  // Authorization header strategy (preference order):
  //  1. Per-user ServiceNow OAuth Bearer — tokens minted/refreshed and stored encrypted in
  //     TokenStoreDO (§2.7, §7.5). Preferred.
  //  2. Explicit dev Basic-Auth/ROPC path (SNOW_DEV_ROPC=1).
  //  3. Not connected -> fail closed.
  const tokenKekSecret = env.TOKEN_KEK_CURRENT;
  const credentialMode = parseCredentialMode(env.SERVICENOW_CREDENTIAL_MODE);
  const serviceNowCredentialMode = selectedCredentialMode(credentialMode);
  const devRopcEnabled = env.SNOW_DEV_ROPC === "1";
  const oauthReady = Boolean(env.SNOW_OAUTH_CLIENT_ID && env.SNOW_OAUTH_CLIENT_SECRET && env.TOKEN_DO && tokenKekSecret && env.SNOW_INSTANCE_HOST && (credentialMode !== "per_user_oauth" || auth.workerOrigin));
  const devConnected = Boolean(devRopcEnabled && env.SNOW_INSTANCE_HOST && env.SNOW_DEV_ROPC_USERNAME && env.SNOW_DEV_ROPC_PASSWORD);

  // §6b reauth ticket: in per_user_oauth, a missing/corrupt token must surface a click-through
  // reauth link (the host-HMAC ticket URL = `${workerOrigin}/servicenow/authorize?ticket=…`).
  // Minting is async + memoized (one per buildHandlers); the ticket carries the userId from the
  // authenticated /mcp request. Absent secret (or integration_user) ⇒ undefined URL (the
  // reauth_required still fires, just without a link). Missing origin is a per_user_oauth
  // configuration error handled before this helper. The ticket is short-lived (10 min).
  let http: SnHttpClient;
  let oauthStore: (() => Promise<TokenStore>) | undefined;
  let oauthCfg: SnOAuthConfig | undefined;
  let requestAuthorization: (() => Promise<string>) | undefined;
  let perUserConfigurationError: string | undefined;
  let authorizeUrlPromise: Promise<string | undefined> | undefined;
  const reauthAuthorizeUrl = (): Promise<string | undefined> => {
    if (credentialMode !== "per_user_oauth" || !auth.workerOrigin || !env.OAUTH_PROVIDER_SECRET) {
      return Promise.resolve(undefined);
    }
    authorizeUrlPromise ??= (async () => {
      const existing = oauthStore ? await (await oauthStore()).get("servicenow").catch(() => null) : null;
      if (!actorEmail && !existing?.sys_id) return undefined;
      const ticket = await mintTicket(
        {
          userId,
          ...(actorEmail ? { actorEmail } : {}),
          instanceHost,
          nonce: crypto.randomUUID(),
          ...(existing?.sys_id ? { expectedSnSysId: existing.sys_id } : {}),
          exp: Date.now() + 10 * 60 * 1000,
        },
        env.OAUTH_PROVIDER_SECRET!,
      );
      return `${auth.workerOrigin}/servicenow/authorize?ticket=${encodeURIComponent(ticket)}`;
    })();
    return authorizeUrlPromise;
  };

  if (credentialMode === "invalid") {
    http = new NotConnectedHttpClient("Invalid SERVICENOW_CREDENTIAL_MODE; expected integration_user or per_user_oauth.");
  } else if (credentialMode === "per_user_oauth" && !auth.workerOrigin) {
    perUserConfigurationError = "SERVICENOW_CREDENTIAL_MODE=per_user_oauth requires WORKER_PUBLIC_ORIGIN.";
    http = new NotConnectedHttpClient(perUserConfigurationError);
  } else if (credentialMode === "per_user_oauth" && !oauthReady) {
    perUserConfigurationError = "SERVICENOW_CREDENTIAL_MODE=per_user_oauth is not fully configured; complete OAuth bindings before use.";
    http = new NotConnectedHttpClient(perUserConfigurationError);
  } else if (oauthReady) {
    const stub = env.TOKEN_DO!.get(env.TOKEN_DO!.idFromName(`${userId}|${instanceHost}`)) as unknown as {
      putToken(t: string, v: string): Promise<void>; getToken(t: string): Promise<string | undefined>;
    };
    const cfg: SnOAuthConfig = {
      instanceHost, clientId: env.SNOW_OAUTH_CLIENT_ID!, clientSecret: env.SNOW_OAUTH_CLIENT_SECRET!,
      ...(devRopcEnabled && env.SNOW_DEV_ROPC_USERNAME ? { ropcUsername: env.SNOW_DEV_ROPC_USERNAME } : {}),
      ...(devRopcEnabled && env.SNOW_DEV_ROPC_PASSWORD ? { ropcPassword: env.SNOW_DEV_ROPC_PASSWORD } : {}),
    };
    oauthCfg = cfg;
    // Versioned, content-addressed KEK ring (P3): TOKEN_KEK_CURRENT (+ optional TOKEN_KEK_PREV)
    // so a key rotation never bricks stored tokens. Built lazily and memoized per buildHandlers
    // call so preflight, getAuthorization, and effective-principal resolution share one store.
    let ringPromise: Promise<Awaited<ReturnType<typeof buildKekRing>>> | undefined;
    let storePromise: Promise<TokenStore> | undefined;
    oauthStore = () => {
      ringPromise ??= buildKekRing(tokenKekSecret!, env.TOKEN_KEK_PREV);
      storePromise ??= ringPromise.then((ring) => new TokenStore(stub, ring, userId, instanceHost));
      return storePromise;
    };
    let authorizationPromise: Promise<string> | undefined;
    requestAuthorization = (): Promise<string> => {
      authorizationPromise ??= (async () => {
        const store = await oauthStore!();
        return "Bearer " + (await getServiceNowBearer(cfg, store, Date.now(), serviceNowCredentialMode!, await reauthAuthorizeUrl()));
      })();
      return authorizationPromise;
    };
    http = new SnFetchClient({
      instanceHost, allowlist: instanceAllowlist,
      // Request-local cache: one buildHandlers instance serves one authenticated /mcp request, so
      // every ServiceNow call in that request can reuse the same decrypted/refreshed bearer.
      getAuthorization: requestAuthorization,
    });
  } else if (devConnected) {
    http = new SnFetchClient({
      instanceHost, allowlist: instanceAllowlist,
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
          reconcile: (delta: Record<string, number>, userId?: string) => Promise<void>;
        };
      }
    : undefined;

  // PRE-RUN reserve (§P5 tier 1 / finding 5): reserve a unique Worker AND the PER-RUN MAXIMUMS
  // for dimensions a single run can spend many of (serviceNowRequests, sandboxRpcCalls,
  // outboundBytesSent),
  // so concurrent runs admission-check at the true ceiling and cannot collectively overshoot the
  // daily cap. Also runs the daily rows/bytes/sandboxRpcCalls ADMISSION check (deny-next-run when
  // already at/over cap). Per-user tally updated in the same gate via `userId`. The unused
  // reservation is refunded post-run by reconcileDailyBudget.
  const reserveDailyBudget = budgetObj
    ? async (): Promise<{ ok: boolean; dimension?: string }> =>
        budgetObj().reserve(
          {
            uniqueWorkers: 1,
            serviceNowRequests: BUDGETS.perRun.serviceNowRequestLimit,
            sandboxRpcCalls: BUDGETS.perRun.rpcCallLimit,
            outboundBytesSent: BUDGETS.perRun.maxOutboundBytes,
          },
          undefined,
          userId,
        )
    : undefined;

  // POST-RUN reconcile (§P5 tier 3 / finding 5): fold the per-run actuals into the daily global +
  // per-user counters by REFUNDING the unused reservation. Reserved dimensions get a negative
  // delta (actual − reserved); the unreserved rows/bytes get a positive accrual. `snapshot` is
  // undefined on a post-reserve early exit (transpile failure) — nothing was spent, so the full
  // reservation is refunded. uniqueWorkers stays reserved (not reconciled).
  const reconcileDailyBudget = budgetObj
    ? async (snapshot?: Record<string, number>): Promise<void> => {
        await budgetObj().reconcile(
          {
            serviceNowRequests: (snapshot?.serviceNowRequests ?? 0) - BUDGETS.perRun.serviceNowRequestLimit,
            sandboxRpcCalls: (snapshot?.rpcCalls ?? 0) - BUDGETS.perRun.rpcCallLimit,
            rowsReturned: snapshot?.rowsReturned ?? 0,
            bytesReturned: snapshot?.bytesReturned ?? 0,
            outboundBytesSent: (snapshot?.outboundBytesSent ?? 0) - BUDGETS.perRun.maxOutboundBytes,
          },
          userId,
        );
      }
    : undefined;

  const reserveDiscoveryDailyBudget = budgetObj
    ? async (): Promise<{ ok: boolean; dimension?: string }> =>
        budgetObj().reserve(
          {
            serviceNowRequests: BUDGETS.perRun.serviceNowRequestLimit,
            outboundBytesSent: BUDGETS.perRun.maxOutboundBytes,
          },
          undefined,
          userId,
        )
    : undefined;

  const reconcileDiscoveryDailyBudget = budgetObj
    ? async (snapshot: Record<string, number>): Promise<void> => {
        await budgetObj().reconcile(
          {
            serviceNowRequests: (snapshot.serviceNowRequests ?? 0) - BUDGETS.perRun.serviceNowRequestLimit,
            rowsReturned: snapshot.rowsReturned ?? 0,
            bytesReturned: snapshot.bytesReturned ?? 0,
            outboundBytesSent: (snapshot.outboundBytesSent ?? 0) - BUDGETS.perRun.maxOutboundBytes,
          },
          userId,
        );
      }
    : undefined;

  // §6b — resolve the per-user SN principal's sys_id, lazily, at runServerScript sign time
  // (option (b): the sys_id is consumed ONLY by the signed `snow_effective_user_sys_id` claim,
  // so resolving it here avoids a per-/mcp-request decrypt for reads/writes that never sign).
  // Reads the principal stored alongside the token (persisted by the §6b callback / a prior
  // resolve); if absent or stale, resolves it live with the current bearer and persists it. Only
  // in per_user_oauth — integration_user has no per-user principal (stays "").
  const resolveEffectiveSysId = oauthReady && oauthStore && oauthCfg && credentialMode === "per_user_oauth"
    ? async (): Promise<string> => {
        const store = await oauthStore!();
        const authorization = requestAuthorization ? await requestAuthorization() : "";
        const principal = await resolveStoredSnPrincipal(oauthCfg!, store, Date.now(), {
          accessToken: authorization.replace(/^Bearer\s+/i, ""),
        });
        return principal?.sys_id ?? "";
      }
    : undefined;

  // Executor signing (§2.0): host HMAC-signs the actor payload the x_mcp executor verifies.
  const executorReady = Boolean(env.X_MCP_EXECUTOR_HMAC_KEY && env.SNOW_EXECUTOR_PATH);
  const signing = executorReady
    ? {
        claims: {
          mcp_actor_user_id: userId,
          mcp_actor_email: (auth.props.email as string) ?? "",
          snow_effective_user_sys_id: "",
          instance: instanceHost,
          request_id: crypto.randomUUID(),
        },
        hmacKey: decodeFixedBase64Secret("X_MCP_EXECUTOR_HMAC_KEY", env.X_MCP_EXECUTOR_HMAC_KEY!, 32),
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
    ...(auth.props.email ? { mcpActorEmail: auth.props.email as string } : {}),
  };

  // Idempotency ledger (§7.3): one DO per (userId|instanceHost|version:runKey:ordinal).
  const ledgerFactory = env.LEDGER_DO
    ? (runKey: string) =>
        (ordinal: number): LedgerHandle => {
          const ns = env.LEDGER_DO!;
          return ns.get(ns.idFromName(mutationLedgerObjectName({ userId, instanceHost, runKey, ordinal }))) as unknown as LedgerHandle;
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

  // Recovery snapshots (§7.7): encrypt under the SNAPSHOT_KEK_CURRENT ring (same buildKekRing scheme
  // as the token ring, P3) and persist to SNAPSHOT_KV with a 30-day TTL. No enabled tables means
  // no snapshots, so the recovery claim is narrowed. The integration user never decrypts
  // (the KEK lives only host-side). The ring is built lazily + cached.
  const snapshotKekSecret = env.SNAPSHOT_KEK_CURRENT;
  const snapshotEnabledTables = csv(env.SNAPSHOT_ENABLED_TABLES);
  const snapshotReady = Boolean(env.SNAPSHOT_KV && snapshotKekSecret && snapshotEnabledTables.length > 0);
  const snapshotConfig: SnapshotConfig = { enabledTables: snapshotEnabledTables };
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

  // Second-approval policy (§7.9): empty/unconfigured means default-deny for admin_script.
  // A request passes only when the actor is allowlisted and has either a valid approval token
  // or the current required access-group membership.
  const adminScriptAllowlist = csv(env.ADMIN_SCRIPT_ALLOWLIST);
  const validApprovalTokens = csv(env.ADMIN_SCRIPT_APPROVAL_TOKENS);
  const requiredAccessGroup = env.ADMIN_SCRIPT_REQUIRED_GROUP?.trim();
  // Current env only for operator-secret auth; in OIDC, group membership must come from the
  // current IdP-derived grant props, never the static operator-secret binding.
  const actorAccessGroups = auth.props.authMode === "oidc"
    ? stringArrayProp(auth.props.oidcGroups)
    : csv(env.MCP_OPERATOR_ACCESS_GROUPS);
  const approval: Omit<ApprovalContext, "mode" | "actorUserId" | "reason"> = {
    adminScriptAllowlist,
    ...(validApprovalTokens.length > 0 ? { validApprovalTokens: new Set(validApprovalTokens) } : {}),
    ...(requiredAccessGroup ? { requiredAccessGroup } : {}),
    ...(actorAccessGroups.length > 0 ? { actorAccessGroups } : {}),
  };

  function buildMutationDeps(runContext: RunContext): MutationDeps {
    return {
      runContext,
      identity,
      now: () => Date.now(),
      durabilityRequired: true,
      ...(ledgerFactory && runContext.runKey ? { ledger: ledgerFactory(runContext.runKey) } : {}),
      ...(auditSink ? { audit: auditSink } : {}),
      ...(captureSnapshot ? { captureSnapshot, snapshotEnabledTables } : {}),
      approval,
    };
  }

  // §6b pre-sandbox reauth preflight: in per_user_oauth, short-circuit with host-attested
  // reauth_required (+authorizeUrl) BEFORE the billable Worker when no usable token exists.
  // No-op in integration_user / non-OAuth boots (oauthStore absent).
  const preflightAuthDep = perUserConfigurationError
    ? async (): Promise<never> => { throw new McpToolError("reauth_required", perUserConfigurationError); }
    : oauthStore
    ? async (): Promise<void> => preflightAuth(await oauthStore!(), serviceNowCredentialMode!, await reauthAuthorizeUrl())
    : undefined;

  const runCodeDeps: RunCodeDeps = {
    loader: env.LOADER,
    scopeMaxMode, // from the client's OAuth scope (§2.0.1)
    // Mode ceilings (§P5): env-configurable. UNSET leaves the OAuth scope as the cap; a
    // SET-but-invalid value fails closed to read_only and never widens the ceiling.
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
    ...(reconcileDailyBudget ? { reconcileDailyBudget } : {}),
  };

  function makeDiscoveryRunBudget(): RunBudget {
    return new RunBudget(BUDGETS.perRun, { maxRows: policy.maxRowsPerRun, maxBytes: policy.maxBytesPerRun });
  }

  function discoveryDeps(runBudget: RunBudget): DiscoveryDeps {
    return { http, instanceHost, effectiveMode: "read_only", actorPolicy: policy, runBudget, credentialMode: serviceNowCredentialMode };
  }

  async function runDiscoveryWithBudget<T>(runBudget: RunBudget, fn: () => Promise<T>): Promise<T> {
    if (reserveDiscoveryDailyBudget && preflightAuthDep) {
      await preflightAuthDep();
    } else if (!requestAuthorization && http instanceof NotConnectedHttpClient) {
      await http.request();
    }
    let reserved = false;
    if (reserveDiscoveryDailyBudget) {
      const reservation = await reserveDiscoveryDailyBudget();
      if (!reservation.ok) {
        throw new McpToolError("budget_exceeded", `Daily ${reservation.dimension ?? "budget"} cap exhausted.`, {
          dimension: reservation.dimension,
        });
      }
      reserved = true;
    }
    try {
      if (requestAuthorization) {
        await requestAuthorization();
      }
      return await fn();
    } finally {
      if (reserved && reconcileDiscoveryDailyBudget) {
        try {
          await reconcileDiscoveryDailyBudget(runBudget.snapshot());
        } catch (e) {
          console.error(
            JSON.stringify({
              event: "discovery_budget_reconcile_failed",
              severity: "alert",
              note: "daily discovery reservation not refunded; serviceNowRequests/outboundBytesSent over-count and rows/bytes may be under-accrued until BUDGET_DO recovers",
              error: e instanceof Error ? e.message : String(e),
            }),
          );
        }
      }
    }
  }

  // User-aware schema cache (§2.6) when SCHEMA_KV is bound. Built lazily so run_code and other
  // non-schema calls do not pay a per-user TokenStore read/decrypt just to compute identity.
  // In per_user_oauth the resolver must return the ServiceNow sys_id; if it cannot, we skip cache
  // for this request rather than keying ACL-filtered schema under the wrong identity.
  let schemaCachePromise: Promise<SchemaCache | undefined> | undefined;
  let freshSchemaCachePromise: Promise<SchemaCache | undefined> | undefined;
  async function schemaCacheIdentity(freshOnly: boolean): Promise<SchemaCachePrincipalIdentity | undefined> {
    if (auth.schemaIdentity) return auth.schemaIdentity;
    if (freshOnly) {
      if (auth.schemaIdentityFreshResolver) return auth.schemaIdentityFreshResolver();
      return auth.schemaIdentityResolver ? undefined : { principalId: userId, roleHash: "default" };
    }
    return auth.schemaIdentityResolver ? auth.schemaIdentityResolver() : { principalId: userId, roleHash: "default" };
  }
  async function buildSchemaCache(freshOnly: boolean): Promise<SchemaCache | undefined> {
    if (!env.SCHEMA_KV) return undefined;
    const identity = await schemaCacheIdentity(freshOnly);
    return identity ? new SchemaCache(env.SCHEMA_KV!, { instanceHost, ...identity, policyHash: await actorPolicyHash(policy) }) : undefined;
  }
  async function buildFreshSchemaCache(): Promise<SchemaCache | undefined> {
    const pending = buildSchemaCache(true);
    freshSchemaCachePromise = pending;
    try {
      const cache = await pending;
      if (!cache && freshSchemaCachePromise === pending) freshSchemaCachePromise = undefined;
      return cache;
    } catch (e) {
      if (freshSchemaCachePromise === pending) freshSchemaCachePromise = undefined;
      throw e;
    }
  }
  const schemaCache = (opts: { freshOnly?: boolean } = {}): Promise<SchemaCache | undefined> => {
    if (opts.freshOnly) {
      return freshSchemaCachePromise ?? buildFreshSchemaCache();
    }
    schemaCachePromise ??= buildSchemaCache(false);
    return schemaCachePromise;
  };

  async function budgetedDescribeTable(table: string): Promise<{ fields: Awaited<ReturnType<typeof describeTable>>; cached: boolean }> {
    const runBudget = makeDiscoveryRunBudget();
    return runDiscoveryWithBudget(runBudget, async () => {
      const cache = await schemaCache();
      const fetcher = () => describeTable(discoveryDeps(runBudget), table);
      return cache ? cache.describeTable(table, fetcher) : { fields: await fetcher(), cached: false };
    });
  }

  async function budgetedListTables(filter: string | undefined): Promise<Awaited<ReturnType<typeof listTables>> & { cached: boolean }> {
    const runBudget = makeDiscoveryRunBudget();
    return runDiscoveryWithBudget(runBudget, async () => {
      const cache = await schemaCache();
      const fetcher = () => listTables(discoveryDeps(runBudget), filter);
      return cache ? cache.listTables(filter, fetcher) : { ...(await fetcher()), cached: false };
    });
  }

  return {
    runCode: (input) => runCode(input, runCodeDeps),
    describeTable: async ({ table }): Promise<ToolTextResult> => {
      try {
        const cache = await schemaCache({ freshOnly: true });
        const fetcher = () => {
          const runBudget = makeDiscoveryRunBudget();
          return runDiscoveryWithBudget(runBudget, () => describeTable(discoveryDeps(runBudget), table));
        };
        const { fields, cached } = cache ? await cache.describeTable(table, fetcher) : await budgetedDescribeTable(table);
        return { content: [{ type: "text", text: JSON.stringify({ table, fields }) }], isError: false, structuredContent: { table, fieldCount: fields.length, cached } };
      } catch (e) {
        return toToolResult(e);
      }
    },
    listTables: async ({ filter }): Promise<ToolTextResult> => {
      try {
        const cache = await schemaCache({ freshOnly: true });
        const fetcher = () => {
          const runBudget = makeDiscoveryRunBudget();
          return runDiscoveryWithBudget(runBudget, () => listTables(discoveryDeps(runBudget), filter));
        };
        const result = cache ? await cache.listTables(filter, fetcher) : await budgetedListTables(filter);
        const { tables, partial, total, policyFilteredPartial, warning, cached } = result;
        return {
          content: [{ type: "text", text: JSON.stringify({ tables, partial, ...(total !== undefined ? { total } : {}), ...(warning ? { warning } : {}) }) }],
          isError: false,
          structuredContent: {
            count: tables.length,
            cached,
            partial,
            ...(total !== undefined ? { total } : {}),
            ...(policyFilteredPartial ? { policyFilteredPartial } : {}),
            ...(warning ? { warning } : {}),
          },
        };
      } catch (e) {
        return toToolResult(e);
      }
    },
  };
}

/**
 * Resolve the SchemaCache identity for a /mcp request (§6b). buildHandlers is sync, so apiHandler
 * threads this async resolver through AuthContext and schema tools invoke it lazily.
 *
 * Returns the authenticated MCP actor identity in integration_user mode (no extra work, no decrypt).
 * In per_user_oauth it returns a fresh ServiceNow `sys_id` plus role hash. If the principal is
 * absent, stale-unresolvable, or unreadable, returns undefined so schema tools bypass cache for
 * that request. It NEVER throws, so it cannot block the reauth_required path.
 */
export async function resolveSchemaIdentity(
  env: HandlerEnv,
  userId: string,
  opts: { freshOnly?: boolean } = {},
): Promise<SchemaCachePrincipalIdentity | undefined> {
  const tokenKekSecret = env.TOKEN_KEK_CURRENT;
  const credentialMode = parseCredentialMode(env.SERVICENOW_CREDENTIAL_MODE);
  const oauthReady = Boolean(
    env.SNOW_OAUTH_CLIENT_ID && env.SNOW_OAUTH_CLIENT_SECRET && env.TOKEN_DO && tokenKekSecret && env.SNOW_INSTANCE_HOST,
  );
  if (credentialMode === "invalid") return undefined;
  if (credentialMode === "integration_user") return { principalId: userId, roleHash: "default" };
  if (!oauthReady) return undefined;
  try {
    // Intentional two-step guard: normalize the configured ServiceNow host under the default
    // service-now.com suffix allowlist, then re-check the canonical host against the active profile
    // allowlist (production pins it to this exact instance).
    const instanceHost = canonicalizeInstanceHost(env.SNOW_INSTANCE_HOST!, defaultInstanceAllowlist);
    const instanceAllowlist = instanceAllowlistForProfile(env, instanceHost);
    canonicalizeInstanceHost(instanceHost, instanceAllowlist);
    const stub = env.TOKEN_DO!.get(env.TOKEN_DO!.idFromName(`${userId}|${instanceHost}`)) as unknown as {
      putToken(t: string, v: string): Promise<void>; getToken(t: string): Promise<string | undefined>;
    };
    const store = new TokenStore(stub, await buildKekRing(tokenKekSecret!, env.TOKEN_KEK_PREV), userId, instanceHost);
    const principal = opts.freshOnly
      ? await resolveFreshStoredSnPrincipal(store, Date.now())
      : await resolveStoredSnPrincipal(
        {
          instanceHost,
          clientId: env.SNOW_OAUTH_CLIENT_ID!,
          clientSecret: env.SNOW_OAUTH_CLIENT_SECRET!,
        },
        store,
        Date.now(),
      );
    if (!principal) return undefined;
    const roles = principal.roles;
    return {
      principalId: principal.sys_id,
      roleHash: roles && roles.length > 0 ? await roleHash(roles) : "default",
    };
  } catch (e) {
    // Best-effort: an identity failure must NEVER block the request. Bypassing cache is safer than
    // reusing the wrong key for ACL-filtered schema. Log only the error object (no token/key data).
    console.error("resolveSchemaIdentity failed; SchemaCache disabled for this request", e);
    return undefined;
  }
}
