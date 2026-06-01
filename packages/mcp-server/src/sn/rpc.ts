// ServiceNowRPC — the security boundary the sandbox sees (plan §3.3, §3.1).
//
// Public methods are the ONLY ServiceNow capabilities reachable from the sandbox; the
// OAuth bearer is injected host-side in SnHttpClient and never appears in any
// signature or return. Every method — reads included — enforces, IN ORDER:
//   ActorPolicy (§2.12) -> effective-mode capability (§3.5) -> per-run budget (§2.5)
// before calling ServiceNow. The ActorPolicy step is table-scoped for reads/writes
// (assertActorPolicy: instance + table allowlist + mode ceiling) and additionally screens the
// caller query for masked fields (assertQueryFieldsAllowed). runServerScript is TABLE-LESS, so it
// applies the ActorPolicy MODE CEILING explicitly (H-1) — there is no table allowlist to run.
// The enforcement is unit-verified locally against a mock
// SnHttpClient; live ServiceNow behavior is not (see OPEN_QUESTIONS.md).
//
// NOTE: the plan writes `class ServiceNowRPC extends RpcTarget`. We expose plain
// methods and hand `fns()` to codemode, whose ToolDispatcher is itself the RpcTarget
// over Workers RPC — so extending RpcTarget here is unnecessary (recorded in DELTAS).

import type { Mode } from "@servicenow-codemode/shared";
import { modeRisk } from "@servicenow-codemode/shared";
import type { SnHttpClient } from "./http.js";
import { mapServiceNowError, encodeSandboxError, McpToolError } from "./errors.js";
import { requireCapability } from "../config.js";
import { TABLE_PAGE_CAP } from "../config.js";
import { RunBudget } from "./run-budget.js";
import { utf8Len } from "../sandbox/serialize.js";
import {
  assertActorPolicy,
  applyRowFilter,
  assertRequestedFieldsAllowed,
  assertQueryFieldsAllowed,
  maskRow,
  type ActorPolicy,
} from "../authz/actor-policy.js";
import { signActor, type ActorClaims } from "../auth/actor.js";
import {
  validateTableName,
  validateSysId,
  validateLimit,
  validateFields,
  validateUpdateFields,
  validateReason,
  validateUserQuery,
} from "./validate.js";
import {
  guardMutation,
  tableUpdateRequestHash,
  runServerScriptRequestHash,
  type RunContext,
  type LedgerHandle,
} from "./mutation-guard.js";
import type { AuditSink, AuditIdentity } from "./mutation-guard.js";
import { assertAdminScriptApproved, type ApprovalContext } from "../authz/approval.js";
import { recoverability } from "../recovery/policy.js";

export interface ServiceNowRpcDeps {
  http: SnHttpClient;
  instanceHost: string;
  effectiveMode: Mode;
  actorPolicy: ActorPolicy;
  runBudget: RunBudget;
  /** Host-signed actor for mutating/executor calls (§2.0). Always host-signed when the executor
   *  is configured, orthogonal to credential mode. In per_user_oauth, `resolveEffectiveUserSysId`
   *  fills the `snow_effective_user_sys_id` claim lazily at sign time (§6b option (b)). */
  signing?: {
    claims: ActorClaims;
    hmacKey: Uint8Array;
    nonce: () => string;
    now: () => number;
    resolveEffectiveUserSysId?: () => Promise<string>;
  };
  /** Executor endpoint path (instance-specific; global-scope APIs get a numeric namespace). */
  executorPath?: string;
  /**
   * Host-authoritative per-run mutation context + the wired safety layers (plan §P4).
   * When present, every mutating/executor call runs through the idempotency ledger,
   * approval gate, recovery snapshot, and host audit (audit-before-effect, fail-closed).
   * Unit tests may omit the durable stores; live handler wiring marks them required.
   */
  mutation?: MutationDeps;
}

/** The live-path safety wiring captured by handlers' buildRpc closure (plan §P4). */
export interface MutationDeps {
  runContext: RunContext;
  identity: AuditIdentity;
  now: () => number;
  /** Live handler wiring requires ledger + audit before any mutation/executor effect. */
  durabilityRequired?: boolean;
  /** Per run+ordinal idempotency-ledger handle (LEDGER_DO-backed in production). */
  ledger?: (ordinal: number) => LedgerHandle;
  /** Durable host audit sink (AUDIT_KV-backed in production). */
  audit?: AuditSink;
  /**
   * Recovery snapshot capture for a reversible-class tableUpdate. Owns the (lazily-built)
   * SNAPSHOT_KEK ring, the enabled-table classification, encryption (AAD-bound), and the
   * durable persist (SNAPSHOT_KV). Returns true when a snapshot was persisted, false when
   * the table is opted out (claim narrowed). THROWS if it cannot persist — the caller then
   * fails the mutation CLOSED (no recovery row => no mutate). The integration user never
   * decrypts (the ring lives only here, host-side).
   */
  captureSnapshot?: (input: {
    requestId: string;
    ordinal: number;
    table: string;
    sysId: string;
    before: Record<string, unknown>;
    after: Record<string, unknown>;
    takenAt: number;
  }) => Promise<boolean>;
  /** Tables eligible for a reversible-from-snapshot tableUpdate (for the recoverability
   *  classification); empty when snapshots are disabled/opted-out for this tenant. */
  snapshotEnabledTables?: readonly string[];
  /** Second-approval context for admin_script (allowlist + token/access-group).
   * Absent is treated as an empty policy, which denies admin_script. */
  approval?: Omit<ApprovalContext, "mode" | "actorUserId" | "reason">;
}

export interface TableQueryArgs {
  table: string;
  query?: string;
  fields?: string[];
  limit?: number;
}
export interface TableRowsResult {
  rows: Record<string, unknown>[];
  partial: boolean;
}

/**
 * Host-attested, monotonic signals raised when the HOST (not the snippet) hits a
 * terminal condition during a run (plan §P2). Set once, never cleared: a snippet that
 * catches the thrown error cannot un-set the signal, so run_code can attest these codes
 * even after a catch. Only `budgetExceeded`/`reauthRequired` are host-attested — a
 * snippet's forged `throw new Error("[[…]]")` never transits the host RPC path and so
 * never sets a signal.
 */
export interface HostSignals {
  budgetExceeded?: { dimension?: string };
  reauthRequired?: { authorizeUrl?: string };
}

/**
 * Exactly-once classifier for a mutation/executor effect throw (S17, plan §P4). A
 * DEFINITIVE server rejection (401 reauth, 403 ACL) means the effect did NOT apply — a
 * clean failure that is safe to retry. Anything else — a raw transport error (no
 * response), a 5xx (`instance_hibernating`), or a 429 (`budget_exceeded`) — is POST-SEND
 * UNKNOWN: the effect MAY have applied, so the ledger must mark it indeterminate and block
 * any retry rather than risk a double-apply.
 */
function isPostSendUnknown(err: unknown): boolean {
  if (err instanceof McpToolError) {
    return !(err.code === "reauth_required" || err.code === "actor_policy_denied");
  }
  return true; // transport error / abort / unknown — could have applied.
}

export class ServiceNowRPC {
  /** Host-attested signals for this run; a fresh instance is built per run (§P2). */
  readonly hostSignals: HostSignals = {};

  /** Out-of-band per-run mutation counter (plan §P4). Each guarded mutation/executor call
   *  gets a fresh ordinal so its ledger key + audit key + snapshot key are unique within a
   *  run (multiple mutations in one snippet never collide). Read-only methods don't bump it. */
  private ordinal = 0;

  constructor(private readonly deps: ServiceNowRpcDeps) {}

  private requireMutationDeps(op: "tableUpdate" | "runServerScript"): MutationDeps {
    if (!this.deps.mutation) {
      throw new McpToolError("internal_error", `${op} requires mutation safety wiring — refusing to mutate (fail closed).`);
    }
    return this.deps.mutation;
  }

  // ── shared gate (the order is a security property, §3.1) ──
  private gateRead(table: string, fields?: string[]): void {
    assertActorPolicy(this.deps.actorPolicy, { instance: this.deps.instanceHost, table, mode: this.deps.effectiveMode });
    requireCapability(this.deps.effectiveMode, "readTables");
    assertRequestedFieldsAllowed(this.deps.actorPolicy, table, fields);
    this.deps.runBudget.countRpcCall();
  }

  /** Does a mandatory row filter apply to this table (restrictive policy active)? */
  private hasMandatoryFilter(table: string): boolean {
    return Boolean(this.deps.actorPolicy.rowFilters?.[table]);
  }

  async tableQuery(args: TableQueryArgs): Promise<TableRowsResult> {
    // Validate untrusted sandbox input BEFORE the gate / any path interpolation (P1).
    const table = validateTableName(args.table);
    const reqFields = validateFields(args.fields);
    const userQuery = validateUserQuery(args.query, this.hasMandatoryFilter(table));
    const reqLimit = validateLimit(args.limit);
    this.gateRead(table, reqFields);
    // M-6: masked fields must not be referenced in the query predicate/ordering either (closes the
    // row-selection inference oracle — filtering ON a masked column without REQUESTING it).
    assertQueryFieldsAllowed(this.deps.actorPolicy, table, userQuery);
    const query = applyRowFilter(this.deps.actorPolicy, table, userQuery);
    const limit = reqLimit ?? TABLE_PAGE_CAP;

    // sys_id is always fetched internally so row identity remains available after field selection.
    const fields = reqFields ? Array.from(new Set(["sys_id", ...reqFields])) : undefined;
    const q: Record<string, string> = {
      sysparm_limit: String(limit),
      sysparm_exclude_reference_link: "true",
    };
    if (query) q.sysparm_query = query;
    if (fields) q.sysparm_fields = fields.join(",");

    this.deps.runBudget.countServiceNowRequest();
    const res = await this.deps.http.request({ method: "GET", path: `/api/now/table/${encodeURIComponent(table)}`, query: q });
    const mapped = mapServiceNowError(res.status, res.json as { error?: { message?: string } });
    if (mapped) throw mapped;

    const raw = ((res.json as { result?: unknown[] }).result ?? []) as Record<string, unknown>[];
    const rows = raw.map((r) => maskRow(this.deps.actorPolicy, table, r));
    // Per-run row + byte enforcement (§P5): measure the MASKED payload the snippet sees.
    this.deps.runBudget.countRows(rows.length);
    this.deps.runBudget.countBytes(utf8Len(JSON.stringify(rows)));
    return { rows, partial: rows.length >= limit };
  }

  async tableGet(args: { table: string; sys_id: string; fields?: string[] }): Promise<Record<string, unknown> | null> {
    const table = validateTableName(args.table);
    const sysId = validateSysId(args.sys_id);
    const reqFields = validateFields(args.fields);
    this.gateRead(table, reqFields);
    const fieldsParam = reqFields ? Array.from(new Set(["sys_id", ...reqFields])).join(",") : undefined;

    let row: Record<string, unknown> | undefined;
    if (this.hasMandatoryFilter(table)) {
      // Finding 8a: a direct /table/{table}/{sysId} GET ignores the mandatory row filter that
      // tableQuery/aggregate enforce. Route the single-record lookup through the filtered list
      // endpoint so the configured rowFilter is AND-ed in (sysId is 32-hex-validated, safe to
      // embed). A record outside the filter — or absent — returns null with no existence leak.
      const query = applyRowFilter(this.deps.actorPolicy, table, `sys_id=${sysId}`);
      const q: Record<string, string> = { sysparm_exclude_reference_link: "true", sysparm_query: query, sysparm_limit: "1" };
      if (fieldsParam) q.sysparm_fields = fieldsParam;
      this.deps.runBudget.countServiceNowRequest();
      const res = await this.deps.http.request({ method: "GET", path: `/api/now/table/${encodeURIComponent(table)}`, query: q });
      const mapped = mapServiceNowError(res.status, res.json as { error?: { message?: string } });
      if (mapped) throw mapped;
      row = ((res.json as { result?: Record<string, unknown>[] }).result ?? [])[0];
    } else {
      const q: Record<string, string> = { sysparm_exclude_reference_link: "true" };
      if (fieldsParam) q.sysparm_fields = fieldsParam;
      this.deps.runBudget.countServiceNowRequest();
      const res = await this.deps.http.request({ method: "GET", path: `/api/now/table/${encodeURIComponent(table)}/${encodeURIComponent(sysId)}`, query: q });
      if (res.status === 404) return null;
      const mapped = mapServiceNowError(res.status, res.json as { error?: { message?: string } });
      if (mapped) throw mapped;
      row = (res.json as { result?: Record<string, unknown> }).result;
    }
    if (!row) return null;
    const masked = maskRow(this.deps.actorPolicy, table, row);
    // Per-run row + byte enforcement (§P5): one row, measured on the masked payload.
    this.deps.runBudget.countRows(1);
    this.deps.runBudget.countBytes(utf8Len(JSON.stringify(masked)));
    return masked;
  }

  async aggregate(args: { table: string; query?: string; groupBy?: string[] }): Promise<unknown> {
    const table = validateTableName(args.table);
    const userQuery = validateUserQuery(args.query, this.hasMandatoryFilter(table));
    // groupBy fields are field references: validate AND mask-check (no masked field may be
    // grouped on — same boundary as requested read fields).
    const groupBy = validateFields(args.groupBy);
    this.gateRead(table, groupBy);
    // M-6: the aggregate `query` is an equality/inference oracle if it can filter on a masked field
    // (groupBy is already mask-checked via gateRead; the predicate was not).
    assertQueryFieldsAllowed(this.deps.actorPolicy, table, userQuery);
    const query = applyRowFilter(this.deps.actorPolicy, table, userQuery);
    const q: Record<string, string> = { sysparm_count: "true" };
    if (query) q.sysparm_query = query;
    if (groupBy) q.sysparm_group_by = groupBy.join(",");
    this.deps.runBudget.countServiceNowRequest();
    const res = await this.deps.http.request({ method: "GET", path: `/api/now/stats/${encodeURIComponent(table)}`, query: q });
    const mapped = mapServiceNowError(res.status, res.json as { error?: { message?: string } });
    if (mapped) throw mapped;
    const result = (res.json as { result?: unknown }).result ?? null;
    // Per-run byte enforcement (§P5): the serialized aggregate payload the snippet sees.
    this.deps.runBudget.countBytes(utf8Len(JSON.stringify(result)));
    return result;
  }

  // ── mutating / executor methods: capability-gated; integration mode signs the actor ──
  async tableUpdate(args: { table: string; sys_id: string; fields: Record<string, unknown> }): Promise<Record<string, unknown>> {
    const table = validateTableName(args.table);
    const sysId = validateSysId(args.sys_id);
    const fields = validateUpdateFields(args.fields);
    assertActorPolicy(this.deps.actorPolicy, { instance: this.deps.instanceHost, table, mode: this.deps.effectiveMode });
    requireCapability(this.deps.effectiveMode, "writeTables");
    // Masked fields may not be WRITTEN either (the mask applies to request AND response, §2.12).
    // (P1 finding 16: dot-aware write-key mask — already wired; verified present here.)
    assertRequestedFieldsAllowed(this.deps.actorPolicy, table, Object.keys(fields));
    this.deps.runBudget.countRpcCall();

    const mutation = this.requireMutationDeps("tableUpdate");

    const ordinal = ++this.ordinal;
    const reason = mutation.runContext.reason;
    const requestHash = await tableUpdateRequestHash({ table, sysId, fields, mode: this.deps.effectiveMode, reason });

    // Classify recoverability via the named policy module (recovery/policy.ts): an `update`
    // on a snapshot-enabled table is `reversible_from_snapshot` and captures a before-state
    // snapshot; otherwise it is `non_recoverable` (no snapshot). runServerScript is always
    // non-recoverable (handled in that method — no snapshot).
    let beforeRow: Record<string, unknown> | undefined;
    let snapshotStep: (() => Promise<void>) | undefined;
    const snapshotConfig = { enabledTables: mutation.snapshotEnabledTables ?? [] };
    const reversible = Boolean(mutation.captureSnapshot) && recoverability("update", table, snapshotConfig) === "reversible_from_snapshot";
    if (reversible) {
      snapshotStep = async () => {
        // Capture the real (unmasked) before-state for recovery; never reaches the snippet.
        this.deps.runBudget.countServiceNowRequest();
        const cur = await this.deps.http.request({
          method: "GET",
          path: `/api/now/table/${encodeURIComponent(table)}/${encodeURIComponent(sysId)}`,
          query: { sysparm_exclude_reference_link: "true" },
        });
        const curMapped = mapServiceNowError(cur.status, cur.json as { error?: { message?: string } });
        if (curMapped) throw curMapped;
        beforeRow = (cur.json as { result?: Record<string, unknown> }).result ?? {};
        // captureSnapshot owns encryption + persist; a throw fails the mutation CLOSED
        // (no recovery row => no mutate). false => the table is opted out (claim narrowed).
        await mutation.captureSnapshot!({
          requestId: mutation.runContext.requestId, ordinal, table, sysId,
          before: beforeRow, after: fields, takenAt: mutation.now(),
        });
      };
    }

    // Per-run SN-request budget for the PATCH — counted PRE-guard so a budget trip is a
    // clean pre-send `budget_exceeded` (never misclassified as a post-send indeterminate).
    this.deps.runBudget.countServiceNowRequest();

    const result = await guardMutation<Record<string, unknown>>(
      {
        run: mutation.runContext,
        instance: this.deps.instanceHost,
        identity: mutation.identity,
        now: mutation.now,
        ...(mutation.durabilityRequired ? { durabilityRequired: true } : {}),
        ...(mutation.ledger ? { ledger: mutation.ledger } : {}),
        ...(mutation.audit ? { audit: mutation.audit } : {}),
      },
      {
        ordinal,
        op: "update",
        table,
        sysId,
        requestHash,
        ...(reason !== undefined ? { reason } : {}),
        ...(snapshotStep ? { snapshot: snapshotStep } : {}),
        get before() { return beforeRow; },
        effect: async () => {
          // The SN-request meter was consulted PRE-guard (above) so a budget trip is a clean
          // pre-send error, never reaching the indeterminate classifier. The effect is the
          // network PATCH only.
          const result = await this.patchRow(table, sysId, fields);
          return { result, after: result };
        },
        // Exactly-once (S17): a definitive PRE/at-apply server rejection (401 reauth, 403
        // ACL) means the write did NOT apply -> clean fail() (retry-safe). Anything else —
        // a transport error (no response), a 5xx (instance_hibernating), or a 429
        // (budget_exceeded) — is POST-SEND UNKNOWN: the PATCH may have applied, so it must
        // markIndeterminate() and BLOCK the retry, never fail().
        isIndeterminate: isPostSendUnknown,
      },
    );
    // Per-run byte enforcement (§P5): count the PATCH response AFTER guardMutation resolves.
    // Counting inside the effect closure would let a byte-cap throw classify as post-send
    // unknown (isPostSendUnknown(budget_exceeded)=true) → markIndeterminate() and poison the
    // ledger for a write that actually succeeded (same after-guard placement as runServerScript).
    this.deps.runBudget.countBytes(utf8Len(JSON.stringify(result ?? null)));
    return result;
  }

  /** Issue the PATCH and map the response. Shared by the guarded + unwired paths. */
  private async patchRow(table: string, sysId: string, fields: Record<string, unknown>): Promise<Record<string, unknown>> {
    const res = await this.deps.http.request({ method: "PATCH", path: `/api/now/table/${encodeURIComponent(table)}/${encodeURIComponent(sysId)}`, body: fields });
    const mapped = mapServiceNowError(res.status, res.json as { error?: { message?: string } });
    if (mapped) throw mapped;
    return (res.json as { result?: Record<string, unknown> }).result ?? {};
  }

  /** Arbitrary server-side script via the x_mcp executor (admin_script only). Builds
   *  the host-signed actor payload (§2.0) that the executor verifies in-scope.
   *
   *  ADMIN_SCRIPT PRIVILEGE MODEL (plan §P4) — read before changing this method:
   *  - Executor HMAC signing is ALWAYS host-signed when the executor is configured
   *    (`this.deps.signing`), ORTHOGONAL to the credential mode. The host signs the actor
   *    payload regardless of integration_user / per_user_oauth.
   *  - The script runs at the EXECUTOR APP's privilege, governed by HMAC + the executor's
   *    role ACL + the approval gate + host audit + the signed/audited `reason` — it is NOT
   *    bounded by the caller's per-user ServiceNow ACLs.
   *  - The host controls wired here (audit, idempotency, snapshots, budgets) wrap the
   *    TOP-LEVEL runServerScript call + its response — NOT the script's internal
   *    GlideRecord operations (Level 3 in mutation-ledger.ts is a documented limitation).
   */
  async runServerScript(args: { script: string }): Promise<unknown> {
    if (typeof args.script !== "string" || args.script.length === 0) {
      throw new McpToolError("path_denied", "runServerScript requires a non-empty script string.");
    }
    // H-1: ActorPolicy mode ceiling on the executor path. assertActorPolicy is table-scoped and
    // never runs here (runServerScript is table-less), so the per-actor `maxMode` cap previously
    // failed OPEN on the single most dangerous capability — an actor pinned to `write` could still
    // run arbitrary admin script. In integration_user mode (SN ACLs don't bound the shared
    // identity) this host-side cap is the bound, so enforce it explicitly BEFORE the capability
    // gate, matching the documented ActorPolicy→capability order. modeRisk scores any non-Mode as
    // +Infinity, so it fails closed.
    if (modeRisk(this.deps.effectiveMode) > modeRisk(this.deps.actorPolicy.maxMode)) {
      throw new McpToolError(
        "actor_policy_denied",
        `Mode "${this.deps.effectiveMode}" exceeds this actor's maxMode "${this.deps.actorPolicy.maxMode}".`,
      );
    }
    requireCapability(this.deps.effectiveMode, "runServerScript");
    if (!this.deps.signing) {
      // The executor call is ALWAYS host-signed when the executor is configured (orthogonal to
      // credential mode — see the method header). No signing config => the executor is unwired.
      throw new Error("runServerScript requires signed-actor configuration (executor not configured).");
    }
    // I-6: a security-critical egress target must fail CLOSED, never silently fall back to a
    // hardcoded guess. Require the configured executor path here (handlers gates executorReady on
    // SNOW_EXECUTOR_PATH, so this is set in every wired deployment).
    if (!this.deps.executorPath) {
      throw new Error("runServerScript requires executorPath (executor not configured).");
    }
    const executorPath = this.deps.executorPath;
    const signing = this.deps.signing;
    this.deps.runBudget.countRpcCall();

    // Host-authoritative justification: the operator-supplied tool-level reason. Used for the
    // executor-side audit (P7) POST body, the requestHash, the approval context, and the host
    // audit row.
    const sendScript = async (reason: string): Promise<unknown> => {
      // §6b: in per_user_oauth, resolve the effective user's sys_id at sign time and bind it into
      // the signed claims (the executor verifies it). Unresolved per-user attribution fails closed;
      // integration_user has no resolver and keeps the base shared-credential claim.
      const effectiveSysId = signing.resolveEffectiveUserSysId ? await signing.resolveEffectiveUserSysId() : "";
      if (signing.resolveEffectiveUserSysId && !effectiveSysId) {
        throw new McpToolError("reauth_required", "ServiceNow principal could not be resolved — re-authenticate.");
      }
      const signed = await signActor({
        claims: effectiveSysId ? { ...signing.claims, snow_effective_user_sys_id: effectiveSysId } : signing.claims,
        script: args.script,
        issuedAt: signing.now(),
        nonce: signing.nonce(),
        // Host-authoritative justification, integrity-bound by the signature (plan §P7
        // item 1). The executor verifies + audits this signed `actor.reason`; we no longer
        // send an unsigned top-level `body.reason` (forgeable independent of the signature).
        reason,
        hmacKey: signing.hmacKey,
      });
      const res = await this.deps.http.request({
        method: "POST",
        path: executorPath,
        body: { script: args.script, actor: signed.actor, actor_sig: signed.actor_sig },
      });
      // Executor surfaces 503 (disabled) / 401 (bad signature) as typed conditions.
      const mapped = mapServiceNowError(res.status, res.json as { error?: { message?: string } });
      if (mapped) throw mapped;
      return res.json;
    };

    const mutation = this.requireMutationDeps("runServerScript");

    // run_code hard-requires a non-empty tool-level reason for admin_script (run_code.ts:68)
    // and runServerScript requires admin_script — so runContext.reason is guaranteed here.
    // Guard defensively: if it is somehow absent, fail CLOSED rather than send/audit an empty
    // reason (mirrors run_code's non-empty-reason capability_denied).
    const reason = mutation.runContext.reason;
    if (!reason?.trim()) {
      throw new McpToolError("capability_denied", "admin_script requires a non-empty host-level `reason`.");
    }
    // This host reason is SIGNED into the actor canonical (signActor below) and persisted to the
    // executor audit `reason` column (StringColumn maxLength 1024). Validate it (length<=1024, no
    // control chars) BEFORE it is hashed/signed/sent so the signed+audited value matches the
    // column contract — a too-long/control-char reason would otherwise ride into the HMAC and be
    // silently truncated/garbled on write. Validate, never mutate (mutating after signing would
    // break the HMAC).
    validateReason(reason);

    const ordinal = ++this.ordinal;
    const actorUserId = signing.claims.mcp_actor_user_id;
    const requestHash = await runServerScriptRequestHash({
      script: args.script, reason, mode: this.deps.effectiveMode, instance: this.deps.instanceHost, actorUserId,
    });

    // Second-approval gate (§7.9). Empty/unconfigured policy denies admin_script by default.
    // The interactive dry-run branch is stateless-unsupported in createMcpHandler, so the
    // supported non-interactive paths are approval token or current access-group membership.
    const approval = mutation.approval ?? { adminScriptAllowlist: [] };
    const preflight = () =>
      assertAdminScriptApproved({
        ...approval,
        mode: this.deps.effectiveMode,
        actorUserId,
        reason,
        approvalToken: mutation.runContext.approvalToken,
      });

    // Per-run SN-request budget for the executor POST — counted PRE-guard (clean pre-send).
    this.deps.runBudget.countServiceNowRequest();

    const result = await guardMutation<unknown>(
      {
        run: mutation.runContext,
        instance: this.deps.instanceHost,
        identity: mutation.identity,
        now: mutation.now,
        ...(mutation.durabilityRequired ? { durabilityRequired: true } : {}),
        ...(mutation.ledger ? { ledger: mutation.ledger } : {}),
        ...(mutation.audit ? { audit: mutation.audit } : {}),
      },
      {
        ordinal,
        op: "runServerScript",
        reason,
        requestHash,
        preflight,
        // runServerScript is NON-RECOVERABLE (recovery/policy.ts) — no snapshot.
        effect: async () => ({ result: await sendScript(reason) }),
        isIndeterminate: isPostSendUnknown,
      },
    );
    // Per-run byte enforcement (§P5): count the executor response AFTER guardMutation
    // resolves. Counting inside the effect closure would let a byte-cap throw classify as
    // post-send unknown (isPostSendUnknown(budget_exceeded)=true) → markIndeterminate() and
    // poison the ledger for a script that actually succeeded.
    this.deps.runBudget.countBytes(utf8Len(JSON.stringify(result ?? null)));
    return result;
  }

  // Encode the typed error code into the thrown message so it survives the sandbox
  // boundary (codemode keeps only err.message). Before the lossy re-throw, record the
  // host-attested signal for budget/reauth conditions (§P2): these monotonic signals —
  // captured here at the single host RPC chokepoint, carrying `detail` that
  // encodeSandboxError would drop — are how run_code attests `code` without trusting the
  // snippet-controlled message a forged `throw new Error("[[…]]")` could supply.
  private async coded<T>(p: Promise<T>): Promise<T> {
    try {
      return await p;
    } catch (e) {
      if (e instanceof McpToolError) {
        if (e.code === "budget_exceeded") {
          this.hostSignals.budgetExceeded ??= { dimension: e.detail?.dimension as string | undefined };
        } else if (e.code === "reauth_required") {
          this.hostSignals.reauthRequired ??= { authorizeUrl: e.detail?.authorizeUrl as string | undefined };
        }
      }
      throw new Error(encodeSandboxError(e));
    }
  }

  /** The provider fns handed to the codemode sandbox (surface = `servicenow.*`). */
  fns(): Record<string, (...args: unknown[]) => Promise<unknown>> {
    return {
      tableQuery: (a) => this.coded(this.tableQuery(a as TableQueryArgs)),
      tableGet: (a) => this.coded(this.tableGet(a as { table: string; sys_id: string; fields?: string[] })),
      aggregate: (a) => this.coded(this.aggregate(a as { table: string; query?: string; groupBy?: string[] })),
      tableUpdate: (a) => this.coded(this.tableUpdate(a as { table: string; sys_id: string; fields: Record<string, unknown> })),
      runServerScript: (a) => this.coded(this.runServerScript(a as { script: string })),
    };
  }
}
