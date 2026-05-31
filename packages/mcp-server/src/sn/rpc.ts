// ServiceNowRPC — the security boundary the sandbox sees (plan §3.3, §3.1).
//
// Public methods are the ONLY ServiceNow capabilities reachable from the sandbox; the
// OAuth bearer is injected host-side in SnHttpClient and never appears in any
// signature or return. Every method — reads included — enforces, IN ORDER:
//   ActorPolicy (§2.12) -> effective-mode capability (§3.5) -> per-run budget (§2.5)
// before calling ServiceNow. The enforcement is unit-verified locally against a mock
// SnHttpClient; live ServiceNow behavior is not (see OPEN_QUESTIONS.md).
//
// NOTE: the plan writes `class ServiceNowRPC extends RpcTarget`. We expose plain
// methods and hand `fns()` to codemode, whose ToolDispatcher is itself the RpcTarget
// over Workers RPC — so extending RpcTarget here is unnecessary (recorded in DELTAS).

import type { Mode } from "@servicenow-codemode/shared";
import type { SnHttpClient } from "./http.js";
import { mapServiceNowError, encodeSandboxError, McpToolError } from "./errors.js";
import { requireCapability } from "../config.js";
import { TABLE_PAGE_CAP } from "../config.js";
import { RunBudget } from "./run-budget.js";
import {
  assertActorPolicy,
  applyRowFilter,
  assertRequestedFieldsAllowed,
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
  validateIdempotencyKey,
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
  /** integration_user only: claims + key to sign mutating/executor calls (§2.0). */
  signing?: { claims: ActorClaims; hmacKey: Uint8Array; nonce: () => string; now: () => number };
  /** Executor endpoint path (instance-specific; global-scope APIs get a numeric namespace). */
  executorPath?: string;
  /**
   * Host-authoritative per-run mutation context + the wired safety layers (plan §P4).
   * When present, every mutating/executor call runs through the idempotency ledger,
   * approval gate, recovery snapshot, and host audit (audit-before-effect, fail-closed).
   * Absent in read-only / unit-test contexts — but a mutation always HARD-REQUIRES a
   * tool-level idempotencyKey regardless (see `runContext.runKey`).
   */
  mutation?: MutationDeps;
}

/** The live-path safety wiring captured by handlers' buildRpc closure (plan §P4). */
export interface MutationDeps {
  runContext: RunContext;
  identity: AuditIdentity;
  now: () => number;
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
  /**
   * Second-approval context for admin_script (allowlist + token/access-group). Present
   * ONLY when a tenant approval policy is configured; absent preserves single-operator
   * behavior (the gate is skipped, today's deployment keeps working).
   */
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
    const query = applyRowFilter(this.deps.actorPolicy, table, userQuery);
    const limit = reqLimit ?? TABLE_PAGE_CAP;

    // sys_id is always fetched internally — the keyset cursor needs it (§1.7).
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
    this.deps.runBudget.countRows(rows.length);
    return { rows, partial: rows.length >= limit };
  }

  async tableGet(args: { table: string; sys_id: string; fields?: string[] }): Promise<Record<string, unknown> | null> {
    const table = validateTableName(args.table);
    const sysId = validateSysId(args.sys_id);
    const reqFields = validateFields(args.fields);
    this.gateRead(table, reqFields);
    const q: Record<string, string> = { sysparm_exclude_reference_link: "true" };
    if (reqFields) q.sysparm_fields = Array.from(new Set(["sys_id", ...reqFields])).join(",");
    this.deps.runBudget.countServiceNowRequest();
    const res = await this.deps.http.request({ method: "GET", path: `/api/now/table/${encodeURIComponent(table)}/${encodeURIComponent(sysId)}`, query: q });
    if (res.status === 404) return null;
    const mapped = mapServiceNowError(res.status, res.json as { error?: { message?: string } });
    if (mapped) throw mapped;
    const row = (res.json as { result?: Record<string, unknown> }).result;
    return row ? maskRow(this.deps.actorPolicy, table, row) : null;
  }

  async aggregate(args: { table: string; query?: string; groupBy?: string[]; countField?: string }): Promise<unknown> {
    const table = validateTableName(args.table);
    const userQuery = validateUserQuery(args.query, this.hasMandatoryFilter(table));
    // groupBy / countField are field references: validate AND mask-check (no masked
    // field may be grouped/counted on — same boundary as requested read fields).
    const groupBy = validateFields(args.groupBy);
    const countFields = args.countField !== undefined ? validateFields([args.countField]) : undefined;
    const fieldRefs = [...(groupBy ?? []), ...(countFields ?? [])];
    this.gateRead(table, fieldRefs.length > 0 ? fieldRefs : undefined);
    const query = applyRowFilter(this.deps.actorPolicy, table, userQuery);
    const q: Record<string, string> = { sysparm_count: "true" };
    if (query) q.sysparm_query = query;
    if (groupBy) q.sysparm_group_by = groupBy.join(",");
    this.deps.runBudget.countServiceNowRequest();
    const res = await this.deps.http.request({ method: "GET", path: `/api/now/stats/${encodeURIComponent(table)}`, query: q });
    const mapped = mapServiceNowError(res.status, res.json as { error?: { message?: string } });
    if (mapped) throw mapped;
    return (res.json as { result?: unknown }).result ?? null;
  }

  // ── mutating / executor methods: capability-gated; integration mode signs the actor ──
  async tableUpdate(args: { table: string; sys_id: string; fields: Record<string, unknown>; idempotencyKey: string }): Promise<Record<string, unknown>> {
    const table = validateTableName(args.table);
    const sysId = validateSysId(args.sys_id);
    const fields = validateUpdateFields(args.fields);
    validateIdempotencyKey(args.idempotencyKey);
    assertActorPolicy(this.deps.actorPolicy, { instance: this.deps.instanceHost, table, mode: this.deps.effectiveMode });
    requireCapability(this.deps.effectiveMode, "writeTables");
    // Masked fields may not be WRITTEN either (the mask applies to request AND response, §2.12).
    // (P1 finding 16: dot-aware write-key mask — already wired; verified present here.)
    assertRequestedFieldsAllowed(this.deps.actorPolicy, table, Object.keys(fields));
    this.deps.runBudget.countRpcCall();

    const mutation = this.deps.mutation;
    if (!mutation) {
      // Read-only / unit contexts without the live safety wiring: enforce gates only.
      this.deps.runBudget.countServiceNowRequest();
      return this.patchRow(table, sysId, fields);
    }

    const ordinal = ++this.ordinal;
    const reason = mutation.runContext.reason;
    const requestHash = await tableUpdateRequestHash({ table, sysId, fields, mode: this.deps.effectiveMode, reason });

    // Classify recoverability via the named policy module (recovery/policy.ts): an `update`
    // on a snapshot-enabled table is `reversible_from_snapshot` and captures a before-state
    // snapshot; otherwise it is `non_recoverable` (no snapshot). runServerScript is always
    // non-recoverable (handled in that method — no snapshot).
    let beforeRow: Record<string, unknown> | undefined;
    let snapshotStep: (() => Promise<void>) | undefined;
    const snapshotConfig = { enabledTables: mutation.snapshotEnabledTables ?? [], retentionMs: 0 };
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

    return guardMutation<Record<string, unknown>>(
      {
        run: mutation.runContext,
        instance: this.deps.instanceHost,
        identity: mutation.identity,
        now: mutation.now,
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
  async runServerScript(args: { script: string; reason: string; idempotencyKey: string }): Promise<unknown> {
    if (typeof args.script !== "string" || args.script.length === 0) {
      throw new McpToolError("path_denied", "runServerScript requires a non-empty script string.");
    }
    // Shape-validate the SNIPPET-supplied reason for INPUT HYGIENE only — it is NOT the
    // authoritative audited/hashed/approved/sent value (that is the host tool-level
    // runContext.reason below, mirroring tableUpdate).
    validateReason(args.reason);
    validateIdempotencyKey(args.idempotencyKey);
    requireCapability(this.deps.effectiveMode, "runServerScript");
    if (!this.deps.signing) {
      // per_user_oauth mode does not sign (native attribution); integration_user must.
      throw new Error("runServerScript requires signed-actor configuration in integration_user mode.");
    }
    const signing = this.deps.signing;
    this.deps.runBudget.countRpcCall();

    // Host-authoritative justification: the operator-supplied tool-level reason, never the
    // snippet's args.reason. Used for the executor-side audit (P7) POST body, the requestHash,
    // the approval context, and the host audit row.
    const sendScript = async (reason: string): Promise<unknown> => {
      const signed = await signActor({
        claims: signing.claims,
        script: args.script,
        issuedAt: signing.now(),
        nonce: signing.nonce(),
        hmacKey: signing.hmacKey,
      });
      const res = await this.deps.http.request({
        method: "POST",
        path: this.deps.executorPath ?? "/api/x_mcp/executor/run",
        body: { script: args.script, actor: signed.actor, actor_sig: signed.actor_sig, reason },
      });
      // Executor surfaces 503 (disabled) / 401 (bad signature) as typed conditions.
      const mapped = mapServiceNowError(res.status, res.json as { error?: { message?: string } });
      if (mapped) throw mapped;
      return res.json;
    };

    const mutation = this.deps.mutation;
    if (!mutation) {
      // No live safety wiring (unit contexts) — sign + send only. No host runContext here;
      // the validated snippet reason is the only justification available.
      this.deps.runBudget.countServiceNowRequest();
      return sendScript(args.reason);
    }

    // run_code hard-requires a non-empty tool-level reason for admin_script (run_code.ts:68)
    // and runServerScript requires admin_script — so runContext.reason is guaranteed here.
    // Guard defensively: if it is somehow absent, fail CLOSED rather than send/audit an empty
    // reason (mirrors run_code's non-empty-reason capability_denied).
    const reason = mutation.runContext.reason;
    if (!reason?.trim()) {
      throw new McpToolError("capability_denied", "admin_script requires a non-empty host-level `reason`.");
    }

    const ordinal = ++this.ordinal;
    const actorUserId = signing.claims.mcp_actor_user_id;
    const requestHash = await runServerScriptRequestHash({
      script: args.script, reason, mode: this.deps.effectiveMode, instance: this.deps.instanceHost, actorUserId,
    });

    // Second-approval gate (§7.9) — non-interactive token / access-group branch ONLY when a
    // tenant approval policy is configured (mutation.approval present). Absent => skipped,
    // preserving single-operator behavior (the interactive dry-run branch is stateless-
    // unsupported in createMcpHandler — documented in approval.ts).
    const preflight = mutation.approval
      ? () =>
          assertAdminScriptApproved({
            ...mutation.approval!,
            mode: this.deps.effectiveMode,
            actorUserId,
            reason,
          })
      : undefined;

    // Per-run SN-request budget for the executor POST — counted PRE-guard (clean pre-send).
    this.deps.runBudget.countServiceNowRequest();

    return guardMutation<unknown>(
      {
        run: mutation.runContext,
        instance: this.deps.instanceHost,
        identity: mutation.identity,
        now: mutation.now,
        ...(mutation.ledger ? { ledger: mutation.ledger } : {}),
        ...(mutation.audit ? { audit: mutation.audit } : {}),
      },
      {
        ordinal,
        op: "runServerScript",
        reason,
        requestHash,
        ...(preflight ? { preflight } : {}),
        // runServerScript is NON-RECOVERABLE (recovery/policy.ts) — no snapshot.
        effect: async () => ({ result: await sendScript(reason) }),
        isIndeterminate: isPostSendUnknown,
      },
    );
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
      tableUpdate: (a) => this.coded(this.tableUpdate(a as { table: string; sys_id: string; fields: Record<string, unknown>; idempotencyKey: string })),
      runServerScript: (a) => this.coded(this.runServerScript(a as { script: string; reason: string; idempotencyKey: string })),
    };
  }
}
