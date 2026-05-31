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

export class ServiceNowRPC {
  /** Host-attested signals for this run; a fresh instance is built per run (§P2). */
  readonly hostSignals: HostSignals = {};

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
    assertRequestedFieldsAllowed(this.deps.actorPolicy, table, Object.keys(fields));
    this.deps.runBudget.countRpcCall();
    this.deps.runBudget.countServiceNowRequest();
    const res = await this.deps.http.request({ method: "PATCH", path: `/api/now/table/${encodeURIComponent(table)}/${encodeURIComponent(sysId)}`, body: fields });
    const mapped = mapServiceNowError(res.status, res.json as { error?: { message?: string } });
    if (mapped) throw mapped;
    return (res.json as { result?: Record<string, unknown> }).result ?? {};
  }

  /** Arbitrary server-side script via the x_mcp executor (admin_script only). Builds
   *  the host-signed actor payload (§2.0) that the executor verifies in-scope. */
  async runServerScript(args: { script: string; reason: string; idempotencyKey: string }): Promise<unknown> {
    if (typeof args.script !== "string" || args.script.length === 0) {
      throw new McpToolError("path_denied", "runServerScript requires a non-empty script string.");
    }
    const reason = validateReason(args.reason);
    validateIdempotencyKey(args.idempotencyKey);
    requireCapability(this.deps.effectiveMode, "runServerScript");
    if (!this.deps.signing) {
      // per_user_oauth mode does not sign (native attribution); integration_user must.
      throw new Error("runServerScript requires signed-actor configuration in integration_user mode.");
    }
    this.deps.runBudget.countRpcCall();
    const signed = await signActor({
      claims: this.deps.signing.claims,
      script: args.script,
      issuedAt: this.deps.signing.now(),
      nonce: this.deps.signing.nonce(),
      hmacKey: this.deps.signing.hmacKey,
    });
    this.deps.runBudget.countServiceNowRequest();
    const res = await this.deps.http.request({
      method: "POST",
      path: this.deps.executorPath ?? "/api/x_mcp/executor/run",
      body: { script: args.script, actor: signed.actor, actor_sig: signed.actor_sig, reason },
    });
    // Executor surfaces 503 (disabled) / 401 (bad signature) as typed conditions.
    const mapped = mapServiceNowError(res.status, res.json as { error?: { message?: string } });
    if (mapped) throw mapped;
    return res.json;
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
