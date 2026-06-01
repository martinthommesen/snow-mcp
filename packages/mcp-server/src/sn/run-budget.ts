// Per-run, in-process budget meter (plan §2.5). Trips `budget_exceeded` mid-snippet.
// The daily/global multi-dimensional atomic reserve lives in BudgetDO (Phase 4.5);
// this is the per-run half that bounds one cheap Worker making many RPC/SN calls.

import { McpToolError } from "./errors.js";
import { BUDGETS } from "../config.js";

export interface RunBudgetLimits {
  rpcCallLimit: number;
  serviceNowRequestLimit: number;
}

/**
 * Per-actor row/byte ceilings (plan §P5). Sourced from ActorPolicy.maxRowsPerRun /
 * maxBytesPerRun — formerly DEAD fields (set, never read; CODE_REVIEW finding 11). There
 * is no `config.BUDGETS.perRun` operand for rows/bytes, so these are the SOLE per-run row
 * /byte caps (the literal "min(config, policy)" reduces to policy-only here). Default to
 * Number.POSITIVE_INFINITY so an unconfigured (permissive) RunBudget never trips — matching
 * the legacy observability-only behavior callers rely on.
 */
export interface RunBudgetCaps {
  maxRows?: number;
  maxBytes?: number;
}

export class RunBudget {
  rpcCalls = 0;
  serviceNowRequests = 0;
  rowsReturned = 0;
  bytesReturned = 0;
  private readonly limits: RunBudgetLimits;
  private readonly maxRows: number;
  private readonly maxBytes: number;

  constructor(limits: RunBudgetLimits = BUDGETS.perRun, caps: RunBudgetCaps = {}) {
    this.limits = limits;
    this.maxRows = caps.maxRows ?? Number.POSITIVE_INFINITY;
    this.maxBytes = caps.maxBytes ?? Number.POSITIVE_INFINITY;
  }

  /** One sandbox→host RPC dispatch. */
  countRpcCall(): void {
    if (++this.rpcCalls > this.limits.rpcCallLimit) {
      throw new McpToolError("budget_exceeded", `Per-run RPC call limit (${this.limits.rpcCallLimit}) exceeded.`, {
        dimension: "rpcCalls",
      });
    }
  }

  /** One outbound ServiceNow request. */
  countServiceNowRequest(): void {
    if (++this.serviceNowRequests > this.limits.serviceNowRequestLimit) {
      throw new McpToolError("budget_exceeded", `Per-run ServiceNow request limit (${this.limits.serviceNowRequestLimit}) exceeded.`, {
        dimension: "serviceNowRequests",
      });
    }
  }

  /** Accrue rows returned to the snippet; ENFORCE the per-actor row ceiling (§P5,
   *  CODE_REVIEW finding 11). Trips the P2 `budgetExceeded` host signal via `coded()`. */
  countRows(n: number): void {
    this.rowsReturned += n;
    if (this.rowsReturned > this.maxRows) {
      throw new McpToolError("budget_exceeded", `Per-run row limit (${this.maxRows}) exceeded.`, {
        dimension: "rowsReturned",
      });
    }
  }

  /** Accrue serialized bytes returned to the snippet; ENFORCE the per-actor byte ceiling
   *  (§P5, CODE_REVIEW finding 11). `bytesReturned` was formerly never incremented. */
  countBytes(n: number): void {
    this.bytesReturned += n;
    if (this.bytesReturned > this.maxBytes) {
      throw new McpToolError("budget_exceeded", `Per-run byte limit (${this.maxBytes}) exceeded.`, {
        dimension: "bytesReturned",
      });
    }
  }

  /** Snapshot for logging/metrics (plan §4.5 — emit each dimension). */
  snapshot(): Record<string, number> {
    return {
      rpcCalls: this.rpcCalls,
      serviceNowRequests: this.serviceNowRequests,
      rowsReturned: this.rowsReturned,
      bytesReturned: this.bytesReturned,
    };
  }
}
