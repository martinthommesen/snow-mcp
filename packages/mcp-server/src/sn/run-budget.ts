// Per-run, in-process budget meter (plan §2.5). Trips `budget_exceeded` mid-snippet.
// The daily/global multi-dimensional atomic reserve lives in BudgetDO (Phase 4.5);
// this is the per-run half that bounds one cheap Worker making many RPC/SN calls.

import { McpToolError } from "./errors.js";
import { BUDGETS } from "../config.js";

export interface RunBudgetLimits {
  rpcCallLimit: number;
  serviceNowRequestLimit: number;
  attachmentBytes: number;
}

export class RunBudget {
  rpcCalls = 0;
  serviceNowRequests = 0;
  rowsReturned = 0;
  bytesReturned = 0;
  attachmentBytes = 0;
  private readonly limits: RunBudgetLimits;

  constructor(limits: RunBudgetLimits = BUDGETS.perRun) {
    this.limits = limits;
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

  countRows(n: number): void {
    this.rowsReturned += n;
  }

  countAttachmentBytes(n: number): void {
    this.attachmentBytes += n;
    if (this.attachmentBytes > this.limits.attachmentBytes) {
      throw new McpToolError("budget_exceeded", `Per-run attachment byte limit (${this.limits.attachmentBytes}) exceeded.`, {
        dimension: "attachmentBytes",
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
      attachmentBytes: this.attachmentBytes,
    };
  }
}
