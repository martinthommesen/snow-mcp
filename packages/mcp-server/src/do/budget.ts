import { DurableObject } from "cloudflare:workers";
import { BUDGETS } from "../config.js";

// BudgetDO (plan §2.5, §2.10, §4.5) — daily multi-dimensional counters. The GLOBAL
// daily cap lives in a SINGLE object keyed only by date (`yyyy-mm-dd`) so all runs
// coordinate through it. `reserve()` is the atomic reserve-BEFORE-load transaction
// (§4.5): because a DO processes one method call at a time, the check+increment is
// atomic, so parallel runs cannot collectively exceed the cap (S14).

export type BudgetDimension =
  | "uniqueWorkers"
  | "sandboxRpcCalls"
  | "serviceNowRequests"
  | "rowsReturned"
  | "bytesReturned";

export type ReserveRequest = Partial<Record<BudgetDimension, number>>;
export type ReserveResult = { ok: true } | { ok: false; dimension: BudgetDimension; cap: number; would: number };

const DIMENSIONS: readonly BudgetDimension[] = [
  "uniqueWorkers",
  "sandboxRpcCalls",
  "serviceNowRequests",
  "rowsReturned",
  "bytesReturned",
];

export class BudgetDO extends DurableObject {
  /** Daily caps (from config; overridable for tests via the constructor env later). */
  private caps(): Record<BudgetDimension, number> {
    return {
      uniqueWorkers: BUDGETS.daily.uniqueWorkers,
      sandboxRpcCalls: BUDGETS.daily.sandboxRpcCalls,
      serviceNowRequests: BUDGETS.daily.serviceNowRequests,
      rowsReturned: BUDGETS.daily.rowsReturned,
      bytesReturned: BUDGETS.daily.bytesReturned,
    };
  }

  // Serialize the read-check-write critical section. A DO's input gate does not keep a
  // multi-await method atomic against other concurrent invocations, so we chain reserves
  // through an in-instance promise mutex — the DO is single-threaded, so this guarantees
  // no two reserves interleave and the global cap can never be over-committed (S14).
  private chain: Promise<unknown> = Promise.resolve();

  /**
   * Atomically reserve across all requested dimensions. If ANY dimension would exceed
   * its cap, NOTHING is incremented and the breaching dimension is returned. Otherwise
   * all dimensions are incremented and { ok: true } is returned. This is the gate
   * run_code must pass BEFORE creating a (billable) Dynamic Worker.
   */
  reserve(req: ReserveRequest, capOverride?: Partial<Record<BudgetDimension, number>>): Promise<ReserveResult> {
    const run = this.chain.then(() => this.reserveCritical(req, capOverride));
    this.chain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  private async reserveCritical(req: ReserveRequest, capOverride?: Partial<Record<BudgetDimension, number>>): Promise<ReserveResult> {
    const caps = { ...this.caps(), ...(capOverride ?? {}) };
    const current: Record<BudgetDimension, number> = {} as Record<BudgetDimension, number>;
    for (const d of DIMENSIONS) current[d] = (await this.ctx.storage.get<number>(`dim:${d}`)) ?? 0;

    // Check every requested dimension first (all-or-nothing).
    for (const d of DIMENSIONS) {
      const inc = req[d] ?? 0;
      if (inc <= 0) continue;
      const would = current[d] + inc;
      if (would > caps[d]) return { ok: false, dimension: d, cap: caps[d], would };
    }
    // Commit.
    for (const d of DIMENSIONS) {
      const inc = req[d] ?? 0;
      if (inc > 0) await this.ctx.storage.put(`dim:${d}`, current[d] + inc);
    }
    return { ok: true };
  }

  /** Unconditional increment (used for post-hoc accounting / tests). Prefer reserve(). */
  async increment(dimension: string, n: number): Promise<number> {
    const cur = (await this.ctx.storage.get<number>(`dim:${dimension}`)) ?? 0;
    const next = cur + n;
    await this.ctx.storage.put(`dim:${dimension}`, next);
    return next;
  }

  async get(dimension: BudgetDimension): Promise<number> {
    return (await this.ctx.storage.get<number>(`dim:${dimension}`)) ?? 0;
  }

  async snapshot(): Promise<Record<BudgetDimension, number>> {
    const out: Record<BudgetDimension, number> = {} as Record<BudgetDimension, number>;
    for (const d of DIMENSIONS) out[d] = (await this.ctx.storage.get<number>(`dim:${d}`)) ?? 0;
    return out;
  }
}
