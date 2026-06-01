import { DurableObject } from "cloudflare:workers";
import { BUDGETS } from "../config.js";

// BudgetDO (plan §2.5, §2.10, §4.5, §P5) — daily multi-dimensional counters. The GLOBAL
// daily cap lives in a SINGLE object keyed only by date (`yyyy-mm-dd`) so all runs
// coordinate through it. `reserve()` is the atomic reserve-BEFORE-load transaction
// (§4.5): because a DO processes one method call at a time, the check+increment is
// atomic, so parallel runs cannot collectively exceed the cap (S14).
//
// SHARED-FATE TRADEOFF (plan §P5, CODE_REVIEW finding 19): the GLOBAL counter is the
// ENFORCED ceiling — one cost ceiling for the whole tenant per day, so the operator's bill
// cannot run away no matter how many users there are. The PER-USER map (added in P5) is
// updated in the SAME input gate for ISOLATION/VISIBILITY (who spent what), NOT a separately
// enforced per-user fairness cap: one heavy user CAN still exhaust the global cap for
// everyone that day. Per-user fairness (a per-user enforced cap) is a deliberate non-goal
// here — the global cost ceiling wins. Both counters being written inside the one gate means
// there is no cross-DO atomicity gap between the global and per-user views.

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

function dimensionKey(dimension: BudgetDimension): string {
  return `dim:${dimension}`;
}

function requestedDimensions(req: ReserveRequest): BudgetDimension[] {
  return DIMENSIONS.filter((d) => (req[d] ?? 0) > 0);
}

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
   *
   * Includes a daily rows/bytes ADMISSION check (§P5 tier 1): rows/bytes can't be
   * pre-reserved (usage is unknown until the run spends it), so the next run is DENIED here
   * when the day's ALREADY-ACCRUED rows/bytes (from prior runs' post-run accrual) are at or
   * over cap — even with a 0 increment for those dimensions. This is the only place the
   * daily rows/bytes ceiling bites; the residual overshoot (≤ one per-run ceiling) is
   * documented on the post-run `increment` accrual path.
   */
  reserve(req: ReserveRequest, capOverride?: Partial<Record<BudgetDimension, number>>, userId?: string): Promise<ReserveResult> {
    const run = this.chain.then(() => this.reserveCritical(req, capOverride, userId));
    this.chain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  private async reserveCritical(req: ReserveRequest, capOverride?: Partial<Record<BudgetDimension, number>>, userId?: string): Promise<ReserveResult> {
    const caps = { ...this.caps(), ...(capOverride ?? {}) };
    const incremented = requestedDimensions(req);
    const userKeys = userId ? incremented.map((d) => this.userKey(userId, d)) : [];
    const stored = await this.ctx.storage.get<number>([
      ...DIMENSIONS.map(dimensionKey),
      ...userKeys,
    ]);
    const current: Record<BudgetDimension, number> = {} as Record<BudgetDimension, number>;
    for (const d of DIMENSIONS) current[d] = stored.get(dimensionKey(d)) ?? 0;

    // Daily ADMISSION check (§P5): these dimensions are accrued POST-run (the reserve loop below
    // skips 0-increment dimensions, so it never sees them). Deny the next run if the day is already
    // at/over cap. Unconditional — independent of `req`. M-1: sandboxRpcCalls is accrued post-run
    // too (handlers maps snapshot.rpcCalls -> sandboxRpcCalls) and was previously enforced NOWHERE
    // — the configured cap was dead. It is now an admission dimension alongside rows/bytes.
    for (const d of ["rowsReturned", "bytesReturned", "sandboxRpcCalls"] as const) {
      if (current[d] >= caps[d]) return { ok: false, dimension: d, cap: caps[d], would: current[d] };
    }

    // Check every requested dimension first (all-or-nothing).
    for (const d of DIMENSIONS) {
      const inc = req[d] ?? 0;
      if (inc <= 0) continue;
      const would = current[d] + inc;
      if (would > caps[d]) return { ok: false, dimension: d, cap: caps[d], would };
    }
    // Commit — GLOBAL counters, and (when a userId is given) the per-user view, both inside
    // this single input gate (no cross-DO atomicity gap; shared-fate note at top of file).
    const updates: Record<string, number> = {};
    for (const d of incremented) {
      const inc = req[d]!;
      updates[dimensionKey(d)] = current[d] + inc;
      if (userId) {
        const key = this.userKey(userId, d);
        updates[key] = (stored.get(key) ?? 0) + inc;
      }
    }
    if (Object.keys(updates).length > 0) {
      await this.ctx.storage.put(updates);
    }
    return { ok: true };
  }

  /** Per-user counter key (§P5): isolated tally per (userId, dimension). */
  private userKey(userId: string, dimension: string): string {
    return `user:${userId}:${dimension}`;
  }

  /**
   * Post-run accrual of ACTUAL spend (§P5 tier 3). Increments the GLOBAL counter AND (when a
   * userId is given) the per-user view for every supplied dimension, ALL inside the one input
   * gate. Routed through the SAME promise-chain mutex as `reserve()` so a concurrent
   * `increment`/`reserve` cannot interleave its read-check-write and lose updates (CODE_REVIEW
   * finding 18 — `increment` formerly had no mutex and raced `reserveCritical`).
   *
   * RESIDUAL (state honestly, §P5): because rows/bytes are spent before they are known, a
   * single run can overshoot the daily rows/bytes cap by at most one per-run ceiling. The
   * admission check in `reserve()` is deny-NEXT-run, not perfect daily byte enforcement — we
   * do NOT claim perfect daily byte enforcement.
   */
  increment(req: ReserveRequest, userId?: string): Promise<void> {
    const run = this.chain.then(() => this.incrementCritical(req, userId));
    this.chain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  private async incrementCritical(req: ReserveRequest, userId?: string): Promise<void> {
    const incremented = requestedDimensions(req);
    if (incremented.length === 0) return;
    const userKeys = userId ? incremented.map((d) => this.userKey(userId, d)) : [];
    const stored = await this.ctx.storage.get<number>([
      ...incremented.map(dimensionKey),
      ...userKeys,
    ]);
    const updates: Record<string, number> = {};
    for (const d of incremented) {
      const inc = req[d]!;
      const globalKey = dimensionKey(d);
      updates[globalKey] = (stored.get(globalKey) ?? 0) + inc;
      if (userId) {
        const key = this.userKey(userId, d);
        updates[key] = (stored.get(key) ?? 0) + inc;
      }
    }
    await this.ctx.storage.put(updates);
  }

  async get(dimension: BudgetDimension): Promise<number> {
    return (await this.ctx.storage.get<number>(dimensionKey(dimension))) ?? 0;
  }

  /** Per-user accrued total for one dimension (isolation/visibility, §P5). */
  async getUser(userId: string, dimension: BudgetDimension): Promise<number> {
    return (await this.ctx.storage.get<number>(this.userKey(userId, dimension))) ?? 0;
  }

  async snapshot(): Promise<Record<BudgetDimension, number>> {
    const stored = await this.ctx.storage.get<number>(DIMENSIONS.map(dimensionKey));
    const out: Record<BudgetDimension, number> = {} as Record<BudgetDimension, number>;
    for (const d of DIMENSIONS) out[d] = stored.get(dimensionKey(d)) ?? 0;
    return out;
  }
}
