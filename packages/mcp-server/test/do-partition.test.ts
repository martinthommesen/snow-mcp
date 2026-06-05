import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  MUTATION_LEDGER_MAX_REPLAY_BYTES,
  MUTATION_LEDGER_RETENTION_MS,
  normalizeLedgerRecordForStorage,
} from "../src/do/mutation-ledger.js";
import { replaySafeResult, visibleReplayResult, type ReplaySafeWrapper } from "../src/sn/replay-payload.js";

// ─── Phase 0.12 — Durable Object partition proof ──────────────────────────────
// Proves token isolation per (user,instance) and that the GLOBAL budget counter
// coordinates through a SINGLE date-keyed object (plan §2.5/§2.10).

interface TestEnv {
  TOKEN_DO: DurableObjectNamespace<import("../src/do/token-store.js").TokenStoreDO>;
  BUDGET_DO: DurableObjectNamespace<import("../src/do/budget.js").BudgetDO>;
  LEDGER_DO: DurableObjectNamespace<import("../src/do/mutation-ledger.js").MutationLedgerDO>;
  CONSENT_RATE_DO: DurableObjectNamespace<import("../src/do/consent-rate.js").ConsentRateDO>;
  MCP_ADMISSION_DO: DurableObjectNamespace<import("../src/do/mcp-admission.js").McpAdmissionDO>;
}
const E = env as unknown as TestEnv;

function tokenStub(userId: string, instanceHost: string) {
  const ns = E.TOKEN_DO;
  return ns.get(ns.idFromName(`${userId}|${instanceHost}`));
}

describe("Phase 0.12 — TokenStoreDO isolation per (user, instance)", () => {
  it("does not leak tokens across users or instances", async () => {
    const a1 = tokenStub("userA", "inst1.service-now.com");
    const b1 = tokenStub("userB", "inst1.service-now.com");
    const a2 = tokenStub("userA", "inst2.service-now.com");

    await a1.putToken("refresh", "A1-token");
    await b1.putToken("refresh", "B1-token");
    await a2.putToken("refresh", "A2-token");

    expect(await a1.getToken("refresh")).toBe("A1-token");
    expect(await b1.getToken("refresh")).toBe("B1-token");
    expect(await a2.getToken("refresh")).toBe("A2-token");

    expect(await b1.getToken("refresh")).toBe("B1-token");
    expect(await a2.getToken("refresh")).toBe("A2-token");
  });
});

describe("Phase 0.12 — BudgetDO global counter coordinates through ONE object", () => {
  it("two references to the same global date key share state (single source of truth)", async () => {
    const ns = E.BUDGET_DO;
    const day = "2026-05-30"; // global cap object is keyed by date only (§2.10)
    const ref1 = ns.get(ns.idFromName(day));
    const ref2 = ns.get(ns.idFromName(day)); // independent stub, SAME object

    // §P5: increment now takes a dimension MAP (+ optional userId) and returns void; the
    // global counter is read back via get(). Both refs see the SAME global object.
    await ref1.increment({ uniqueWorkers: 3 });
    await ref2.increment({ uniqueWorkers: 2 }); // sees ref1's increment
    expect(await ref1.get("uniqueWorkers")).toBe(5);
  });

  it("different date keys are independent objects", async () => {
    const ns = E.BUDGET_DO;
    const a = ns.get(ns.idFromName("2026-05-31"));
    await a.increment({ uniqueWorkers: 7 });
    const b = ns.get(ns.idFromName("2026-06-01"));
    expect(await b.get("uniqueWorkers")).toBe(0);
  });
});

describe("MutationLedgerDO replay storage", () => {
  it("normalizes retained rows without expiresAt instead of letting them re-execute", () => {
    const now = 1_700_000_000_000;

    const indeterminate = normalizeLedgerRecordForStorage({ status: "indeterminate", requestHash: "h1" }, now);
    expect(indeterminate).toEqual({
      kind: "migrated",
      record: { status: "indeterminate", requestHash: "h1", expiresAt: now + MUTATION_LEDGER_RETENTION_MS },
    });

    const completed = normalizeLedgerRecordForStorage({
      status: "completed",
      requestHash: "h2",
      result: { ok: true },
    }, now);
    expect(completed).toMatchObject({
      kind: "migrated",
      record: { status: "completed", requestHash: "h2", expiresAt: now + MUTATION_LEDGER_RETENTION_MS },
    });
    expect(visibleReplayResult((completed as { record: { result: ReplaySafeWrapper } }).record.result)).toEqual({ ok: true });

    expect(normalizeLedgerRecordForStorage({ status: "failed", requestHash: "h3" }, now)).toEqual({ kind: "expired" });
  });

  it("keeps expired unknown outcomes blocked instead of turning them into fresh claims", () => {
    const now = 1_700_000_000_000;

    expect(normalizeLedgerRecordForStorage({
      status: "indeterminate",
      requestHash: "h1",
      expiresAt: now - 1,
    }, now)).toMatchObject({
      kind: "migrated",
      record: { status: "indeterminate", requestHash: "h1", expiresAt: now + MUTATION_LEDGER_RETENTION_MS },
    });
    expect(normalizeLedgerRecordForStorage({
      status: "started",
      requestHash: "h2",
      expiresAt: now - 1,
    }, now)).toMatchObject({
      kind: "migrated",
      record: { status: "started", requestHash: "h2", expiresAt: now + MUTATION_LEDGER_RETENTION_MS },
    });
    expect(normalizeLedgerRecordForStorage({
      status: "completed",
      requestHash: "h3",
      expiresAt: now - 1,
      result: { ok: true },
    }, now)).toEqual({ kind: "expired" });
  });

  it("caps oversized completed replay payloads before durable storage", async () => {
    const ns = E.LEDGER_DO;
    const obj = ns.get(ns.idFromName(`ledger-cap-${crypto.randomUUID()}`));
    const requestHash = "hash-1";

    await expect(obj.begin(requestHash)).resolves.toEqual({ state: "new" });
    await obj.complete({ secret: "x".repeat(MUTATION_LEDGER_MAX_REPLAY_BYTES + 1024) });

    const replay = await obj.begin(requestHash);
    expect(replay).toMatchObject({
      state: "replay",
      result: {
        truncated: true,
        totalBytes: expect.any(Number),
        serializedResult: expect.any(String),
      },
    });
    expect((replay as { result: { serializedResult: string } }).result.serializedResult).toHaveLength(
      MUTATION_LEDGER_MAX_REPLAY_BYTES,
    );
  });

  it("serializes parallel begin/complete calls through one promise chain", async () => {
    const ns = E.LEDGER_DO;
    const obj = ns.get(ns.idFromName(`ledger-parallel-${crypto.randomUUID()}`));
    const requestHash = "hash-parallel";

    expect(await obj.begin(requestHash)).toEqual({ state: "new" });
    const results = await Promise.all([
      obj.complete({ ok: true }),
      obj.begin(requestHash),
      obj.begin("different-hash"),
      obj.complete({ ignored: true }),
    ]);
    expect(results.slice(1)).toEqual(expect.arrayContaining([
      expect.objectContaining({ state: expect.stringMatching(/blocked|replay/) }),
    ]));
    const finalReplay = await obj.begin(requestHash);
    expect(finalReplay).toMatchObject({
      state: "replay",
      result: { replaySafe: true, truncated: false, serializedResult: expect.any(String) },
    });
    expect(visibleReplayResult((finalReplay as { result: ReplaySafeWrapper }).result)).toEqual({ ok: true });
  });

  it("does not trust caller-shaped replay wrappers that exceed the cap", () => {
    const out = replaySafeResult({
      truncated: true,
      totalBytes: 1,
      serializedResult: "x".repeat(MUTATION_LEDGER_MAX_REPLAY_BYTES + 1024),
    });
    expect(out).toMatchObject({
      truncated: true,
      totalBytes: expect.any(Number),
      serializedResult: expect.any(String),
    });
    expect((out as { serializedResult: string }).serializedResult).toHaveLength(MUTATION_LEDGER_MAX_REPLAY_BYTES);
  });
});

describe("Phase 4.5 / S14 — BudgetDO atomic reserve-before-load (global cap)", () => {
  it("all-or-nothing: a reserve that would breach any dimension increments nothing", async () => {
    const ns = E.BUDGET_DO;
    const obj = ns.get(ns.idFromName("2026-07-01"));
    const r1 = await obj.reserve({ uniqueWorkers: 2, sandboxRpcCalls: 5 }, { uniqueWorkers: 3, sandboxRpcCalls: 100 });
    expect(r1.ok).toBe(true);
    // Next reserve would push uniqueWorkers to 4 > cap 3 -> rejected, nothing committed.
    const r2 = await obj.reserve({ uniqueWorkers: 2, sandboxRpcCalls: 5 }, { uniqueWorkers: 3, sandboxRpcCalls: 100 });
    expect(r2.ok).toBe(false);
    if (!r2.ok) expect(r2.dimension).toBe("uniqueWorkers");
    expect(await obj.get("uniqueWorkers")).toBe(2); // unchanged by the failed reserve
    expect(await obj.get("sandboxRpcCalls")).toBe(5);
  });

  it("S14 — parallel reserves through the single global object cannot exceed the cap", async () => {
    const ns = E.BUDGET_DO;
    const obj = ns.get(ns.idFromName("2026-07-02")); // global date-keyed object
    const cap = { uniqueWorkers: 10 };
    // 25 concurrent reservations of 1 unique Worker each; only 10 may succeed.
    const results = await Promise.all(
      Array.from({ length: 25 }, () => obj.reserve({ uniqueWorkers: 1 }, cap)),
    );
    const granted = results.filter((r) => r.ok).length;
    expect(granted).toBe(10);
    expect(await obj.get("uniqueWorkers")).toBe(10); // never over-committed
  });
});

// ─── Phase P5 — BudgetDO global + per-user, atomic accrual, admission ──────────
describe("Phase P5 — BudgetDO concurrent increments do not lose updates (mutex)", () => {
  it("100 concurrent increments through one object all land (no lost read-check-write)", async () => {
    const ns = E.BUDGET_DO;
    const obj = ns.get(ns.idFromName("2026-08-01"));
    // increment() formerly had NO mutex (CODE_REVIEW finding 18) and raced reserveCritical,
    // losing updates. With the promise-chain mutex, every increment must land.
    await Promise.all(Array.from({ length: 100 }, () => obj.increment({ rowsReturned: 1 })));
    expect(await obj.get("rowsReturned")).toBe(100);
  });

  it("concurrent reserve + increment on the same dimension never lose an update", async () => {
    const ns = E.BUDGET_DO;
    const obj = ns.get(ns.idFromName("2026-08-02"));
    const cap = { sandboxRpcCalls: 1_000_000 };
    const ops: Promise<unknown>[] = [];
    for (let i = 0; i < 50; i++) {
      ops.push(obj.reserve({ sandboxRpcCalls: 1 }, cap));
      ops.push(obj.increment({ sandboxRpcCalls: 1 }));
    }
    await Promise.all(ops);
    // 50 reserves (+1 each) + 50 increments (+1 each) = 100, none lost to interleaving.
    expect(await obj.get("sandboxRpcCalls")).toBe(100);
  });
});

describe("Finding 5 — BudgetDO reserve-max + reconcile (refund) bounds concurrent overshoot", () => {
  it("refunds the unused reservation: reserve max, reconcile to a smaller actual", async () => {
    const ns = E.BUDGET_DO;
    const obj = ns.get(ns.idFromName("2026-09-01"));
    const cap = { serviceNowRequests: 1_000_000, sandboxRpcCalls: 1_000_000, outboundBytesSent: 1_000_000 };
    // Reserve the per-run MAX, then reconcile to the ACTUAL spend.
    await obj.reserve({ serviceNowRequests: 200, sandboxRpcCalls: 200, outboundBytesSent: 1000 }, cap, "userR");
    await obj.reconcile({
      serviceNowRequests: 3 - 200,
      sandboxRpcCalls: 5 - 200,
      outboundBytesSent: 70 - 1000,
      rowsReturned: 7,
    }, "userR");
    expect(await obj.get("serviceNowRequests")).toBe(3); // 200 reserved − 197 refunded
    expect(await obj.get("sandboxRpcCalls")).toBe(5);
    expect(await obj.get("outboundBytesSent")).toBe(70);
    expect(await obj.get("rowsReturned")).toBe(7); // unreserved dimension accrues positively
    expect(await obj.getUser("userR", "serviceNowRequests")).toBe(3);
    expect(await obj.getUser("userR", "outboundBytesSent")).toBe(70);
  });

  it("clamps a counter at >= 0 (a refund larger than the stored value cannot go negative)", async () => {
    const ns = E.BUDGET_DO;
    const obj = ns.get(ns.idFromName("2026-09-02"));
    await obj.increment({ serviceNowRequests: 10 });
    await obj.reconcile({ serviceNowRequests: -999 }); // over-refund
    expect(await obj.get("serviceNowRequests")).toBe(0);
  });

  it("denies the (N+1)th concurrent reserve once N×max would exceed the daily cap", async () => {
    const ns = E.BUDGET_DO;
    const obj = ns.get(ns.idFromName("2026-09-03"));
    const cap = { serviceNowRequests: 500 }; // exactly 2 runs' worth at 200 reserved + 1 uniqueWorker
    const r1 = await obj.reserve({ uniqueWorkers: 1, serviceNowRequests: 200 }, cap);
    const r2 = await obj.reserve({ uniqueWorkers: 1, serviceNowRequests: 200 }, cap);
    const r3 = await obj.reserve({ uniqueWorkers: 1, serviceNowRequests: 200 }, cap);
    expect(r1.ok).toBe(true);
    expect(r2.ok).toBe(true);
    expect(r3.ok).toBe(false); // 3×200 = 600 > 500 cap — concurrent overshoot is bounded
    if (!r3.ok) expect(r3.dimension).toBe("serviceNowRequests");
  });

  it("denies the (N+1)th outbound reserve once N×maxOutboundBytes would exceed the daily cap", async () => {
    const ns = E.BUDGET_DO;
    const obj = ns.get(ns.idFromName("2026-09-04"));
    const cap = { outboundBytesSent: 500 };
    const r1 = await obj.reserve({ uniqueWorkers: 1, outboundBytesSent: 200 }, cap);
    const r2 = await obj.reserve({ uniqueWorkers: 1, outboundBytesSent: 200 }, cap);
    const r3 = await obj.reserve({ uniqueWorkers: 1, outboundBytesSent: 200 }, cap);
    expect(r1.ok).toBe(true);
    expect(r2.ok).toBe(true);
    expect(r3.ok).toBe(false);
    if (!r3.ok) expect(r3.dimension).toBe("outboundBytesSent");
  });
});

describe("Finding 4 — ConsentRateDO bounds consent writes per key per window", () => {
  it("allows up to the window cap, then denies; a later window resets", async () => {
    const ns = E.CONSENT_RATE_DO;
    const obj = ns.get(ns.idFromName("consent-rate"));
    const t0 = 1_000_000;
    let allowed = 0;
    // 40 attempts in one window: only the first 30 (MAX_PER_WINDOW) are admitted.
    for (let i = 0; i < 40; i++) if (await obj.allow("clientA|1.2.3.4", t0)) allowed++;
    expect(allowed).toBe(30);
    expect(await obj.allow("clientA|1.2.3.4", t0)).toBe(false); // still over cap in-window
    // A request after the window (60s) rolls into a fresh window and is admitted again.
    expect(await obj.allow("clientA|1.2.3.4", t0 + 60_001)).toBe(true);
  });

  it("isolates counters per key (a flood on one IP doesn't block another)", async () => {
    const ns = E.CONSENT_RATE_DO;
    const obj = ns.get(ns.idFromName("consent-rate"));
    const t0 = 2_000_000;
    for (let i = 0; i < 30; i++) await obj.allow("9.9.9.9", t0); // exhaust one key
    expect(await obj.allow("9.9.9.9", t0)).toBe(false);
    expect(await obj.allow("8.8.8.8", t0)).toBe(true); // a different key is unaffected
  });

  it("enforces the MAX_KEYS hard cap: the map never grows past it; oldest is evicted", { timeout: 60_000 }, async () => {
    const ns = E.CONSENT_RATE_DO;
    const obj = ns.get(ns.idFromName("cap-probe")); // a fresh DO instance
    const MAX_KEYS = 10_000;
    const t0 = 5_000_000;
    // Drive the very first IP to its cap, then insert MAX_KEYS distinct new IPs (same window).
    for (let i = 0; i < 30; i++) await obj.allow("ip-0", t0);
    expect(await obj.allow("ip-0", t0)).toBe(false); // ip-0 is at cap
    for (let i = 1; i <= MAX_KEYS; i++) await obj.allow("ip-" + i, t0); // forces eviction of oldest
    expect(await obj.count()).toBe(MAX_KEYS); // NEVER exceeds the bound (was unbounded before)
    // ip-0 (oldest-inserted) was evicted, so it now gets a FRESH window (true), not the stale cap.
    expect(await obj.allow("ip-0", t0)).toBe(true);
  });
});

describe("McpAdmissionDO bounds authenticated /mcp requests per user", () => {
  function admission(key: string) {
    const ns = E.MCP_ADMISSION_DO;
    return ns.get(ns.idFromName(key));
  }

  it("enforces four in-flight leases, releases in-flight slots, and prunes stale leases", async () => {
    const obj = admission(`user-admit-${crypto.randomUUID()}`);
    const t0 = 1_000_000;
    const leases = [];
    for (let i = 0; i < 4; i++) {
      const r = await obj.admit(t0);
      expect(r.ok).toBe(true);
      if (r.ok) leases.push(r.leaseId);
    }
    const denied = await obj.admit(t0);
    expect(denied).toMatchObject({ ok: false, reason: "concurrency" });
    await obj.release(leases[0]!);
    expect(await obj.admit(t0 + 1)).toMatchObject({ ok: true });
    expect(await obj.snapshot(t0 + 75_001)).toMatchObject({ inFlight: 0 });
  });

  it("renews active leases so long-lived streams keep their in-flight slots", async () => {
    const obj = admission(`user-renew-${crypto.randomUUID()}`);
    const t0 = 1_500_000;
    const leases = [];
    for (let i = 0; i < 4; i++) {
      const r = await obj.admit(t0);
      expect(r.ok).toBe(true);
      if (r.ok) leases.push(r.leaseId);
    }

    for (const lease of leases) {
      expect(await obj.renew(lease, t0 + 74_000)).toBe(true);
    }

    expect(await obj.snapshot(t0 + 75_001)).toMatchObject({ inFlight: 4 });
    expect(await obj.admit(t0 + 75_001)).toMatchObject({ ok: false, reason: "concurrency" });
  });

  it("enforces the 60 request/minute authenticated rate cap per user object", async () => {
    const obj = admission(`user-rate-${crypto.randomUUID()}`);
    const t0 = 2_000_000;
    for (let i = 0; i < 60; i++) {
      const r = await obj.admit(t0 + i);
      expect(r.ok).toBe(true);
      if (r.ok) await obj.release(r.leaseId);
    }
    expect(await obj.admit(t0 + 59_999)).toMatchObject({ ok: false, reason: "rate" });
    expect(await obj.admit(t0 + 60_001)).toMatchObject({ ok: true });
  });
});

describe("Phase P5 — BudgetDO per-user isolation (global = sum of users)", () => {
  it("per-user tallies are isolated and the global counter is their sum", async () => {
    const ns = E.BUDGET_DO;
    const obj = ns.get(ns.idFromName("2026-08-03"));
    await obj.increment({ rowsReturned: 30, bytesReturned: 300, outboundBytesSent: 50 }, "userA");
    await obj.increment({ rowsReturned: 12, bytesReturned: 120, outboundBytesSent: 25 }, "userB");
    // Per-user views are isolated.
    expect(await obj.getUser("userA", "rowsReturned")).toBe(30);
    expect(await obj.getUser("userB", "rowsReturned")).toBe(12);
    expect(await obj.getUser("userA", "bytesReturned")).toBe(300);
    expect(await obj.getUser("userA", "outboundBytesSent")).toBe(50);
    // The GLOBAL counter is the enforced ceiling = sum across users (shared-fate).
    expect(await obj.get("rowsReturned")).toBe(42);
    expect(await obj.get("bytesReturned")).toBe(420);
    expect(await obj.get("outboundBytesSent")).toBe(75);
  });

  it("reserve() also updates the per-user view in the same gate", async () => {
    const ns = E.BUDGET_DO;
    const obj = ns.get(ns.idFromName("2026-08-04"));
    await obj.reserve({ uniqueWorkers: 1, serviceNowRequests: 1 }, undefined, "userC");
    expect(await obj.getUser("userC", "uniqueWorkers")).toBe(1);
    expect(await obj.getUser("userC", "serviceNowRequests")).toBe(1);
    expect(await obj.get("uniqueWorkers")).toBe(1);
  });

  it("snapshot returns the batched global counter view", async () => {
    const ns = E.BUDGET_DO;
    const obj = ns.get(ns.idFromName("2026-08-08"));
    await obj.increment({ uniqueWorkers: 2, rowsReturned: 30 }, "userA");
    await obj.reserve({ serviceNowRequests: 3 }, undefined, "userB");
    expect(await obj.snapshot()).toMatchObject({
      uniqueWorkers: 2,
      serviceNowRequests: 3,
      rowsReturned: 30,
      bytesReturned: 0,
      outboundBytesSent: 0,
      sandboxRpcCalls: 0,
    });
  });
});

describe("Phase P5 — BudgetDO daily rows/bytes admission check (tier 1)", () => {
  it("denies the next run when the day's accrued rows are already at/over cap", async () => {
    const ns = E.BUDGET_DO;
    const obj = ns.get(ns.idFromName("2026-08-05"));
    const cap = { rowsReturned: 100 };
    // Prior runs accrued rows to the cap (post-run accrual path).
    await obj.increment({ rowsReturned: 100 });
    // The NEXT run reserves only uniqueWorkers/requests (rows can't be pre-reserved), but the
    // admission check must DENY it because the day is already at the rows cap.
    const r = await obj.reserve({ uniqueWorkers: 1, serviceNowRequests: 1 }, cap, "userD");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.dimension).toBe("rowsReturned");
    // Nothing was committed by the denied reserve.
    expect(await obj.get("uniqueWorkers")).toBe(0);
  });

  it("admits the next run while the day is under the rows/bytes cap", async () => {
    const ns = E.BUDGET_DO;
    const obj = ns.get(ns.idFromName("2026-08-06"));
    const cap = { rowsReturned: 100, bytesReturned: 1000 };
    await obj.increment({ rowsReturned: 99, bytesReturned: 999 });
    const r = await obj.reserve({ uniqueWorkers: 1, serviceNowRequests: 1 }, cap, "userE");
    expect(r.ok).toBe(true);
    expect(await obj.get("uniqueWorkers")).toBe(1);
  });

  it("denies the next run when the day's accrued sandboxRpcCalls are already at/over cap (M-1)", async () => {
    // M-1: sandboxRpcCalls is accrued post-run (handlers maps snapshot.rpcCalls -> sandboxRpcCalls)
    // and was previously compared NOWHERE — the configured daily cap was dead. The admission check
    // must now DENY the next run once the day is at/over the sandboxRpcCalls cap (T-1: every
    // configured ceiling has a test proving it can deny).
    const ns = E.BUDGET_DO;
    const obj = ns.get(ns.idFromName("2026-08-07"));
    const cap = { sandboxRpcCalls: 50 };
    await obj.increment({ sandboxRpcCalls: 50 }); // prior runs accrued to the cap
    const r = await obj.reserve({ uniqueWorkers: 1, serviceNowRequests: 1 }, cap, "userF");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.dimension).toBe("sandboxRpcCalls");
    expect(await obj.get("uniqueWorkers")).toBe(0); // nothing committed by the denied reserve
  });

  it("denies the next run when the day's accrued outboundBytesSent is already at/over cap", async () => {
    const ns = E.BUDGET_DO;
    const obj = ns.get(ns.idFromName("2026-08-09"));
    const cap = { outboundBytesSent: 100 };
    await obj.increment({ outboundBytesSent: 100 });
    const r = await obj.reserve({ uniqueWorkers: 1, serviceNowRequests: 1 }, cap, "userG");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.dimension).toBe("outboundBytesSent");
    expect(await obj.get("uniqueWorkers")).toBe(0);
  });
});

describe("Phase 7.3 / S17 — MutationLedgerDO leveled idempotency", () => {
  function ledger(key: string) {
    const ns = E.LEDGER_DO;
    return ns.get(ns.idFromName(`userA|inst1|${key}`));
  }

  it("Level 1 — a completed key REPLAYS the original result (no re-execute)", async () => {
    const l = ledger("k-l1");
    expect(await l.begin("hashA")).toEqual({ state: "new" });
    await l.complete({ sys_id: "abc", ok: true });
    const replay = await ledger("k-l1").begin("hashA");
    expect(replay).toMatchObject({
      state: "replay",
      result: { replaySafe: true, truncated: false, serializedResult: expect.any(String) },
    });
    expect(visibleReplayResult((replay as { result: ReplaySafeWrapper }).result)).toEqual({ sys_id: "abc", ok: true });
  });

  it("S17 — an INDETERMINATE runServerScript is NOT silently re-executed on retry", async () => {
    const l = ledger("k-l2");
    expect(await l.begin("hashB")).toEqual({ state: "new" });
    await l.markIndeterminate();
    const retry = await ledger("k-l2").begin("hashB");
    expect(retry).toEqual({ state: "blocked", status: "indeterminate" });
  });

  it("does not let a late complete() clobber an indeterminate record", async () => {
    const l = ledger("k-no-clobber-indeterminate");
    expect(await l.begin("hash-indeterminate")).toEqual({ state: "new" });
    await l.markIndeterminate();
    await l.complete({ ok: true });
    expect(await l.status()).toBe("indeterminate");
    expect(await ledger("k-no-clobber-indeterminate").begin("hash-indeterminate")).toEqual({
      state: "blocked",
      status: "indeterminate",
    });
  });

  it("does not let a late markIndeterminate() clobber a clean failed record", async () => {
    const l = ledger("k-no-clobber-failed");
    expect(await l.begin("hash-failed")).toEqual({ state: "new" });
    await l.fail();
    await l.markIndeterminate();
    expect(await l.status()).toBe("failed");
    expect(await ledger("k-no-clobber-failed").begin("hash-failed")).toEqual({ state: "new" });
  });

  it("does not let a late fail() clobber a completed replay record", async () => {
    const l = ledger("k-no-clobber-completed");
    expect(await l.begin("hash-completed")).toEqual({ state: "new" });
    await l.complete({ ok: true });
    await l.fail();
    expect(await l.status()).toBe("completed");
    expect((await ledger("k-no-clobber-completed").begin("hash-completed")).state).toBe("replay");
  });

  it("an in-flight (started) key blocks a concurrent duplicate", async () => {
    const l = ledger("k-inflight");
    expect((await l.begin("h")).state).toBe("new");
    expect((await ledger("k-inflight").begin("h")).state).toBe("blocked");
  });

  it("a clean failure permits a retry", async () => {
    const l = ledger("k-fail");
    await l.begin("h");
    await l.fail();
    expect((await ledger("k-fail").begin("h")).state).toBe("new");
  });

  it("a request-hash mismatch on an existing key is blocked (conflict)", async () => {
    const l = ledger("k-conflict");
    await l.begin("hash1");
    await l.complete({ x: 1 });
    expect((await ledger("k-conflict").begin("DIFFERENT")).state).toBe("blocked");
  });

  it("P4 — complete() WITHOUT a matching begin() does NOT fabricate a record (no false replay)", async () => {
    // The pre-P4 complete() invented { requestHash: "" } when the row was missing, which
    // would replay a stored result for ANY future begin() with an empty-string hash.
    const l = ledger("k-stray");
    await l.complete({ leaked: true }); // stray complete, no begin
    expect(await l.status()).toBe("none"); // nothing was stamped
    // A subsequent real begin() with the empty hash still claims "new" (no false replay).
    expect((await ledger("k-stray").begin("")).state).toBe("new");
  });
});
