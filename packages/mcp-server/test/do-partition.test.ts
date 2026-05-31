import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

// ─── Phase 0.12 — Durable Object partition proof ──────────────────────────────
// Proves token isolation per (user,instance) and that the GLOBAL budget counter
// coordinates through a SINGLE date-keyed object (plan §2.5/§2.10).

interface TestEnv {
  TOKEN_DO: DurableObjectNamespace<import("../src/do/token-store.js").TokenStoreDO>;
  BUDGET_DO: DurableObjectNamespace<import("../src/do/budget.js").BudgetDO>;
  LEDGER_DO: DurableObjectNamespace<import("../src/do/mutation-ledger.js").MutationLedgerDO>;
}
const E = env as unknown as TestEnv;

function tokenStub(userId: string, instanceHost: string) {
  const ns = E.TOKEN_DO;
  return ns.get(ns.idFromName(`${userId}|${instanceHost}`));
}

describe("Phase 0.12 — TokenStoreDO isolation per (user, instance)", () => {
  it("does not leak tokens across users or instances, and revoke is scoped", async () => {
    const a1 = tokenStub("userA", "inst1.service-now.com");
    const b1 = tokenStub("userB", "inst1.service-now.com");
    const a2 = tokenStub("userA", "inst2.service-now.com");

    await a1.putToken("refresh", "A1-token");
    await b1.putToken("refresh", "B1-token");
    await a2.putToken("refresh", "A2-token");

    expect(await a1.getToken("refresh")).toBe("A1-token");
    expect(await b1.getToken("refresh")).toBe("B1-token");
    expect(await a2.getToken("refresh")).toBe("A2-token");

    // Revoking userA@inst1 must not affect userB@inst1 or userA@inst2 (plan §2.7 S7).
    await a1.revokeAll();
    expect(await tokenStub("userA", "inst1.service-now.com").getToken("refresh")).toBeUndefined();
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

    await ref1.increment("uniqueWorkers", 3);
    const total = await ref2.increment("uniqueWorkers", 2); // sees ref1's increment
    expect(total).toBe(5);
    expect(await ref1.get("uniqueWorkers")).toBe(5);
  });

  it("different date keys are independent objects", async () => {
    const ns = E.BUDGET_DO;
    const a = ns.get(ns.idFromName("2026-05-31"));
    await a.increment("uniqueWorkers", 7);
    const b = ns.get(ns.idFromName("2026-06-01"));
    expect(await b.get("uniqueWorkers")).toBe(0);
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
    expect(replay).toEqual({ state: "replay", result: { sys_id: "abc", ok: true } });
  });

  it("S17 — an INDETERMINATE runServerScript is NOT silently re-executed on retry", async () => {
    const l = ledger("k-l2");
    expect(await l.begin("hashB")).toEqual({ state: "new" });
    await l.markIndeterminate();
    const retry = await ledger("k-l2").begin("hashB");
    expect(retry).toEqual({ state: "blocked", status: "indeterminate" });
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
