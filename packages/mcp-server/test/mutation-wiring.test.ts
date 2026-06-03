import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { ServiceNowRPC, type MutationDeps } from "../src/sn/rpc.js";
import { RunBudget } from "../src/sn/run-budget.js";
import { BUDGETS } from "../src/config.js";
import { permissivePolicy, type ActorPolicy } from "../src/authz/actor-policy.js";
import type { SnHttpClient, SnRequest, SnResponse } from "../src/sn/http.js";
import { mutationLedgerObjectName, type LedgerHandle, type RunContext } from "../src/sn/mutation-guard.js";
import type { AuditRecord } from "../src/observability/audit.js";

// ─── Phase P4 — the unwired safety layers, now WIRED into the live mutating path ─────
// These exercise the real ServiceNowRPC.tableUpdate / runServerScript against a mock SN,
// the real MutationLedgerDO (idempotency), and in-memory audit/snapshot/approval fakes.
// They assert the NEW secure behavior the live path must enforce (they would fail against
// the pre-P4 RPC, which sent the PATCH/POST with no ledger / audit / snapshot / approval).

interface TestEnv {
  LEDGER_DO: DurableObjectNamespace<import("../src/do/mutation-ledger.js").MutationLedgerDO>;
}
const E = env as unknown as TestEnv;
const INSTANCE = "inst1.service-now.com";

/** A mock SN client; records calls and lets a test override the PATCH/GET/POST behavior. */
class MockHttp implements SnHttpClient {
  calls: SnRequest[] = [];
  patchHandler: (req: SnRequest) => SnResponse | Promise<SnResponse> = () => ({ status: 200, json: { result: { sys_id: "a1", updated: true } } });
  getHandler: (req: SnRequest) => SnResponse | Promise<SnResponse> = () => ({ status: 200, json: { result: { sys_id: "a1", state: "1", short_description: "old" } } });
  postHandler: (req: SnRequest) => SnResponse | Promise<SnResponse> = () => ({ status: 200, json: { ok: true } });
  async request(req: SnRequest): Promise<SnResponse> {
    this.calls.push(req);
    if (req.method === "PATCH") return this.patchHandler(req);
    if (req.method === "POST") return this.postHandler(req);
    return this.getHandler(req);
  }
}

/** Ledger handle backed by the real MutationLedgerDO (so begin/complete/markIndeterminate
 *  semantics are genuinely exercised, not faked). */
function realLedger(runKey: string): (ordinal: number) => LedgerHandle {
  return (ordinal) => {
    const ns = E.LEDGER_DO;
    return ns.get(ns.idFromName(mutationLedgerObjectName({ userId: "userA", instanceHost: INSTANCE, runKey, ordinal }))) as unknown as LedgerHandle;
  };
}

const SIGNING = {
  claims: {
    mcp_actor_user_id: "userA", mcp_actor_email: "a@x.com", snow_effective_user_sys_id: "",
    instance: INSTANCE, request_id: "req-1",
  },
  hmacKey: new Uint8Array(32).fill(7),
  nonce: () => crypto.randomUUID(),
  now: () => 1_700_000_000_000,
};

function mutationDeps(over: Partial<MutationDeps> & { runContext: RunContext }): MutationDeps {
  return {
    identity: { mcpActorUserId: "userA" },
    now: () => 1_700_000_000_000,
    ...over,
  };
}

function rpc(opts: {
  http?: MockHttp; mode?: "write" | "admin_script"; mutation: MutationDeps; signing?: boolean; actorPolicy?: ActorPolicy; runBudget?: RunBudget;
}): ServiceNowRPC {
  return new ServiceNowRPC({
    http: opts.http ?? new MockHttp(),
    instanceHost: INSTANCE,
    effectiveMode: opts.mode ?? "write",
    actorPolicy: opts.actorPolicy ?? permissivePolicy([INSTANCE]),
    runBudget: opts.runBudget ?? new RunBudget(),
    mutation: opts.mutation,
    ...(opts.signing ? { signing: SIGNING, executorPath: "/api/x_1793136_mcp/x_mcp/executor/run" } : {}),
  });
}

const SYS_ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

describe("P4 — idempotency ledger wired into tableUpdate", () => {
  it("keeps the ledger Durable Object name stable across deploys", () => {
    expect(mutationLedgerObjectName({ userId: "userA", instanceHost: INSTANCE, runKey: "k1", ordinal: 1 })).toBe(
      `userA|${INSTANCE}|k1:1`,
    );
  });

  it("a mutating RPC with NO tool-level idempotencyKey is denied (capability_denied)", async () => {
    const http = new MockHttp();
    const r = rpc({ http, mutation: mutationDeps({ runContext: { requestId: "r-nokey" } }) });
    await expect(
      r.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } }),
    ).rejects.toMatchObject({ code: "capability_denied" });
    // No PATCH ever left the host.
    expect(http.calls.filter((c) => c.method === "PATCH")).toHaveLength(0);
  });

  it("FAILS CLOSED when the live path requires durability but the ledger is missing", async () => {
    const http = new MockHttp();
    const r = rpc({
      http,
      mutation: mutationDeps({
        runContext: { requestId: "r-no-ledger", runKey: "k1" },
        durabilityRequired: true,
        audit: async () => {},
      }),
    });
    await expect(
      r.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } }),
    ).rejects.toMatchObject({ code: "internal_error" });
    expect(http.calls.filter((c) => c.method === "PATCH")).toHaveLength(0);
  });

  it("FAILS CLOSED when the live path requires durability but audit is missing", async () => {
    const runKey = `no-audit-${crypto.randomUUID()}`;
    const http = new MockHttp();
    const r = rpc({
      http,
      mutation: mutationDeps({
        runContext: { requestId: "r-no-audit", runKey },
        durabilityRequired: true,
        ledger: realLedger(runKey),
      }),
    });
    await expect(
      r.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } }),
    ).rejects.toMatchObject({ code: "internal_error" });
    expect(http.calls.filter((c) => c.method === "PATCH")).toHaveLength(0);
  });

  it("P2a: a durability-required mutation with NO runKey is denied AND audited (not internal_error)", async () => {
    // With audit present, a missing idempotencyKey must surface as capability_denied with a
    // denial audit row — the audit-require check must NOT pre-empt the denial.
    const rows: AuditRecord[] = [];
    const http = new MockHttp();
    const r = rpc({
      http,
      mutation: mutationDeps({
        runContext: { requestId: "r-dur-nokey" },
        durabilityRequired: true,
        audit: async (rec) => { rows.push(rec); },
      }),
    });
    await expect(
      r.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } }),
    ).rejects.toMatchObject({ code: "capability_denied" });
    expect(http.calls.filter((c) => c.method === "PATCH")).toHaveLength(0);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ status: "denied", errorClass: "capability_denied" });
  });

  it("P2a: audit-missing + NO runKey stays internal_error (misconfig is not masked as a denial)", async () => {
    // emitDenial no-ops without an audit sink; the audit-require check must run first so a
    // missing AUDIT_KV surfaces as internal_error rather than an unaudited capability_denied.
    const http = new MockHttp();
    const r = rpc({
      http,
      mutation: mutationDeps({ runContext: { requestId: "r-dur-nokey-noaudit" }, durabilityRequired: true }),
    });
    await expect(
      r.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } }),
    ).rejects.toMatchObject({ code: "internal_error" });
    expect(http.calls.filter((c) => c.method === "PATCH")).toHaveLength(0);
  });

  it("a retried tableUpdate with the SAME tool key REPLAYS the stored result (no second PATCH)", async () => {
    const runKey = `dedup-${crypto.randomUUID()}`;
    const http1 = new MockHttp();
    const r1 = rpc({ http: http1, mutation: mutationDeps({ runContext: { requestId: "r1", runKey }, ledger: realLedger(runKey) }) });
    const first = await r1.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } });
    expect(first).toMatchObject({ updated: true });
    expect(http1.calls.filter((c) => c.method === "PATCH")).toHaveLength(1);

    // Fresh run (fresh RPC => ordinal resets to 1), same runKey => same ledger object.
    const http2 = new MockHttp();
    const r2 = rpc({ http: http2, mutation: mutationDeps({ runContext: { requestId: "r2", runKey }, ledger: realLedger(runKey) }) });
    const replay = await r2.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } });
    expect(replay).toMatchObject({ updated: true });
    // Replay returns the stored result without re-sending the PATCH.
    expect(http2.calls.filter((c) => c.method === "PATCH")).toHaveLength(0);
  });

  it("a POST-SEND-UNKNOWN failure (5xx) marks INDETERMINATE so a retry is BLOCKED, never re-applied", async () => {
    const runKey = `indet-${crypto.randomUUID()}`;
    const http1 = new MockHttp();
    http1.patchHandler = () => ({ status: 503, json: { error: { message: "gateway" } } }); // post-send unknown
    const r1 = rpc({ http: http1, mutation: mutationDeps({ runContext: { requestId: "r1", runKey }, ledger: realLedger(runKey) }) });
    await expect(r1.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } })).rejects.toBeTruthy();

    // Retry the SAME logical mutation — must be blocked (indeterminate), no second PATCH.
    const http2 = new MockHttp();
    const r2 = rpc({ http: http2, mutation: mutationDeps({ runContext: { requestId: "r2", runKey }, ledger: realLedger(runKey) }) });
    await expect(
      r2.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } }),
    ).rejects.toMatchObject({ code: "idempotency_conflict" });
    expect(http2.calls.filter((c) => c.method === "PATCH")).toHaveLength(0);
  });

  it("a DEFINITIVE server rejection (403) is a clean failure — the SAME mutation may be retried", async () => {
    const runKey = `clean-${crypto.randomUUID()}`;
    const http1 = new MockHttp();
    http1.patchHandler = () => ({ status: 403, json: { error: { message: "ACL" } } }); // did NOT apply
    const r1 = rpc({ http: http1, mutation: mutationDeps({ runContext: { requestId: "r1", runKey }, ledger: realLedger(runKey) }) });
    await expect(r1.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } })).rejects.toMatchObject({ code: "actor_policy_denied" });

    // Retry: a clean failure permits a fresh attempt (now succeeds).
    const http2 = new MockHttp();
    const r2 = rpc({ http: http2, mutation: mutationDeps({ runContext: { requestId: "r2", runKey }, ledger: realLedger(runKey) }) });
    const ok = await r2.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } });
    expect(ok).toMatchObject({ updated: true });
    expect(http2.calls.filter((c) => c.method === "PATCH")).toHaveLength(1);
  });

  it("a DIVERGENT retry under the same run key:ordinal is a conflict (blocked)", async () => {
    const runKey = `diverge-${crypto.randomUUID()}`;
    const http1 = new MockHttp();
    const r1 = rpc({ http: http1, mutation: mutationDeps({ runContext: { requestId: "r1", runKey }, ledger: realLedger(runKey) }) });
    await r1.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } });

    // Same runKey+ordinal but DIFFERENT fields => different requestHash => conflict.
    const http2 = new MockHttp();
    const r2 = rpc({ http: http2, mutation: mutationDeps({ runContext: { requestId: "r2", runKey }, ledger: realLedger(runKey) }) });
    await expect(
      r2.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "9" } }),
    ).rejects.toMatchObject({ code: "idempotency_conflict" });
    expect(http2.calls.filter((c) => c.method === "PATCH")).toHaveLength(0);
  });

  it("two mutations in one run get DISTINCT ledger ordinals (the second is not a replay)", async () => {
    const runKey = `multi-${crypto.randomUUID()}`;
    const http = new MockHttp();
    const r = rpc({ http, mutation: mutationDeps({ runContext: { requestId: "r1", runKey }, ledger: realLedger(runKey) }) });
    await r.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } });
    await r.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } });
    // Same logical fields but DIFFERENT ordinals => two real PATCHes (not deduped within a run).
    expect(http.calls.filter((c) => c.method === "PATCH")).toHaveLength(2);
  });
});

describe("P4 — host audit wired (audit-before-effect, fail-closed)", () => {
  it("emits one ok audit row per successful mutation (hashes + attribution + reason, no raw)", async () => {
    const rows: AuditRecord[] = [];
    const http = new MockHttp();
    const r = rpc({
      http,
      mutation: mutationDeps({ runContext: { requestId: "r-audit", runKey: "k1", reason: "fix it" }, audit: async (rec) => { rows.push(rec); } }),
    });
    await r.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } });
    // PRE-effect intent row (status "intent") then the superseding OUTCOME row (status "ok"),
    // both for ordinal 1 (the result row supersedes the intent at the same audit key).
    expect(rows.length).toBe(2);
    const [intent, last] = rows as [AuditRecord, AuditRecord];
    expect(intent.status).toBe("intent"); // NOT "ok": a dropped outcome reads as unresolved
    expect(intent.ordinal).toBe(1);
    expect(last.status).toBe("ok"); // success supersedes the intent
    expect(last.op).toBe("update");
    expect(last.table).toBe("incident");
    expect(last.reason).toBe("fix it");
    expect(last.ordinal).toBe(1);
    expect(last.afterHash).toBeTruthy(); // hashed, not raw
    expect((last as unknown as Record<string, unknown>).after).toBeUndefined();
  });

  it("two mutations in one run -> two audit rows + two snapshots with DISTINCT ordinals/keys", async () => {
    const rows: AuditRecord[] = [];
    const snapshots: { ordinal: number }[] = [];
    const http = new MockHttp();
    const r = rpc({
      http,
      mutation: mutationDeps({
        runContext: { requestId: "r-multi", runKey: "k1", reason: "fix it" },
        audit: async (rec) => { rows.push(rec); },
        snapshotEnabledTables: ["incident"],
        captureSnapshot: async (input) => { snapshots.push({ ordinal: input.ordinal }); return true; },
      }),
    });
    await r.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } });
    await r.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "3" } });

    // Each successful mutation emits an intent row + a superseding outcome row, across two
    // DISTINCT ordinals (1, 2) — i.e. two audit-event keys, never overwriting each other.
    expect(new Set(rows.map((x) => x.ordinal))).toEqual(new Set([1, 2]));
    // One snapshot per mutation, each at its own ordinal => two distinct snapshot keys.
    expect(snapshots.map((s) => s.ordinal)).toEqual([1, 2]);
    // Two real PATCHes (distinct ordinals => not deduped within the run).
    expect(http.calls.filter((c) => c.method === "PATCH")).toHaveLength(2);
  });

  it("a denial (no tool key) still produces a DENIED audit row", async () => {
    const rows: AuditRecord[] = [];
    const r = rpc({
      mutation: mutationDeps({ runContext: { requestId: "r-deny" }, audit: async (rec) => { rows.push(rec); } }),
    });
    await expect(r.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } })).rejects.toBeTruthy();
    expect(rows.some((x) => x.status === "denied")).toBe(true);
  });

  it("a thrown effect (503 indeterminate) is audited as status:error — the intent row never stays ok", async () => {
    // The durable row at this ordinal must reflect the OUTCOME, not the optimistic intent.
    const byOrdinal = new Map<number, AuditRecord>(); // last write per ordinal = the durable state
    const http = new MockHttp();
    http.patchHandler = () => ({ status: 503, json: { error: { message: "gateway" } } });
    const r = rpc({
      http,
      mutation: mutationDeps({
        runContext: { requestId: "r-err", runKey: "k1" },
        audit: async (rec) => { byOrdinal.set(rec.ordinal ?? -1, rec); },
      }),
    });
    await expect(r.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } })).rejects.toBeTruthy();
    const durable = byOrdinal.get(1)!;
    expect(durable.status).toBe("error"); // NOT "ok"
    expect(durable.errorClass).toContain("indeterminate"); // 503 is post-send unknown
  });

  it("AUDIT-BEFORE-EFFECT: if the audit WRITE throws, the mutation is DENIED (no PATCH)", async () => {
    const http = new MockHttp();
    const r = rpc({
      http,
      mutation: mutationDeps({ runContext: { requestId: "r-failclosed", runKey: "k1" }, audit: async () => { throw new Error("kv down"); } }),
    });
    await expect(r.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } })).rejects.toBeTruthy();
    expect(http.calls.filter((c) => c.method === "PATCH")).toHaveLength(0);
  });
});

describe("P4 — recovery snapshot wired (before-state, fail-closed)", () => {
  it("captures a before-state snapshot BEFORE the update for a reversible-class table", async () => {
    const order: string[] = [];
    const http = new MockHttp();
    http.getHandler = () => { order.push("get-before"); return { status: 200, json: { result: { sys_id: "a1", state: "1" } } }; };
    http.patchHandler = () => { order.push("patch"); return { status: 200, json: { result: { sys_id: "a1", updated: true } } }; };
    const r = rpc({
      http,
      mutation: mutationDeps({
        runContext: { requestId: "r-snap", runKey: "k1" },
        snapshotEnabledTables: ["incident"],
        captureSnapshot: async () => { order.push("snapshot"); return true; },
      }),
    });
    await r.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } });
    // before-state GET + snapshot persist BOTH happen before the PATCH (fail-closed ordering).
    expect(order.indexOf("snapshot")).toBeLessThan(order.indexOf("patch"));
    expect(order.indexOf("get-before")).toBeLessThan(order.indexOf("patch"));
  });

  it("FAILS CLOSED: a snapshot that cannot persist aborts the update (no PATCH)", async () => {
    const http = new MockHttp();
    const r = rpc({
      http,
      mutation: mutationDeps({
        runContext: { requestId: "r-snapfail", runKey: "k1" },
        snapshotEnabledTables: ["incident"],
        captureSnapshot: async () => { throw new Error("snapshot store down"); },
      }),
    });
    await expect(r.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } })).rejects.toBeTruthy();
    expect(http.calls.filter((c) => c.method === "PATCH")).toHaveLength(0);
  });

  it("no snapshot is captured for a non-reversible-class (non-configured) table", async () => {
    let captured = false;
    const http = new MockHttp();
    const r = rpc({
      http,
      mutation: mutationDeps({
        runContext: { requestId: "r-noconfig", runKey: "k1" },
        snapshotEnabledTables: ["change_request"], // incident NOT enabled
        captureSnapshot: async () => { captured = true; return true; },
      }),
    });
    await r.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } });
    expect(captured).toBe(false);
    expect(http.calls.filter((c) => c.method === "PATCH")).toHaveLength(1);
  });
});

describe("Phase 1A — row filters are enforced on tableUpdate", () => {
  const rowFilteredPolicy: ActorPolicy = {
    ...permissivePolicy([INSTANCE]),
    rowFilters: { incident: "department=hr" },
    fieldMasks: { incident: ["caller_id"] },
  };

  function scopedRpc(opts: {
    http?: MockHttp;
    runKey?: string;
    audit?: (rec: AuditRecord) => Promise<void>;
    captureSnapshot?: MutationDeps["captureSnapshot"];
    snapshotEnabledTables?: string[];
    runBudget?: RunBudget;
    ledger?: MutationDeps["ledger"];
    actorPolicy?: ActorPolicy;
  } = {}): { rpc: ServiceNowRPC; http: MockHttp; budget: RunBudget } {
    const http = opts.http ?? new MockHttp();
    if (!opts.http) {
      http.getHandler = () => ({ status: 200, json: { result: [{ sys_id: SYS_ID, state: "1", short_description: "old" }] } });
    }
    const budget = opts.runBudget ?? new RunBudget();
    return {
      http,
      budget,
      rpc: new ServiceNowRPC({
        http,
        instanceHost: INSTANCE,
        effectiveMode: "write",
        actorPolicy: opts.actorPolicy ?? rowFilteredPolicy,
        runBudget: budget,
        mutation: mutationDeps({
          runContext: { requestId: `r-${crypto.randomUUID()}`, runKey: opts.runKey ?? "k1", reason: "update scoped incident" },
          ...(opts.ledger ? { ledger: opts.ledger } : {}),
          ...(opts.audit ? { audit: opts.audit } : {}),
          ...(opts.captureSnapshot ? { captureSnapshot: opts.captureSnapshot } : {}),
          ...(opts.snapshotEnabledTables ? { snapshotEnabledTables: opts.snapshotEnabledTables } : {}),
        }),
      }),
    };
  }

  it("allows an in-scope PATCH after a filtered sys_id preflight GET", async () => {
    const { rpc: r, http } = scopedRpc();
    const out = await r.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } });
    expect(out).toMatchObject({ updated: true });
    const get = http.calls.find((c) => c.method === "GET")!;
    expect(get.path).toBe("/api/now/table/incident");
    expect(get.query).toMatchObject({ sysparm_query: `department=hr^sys_id=${SYS_ID}`, sysparm_limit: "1" });
    expect(http.calls.filter((c) => c.method === "PATCH")).toHaveLength(1);
  });

  it("replays a completed tableUpdate without re-running the live row-filter scope GET", async () => {
    const runKey = `scope-replay-${crypto.randomUUID()}`;
    const ledger = realLedger(runKey);
    const first = scopedRpc({ runKey, ledger });
    const out = await first.rpc.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } });
    expect(out).toMatchObject({ updated: true });
    expect(first.http.calls.filter((c) => c.method === "GET")).toHaveLength(1);
    expect(first.http.calls.filter((c) => c.method === "PATCH")).toHaveLength(1);

    const http = new MockHttp();
    http.getHandler = () => ({ status: 200, json: { result: [] } });
    const replay = scopedRpc({ http, runKey, ledger });
    const replayed = await replay.rpc.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } });
    expect(replayed).toMatchObject({ updated: true });
    expect(http.calls.filter((c) => c.method === "GET")).toHaveLength(0);
    expect(http.calls.filter((c) => c.method === "PATCH")).toHaveLength(0);
  });

  it("blocks a completed tableUpdate replay when the actor row-filter policy changes", async () => {
    const runKey = `scope-change-${crypto.randomUUID()}`;
    const ledger = realLedger(runKey);
    await scopedRpc({ runKey, ledger }).rpc.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } });

    const http = new MockHttp();
    const narrowedPolicy: ActorPolicy = {
      ...rowFilteredPolicy,
      rowFilters: { incident: "department=finance" },
    };
    const replay = scopedRpc({ http, runKey, ledger, actorPolicy: narrowedPolicy });
    await expect(
      replay.rpc.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } }),
    ).rejects.toMatchObject({ code: "idempotency_conflict" });
    expect(http.calls.filter((c) => c.method === "GET")).toHaveLength(0);
    expect(http.calls.filter((c) => c.method === "PATCH")).toHaveLength(0);
  });

  it("denies an out-of-scope sys_id with actor_policy_denied, emits denial audit, and sends zero PATCHes/bytes", async () => {
    const rows: AuditRecord[] = [];
    const http = new MockHttp();
    http.getHandler = () => ({ status: 200, json: { result: [] } });
    const { rpc: r, budget } = scopedRpc({ http, audit: async (rec) => { rows.push(rec); } });
    await expect(
      r.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2", short_description: "x".repeat(500) } }),
    ).rejects.toMatchObject({ code: "actor_policy_denied" });
    expect(http.calls.filter((c) => c.method === "PATCH")).toHaveLength(0);
    expect(budget.outboundBytesSent).toBe(0);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ status: "denied", errorClass: "actor_policy_denied" });
  });

  it("reuses the raw filtered preflight row for recovery snapshot and masks the user-facing result", async () => {
    const snapshots: { before: Record<string, unknown> }[] = [];
    const http = new MockHttp();
    http.getHandler = () => ({
      status: 200,
      json: { result: [{ sys_id: SYS_ID, state: "1", caller_id: "raw-caller" }] },
    });
    http.patchHandler = () => ({
      status: 200,
      json: { result: { sys_id: SYS_ID, state: "2", caller_id: "raw-caller" } },
    });
    const { rpc: r } = scopedRpc({
      http,
      snapshotEnabledTables: ["incident"],
      captureSnapshot: async (input) => {
        snapshots.push({ before: input.before });
        return true;
      },
    });

    const out = await r.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } });
    expect(snapshots).toEqual([{ before: { sys_id: SYS_ID, state: "1", caller_id: "raw-caller" } }]);
    expect(out).toEqual({ sys_id: SYS_ID, state: "2" });
    expect(http.calls.filter((c) => c.method === "GET")).toHaveLength(1);
    expect(http.calls.find((c) => c.method === "GET")!.path).toBe("/api/now/table/incident");
  });

  it("meters the filtered scope-check GET once and does not double-count when reused for the snapshot", async () => {
    const { rpc: r, budget } = scopedRpc({
      snapshotEnabledTables: ["incident"],
      captureSnapshot: async () => true,
    });
    await r.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } });
    expect(budget.serviceNowRequests).toBe(2); // one filtered GET + one PATCH; no separate snapshot GET.
  });

  it("does not add a scope-check GET for a table without a mandatory row filter", async () => {
    const http = new MockHttp();
    const r = rpc({ http, mutation: mutationDeps({ runContext: { requestId: "r-unfiltered", runKey: "k1" } }) });
    await r.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } });
    expect(http.calls.filter((c) => c.method === "GET")).toHaveLength(0);
    expect(http.calls.filter((c) => c.method === "PATCH")).toHaveLength(1);
  });

  it("cleans the ledger on out-of-scope denial so a corrected retry can proceed", async () => {
    const runKey = `scope-deny-${crypto.randomUUID()}`;
    const ledger = realLedger(runKey);
    const http1 = new MockHttp();
    http1.getHandler = () => ({ status: 200, json: { result: [] } });
    const first = scopedRpc({ http: http1, runKey, ledger });
    await expect(first.rpc.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } })).rejects.toMatchObject({
      code: "actor_policy_denied",
    });

    const second = scopedRpc({ runKey, ledger });
    const out = await second.rpc.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { state: "2" } });
    expect(out).toMatchObject({ updated: true });
    expect(second.http.calls.filter((c) => c.method === "PATCH")).toHaveLength(1);
  });
});

describe("Phase 1C — outbound request bodies are pre-serialized and metered", () => {
  it("tableUpdate sends a sorted object bodyJson and accrues outbound bytes for the admitted PATCH", async () => {
    const http = new MockHttp();
    const budget = new RunBudget();
    const r = rpc({ http, runBudget: budget, mutation: mutationDeps({ runContext: { requestId: "r-body-json", runKey: "k1" } }) });
    await r.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { z: 2, a: 1 } });
    const patch = http.calls.find((c) => c.method === "PATCH")!;
    expect(patch.bodyJson).toBe("{\"a\":1,\"z\":2}");
    expect(patch.body).toBeUndefined();
    expect(budget.outboundBytesSent).toBe(new TextEncoder().encode("{\"a\":1,\"z\":2}").length);
  });

  it("tableUpdate rejects non-JSON fields as a clean pre-send precondition error", async () => {
    const http = new MockHttp();
    const r = rpc({ http, mutation: mutationDeps({ runContext: { requestId: "r-body-bad", runKey: "k1" } }) });
    await expect(
      r.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { amount: 1n } }),
    ).rejects.toMatchObject({ code: "precondition_required" });
    expect(http.calls.filter((c) => c.method === "PATCH")).toHaveLength(0);
  });

  it("tableUpdate trips outboundBytesSent before any PATCH leaves the host without accruing sent bytes", async () => {
    const http = new MockHttp();
    const budget = new RunBudget({ ...BUDGETS.perRun, maxOutboundBytes: 5 });
    const r = rpc({ http, runBudget: budget, mutation: mutationDeps({ runContext: { requestId: "r-body-cap", runKey: "k1" } }) });
    await expect(
      r.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { short_description: "too large" } }),
    ).rejects.toMatchObject({ code: "budget_exceeded", detail: { dimension: "outboundBytesSent" } });
    expect(http.calls.filter((c) => c.method === "PATCH")).toHaveLength(0);
    expect(budget.outboundBytesSent).toBe(0);
  });
});

describe("P4 — second-approval gate wired into runServerScript", () => {
  const SCRIPT = "return gs.getUserName();";
  const APPROVED = { adminScriptAllowlist: ["userA"], requiredAccessGroup: "mcp-admins", actorAccessGroups: ["mcp-admins"] };

  it("FAILS CLOSED when the live executor path requires durability but the ledger is missing", async () => {
    const http = new MockHttp();
    const r = rpc({
      http, mode: "admin_script", signing: true,
      mutation: mutationDeps({
        runContext: { requestId: "r-script-no-ledger", runKey: "k1", reason: "rotate" },
        durabilityRequired: true,
        audit: async () => {},
      }),
    });
    await expect(
      r.runServerScript({ script: SCRIPT }),
    ).rejects.toMatchObject({ code: "internal_error" });
    expect(http.calls.filter((c) => c.method === "POST")).toHaveLength(0);
  });

  it("FAILS CLOSED when the live executor path requires durability but audit is missing", async () => {
    const runKey = `script-no-audit-${crypto.randomUUID()}`;
    const http = new MockHttp();
    const r = rpc({
      http, mode: "admin_script", signing: true,
      mutation: mutationDeps({
        runContext: { requestId: "r-script-no-audit", runKey, reason: "rotate" },
        durabilityRequired: true,
        ledger: realLedger(runKey),
      }),
    });
    await expect(
      r.runServerScript({ script: SCRIPT }),
    ).rejects.toMatchObject({ code: "internal_error" });
    expect(http.calls.filter((c) => c.method === "POST")).toHaveLength(0);
  });

  it("ENFORCES when a policy is configured: admin_script with no valid token/group is DENIED (no POST)", async () => {
    const http = new MockHttp();
    const r = rpc({
      http, mode: "admin_script", signing: true,
      mutation: mutationDeps({
        runContext: { requestId: "r-approve", runKey: "k1", reason: "rotate" },
        approval: { adminScriptAllowlist: ["userA"], requiredAccessGroup: "mcp-admins" }, // actor has no group
      }),
    });
    await expect(
      r.runServerScript({ script: SCRIPT }),
    ).rejects.toMatchObject({ code: "capability_denied" });
    expect(http.calls.filter((c) => c.method === "POST")).toHaveLength(0);
  });

  it("PASSES when the actor is allowlisted AND in the required group (POST sent)", async () => {
    const http = new MockHttp();
    const r = rpc({
      http, mode: "admin_script", signing: true,
      mutation: mutationDeps({
        runContext: { requestId: "r-approve-ok", runKey: "k1", reason: "rotate" },
        approval: { adminScriptAllowlist: ["userA"], requiredAccessGroup: "mcp-admins", actorAccessGroups: ["mcp-admins"] },
      }),
    });
    const out = await r.runServerScript({ script: SCRIPT });
    expect(out).toMatchObject({ ok: true });
    expect(http.calls.filter((c) => c.method === "POST")).toHaveLength(1);
  });

  it("DENIES admin_script when ActorPolicy.maxMode is write even with approval satisfied", async () => {
    const http = new MockHttp();
    const r = rpc({
      http,
      mode: "admin_script",
      signing: true,
      actorPolicy: { ...permissivePolicy([INSTANCE]), maxMode: "write" },
      mutation: mutationDeps({
        runContext: { requestId: "r-script-policy-ceiling", runKey: "k1", reason: "rotate" },
        approval: APPROVED,
      }),
    });
    await expect(r.runServerScript({ script: SCRIPT })).rejects.toMatchObject({ code: "actor_policy_denied" });
    expect(http.calls.filter((c) => c.method === "POST")).toHaveLength(0);
  });

  it("allows admin_script at an admin_script ActorPolicy ceiling", async () => {
    const http = new MockHttp();
    const r = rpc({
      http,
      mode: "admin_script",
      signing: true,
      actorPolicy: { ...permissivePolicy([INSTANCE]), maxMode: "admin_script" },
      mutation: mutationDeps({
        runContext: { requestId: "r-script-policy-ceiling-ok", runKey: "k1", reason: "rotate" },
        approval: APPROVED,
      }),
    });
    await expect(r.runServerScript({ script: SCRIPT })).resolves.toMatchObject({ ok: true });
    expect(http.calls.filter((c) => c.method === "POST")).toHaveLength(1);
  });

  it("checks the ActorPolicy ceiling before signing or approval wiring", async () => {
    const http = new MockHttp();
    const r = rpc({
      http,
      mode: "admin_script",
      actorPolicy: { ...permissivePolicy([INSTANCE]), maxMode: "write" },
      mutation: mutationDeps({ runContext: { requestId: "r-script-policy-before-signing", runKey: "k1", reason: "rotate" } }),
    });
    await expect(r.runServerScript({ script: SCRIPT })).rejects.toMatchObject({ code: "actor_policy_denied" });
    expect(http.calls.filter((c) => c.method === "POST")).toHaveLength(0);
  });

  it("PASSES when the actor is allowlisted AND the host-level approvalToken is valid (POST sent)", async () => {
    const http = new MockHttp();
    const r = rpc({
      http, mode: "admin_script", signing: true,
      mutation: mutationDeps({
        runContext: { requestId: "r-approve-token-ok", runKey: "k1", reason: "rotate", approvalToken: "token-1" },
        approval: { adminScriptAllowlist: ["userA"], validApprovalTokens: new Set(["token-1"]) },
      }),
    });
    const out = await r.runServerScript({ script: SCRIPT });
    expect(out).toMatchObject({ ok: true });
    expect(http.calls.filter((c) => c.method === "POST")).toHaveLength(1);
  });

  it("DENIES an idempotency replay when the current second approval is missing", async () => {
    const runKey = `approve-replay-${crypto.randomUUID()}`;
    const approval = { adminScriptAllowlist: ["userA"], validApprovalTokens: new Set(["token-1"]) };
    const http1 = new MockHttp();
    const r1 = rpc({
      http: http1, mode: "admin_script", signing: true,
      mutation: mutationDeps({
        runContext: { requestId: "r-approve-replay-1", runKey, reason: "rotate", approvalToken: "token-1" },
        ledger: realLedger(runKey),
        approval,
      }),
    });
    await r1.runServerScript({ script: SCRIPT });
    expect(http1.calls.filter((c) => c.method === "POST")).toHaveLength(1);

    const http2 = new MockHttp();
    const r2 = rpc({
      http: http2, mode: "admin_script", signing: true,
      mutation: mutationDeps({
        runContext: { requestId: "r-approve-replay-2", runKey, reason: "rotate" },
        ledger: realLedger(runKey),
        approval,
      }),
    });
    await expect(
      r2.runServerScript({ script: SCRIPT }),
    ).rejects.toMatchObject({ code: "capability_denied" });
    expect(http2.calls.filter((c) => c.method === "POST")).toHaveLength(0);
  });

  it("treats executor-disabled 503s as clean failures so the runKey can retry", async () => {
    const runKey = `executor-disabled-${crypto.randomUUID()}`;
    const http1 = new MockHttp();
    http1.postHandler = () => ({ status: 503, json: { error: "executor_disabled", audit_id: "a1" } });
    const r1 = rpc({
      http: http1, mode: "admin_script", signing: true,
      mutation: mutationDeps({
        runContext: { requestId: "r-executor-disabled-1", runKey, reason: "rotate" },
        ledger: realLedger(runKey),
        approval: APPROVED,
      }),
    });
    await expect(r1.runServerScript({ script: SCRIPT })).rejects.toMatchObject({ code: "capability_denied" });
    expect(http1.calls.filter((c) => c.method === "POST")).toHaveLength(1);

    const http2 = new MockHttp();
    const r2 = rpc({
      http: http2, mode: "admin_script", signing: true,
      mutation: mutationDeps({
        runContext: { requestId: "r-executor-disabled-2", runKey, reason: "rotate" },
        ledger: realLedger(runKey),
        approval: APPROVED,
      }),
    });
    await expect(r2.runServerScript({ script: SCRIPT })).resolves.toMatchObject({ ok: true });
    expect(http2.calls.filter((c) => c.method === "POST")).toHaveLength(1);
  });

  it("FAILS CLOSED with NO approval policy configured (empty policy denies admin_script)", async () => {
    const http = new MockHttp();
    const r = rpc({
      http, mode: "admin_script", signing: true,
      mutation: mutationDeps({ runContext: { requestId: "r-solo", runKey: "k1", reason: "rotate" } }), // no approval
    });
    await expect(r.runServerScript({ script: SCRIPT })).rejects.toMatchObject({
      code: "capability_denied",
    });
    expect(http.calls.filter((c) => c.method === "POST")).toHaveLength(0);
  });

  it("uses the HOST tool-level reason for the POST body + audit", async () => {
    const rows: AuditRecord[] = [];
    const http = new MockHttp();
    const r = rpc({
      http, mode: "admin_script", signing: true,
      mutation: mutationDeps({
        runContext: { requestId: "r-hostreason", runKey: "k1", reason: "HOST-REASON" },
        approval: APPROVED,
        audit: async (rec) => { rows.push(rec); },
      }),
    });
    await r.runServerScript({ script: SCRIPT });
    const post = http.calls.find((c) => c.method === "POST")!;
    // P7 item 1: reason is now SIGNED into the actor payload (integrity-bound), not sent as
    // an unsigned top-level body.reason. The executor verifies + audits actor.reason.
    const body = JSON.parse(post.bodyJson!) as { actor: { reason: string }; reason?: string };
    expect(body.actor.reason).toBe("HOST-REASON");
    expect(body.reason).toBeUndefined();
    expect(rows.every((x) => x.reason === "HOST-REASON")).toBe(true);
  });

  it("runServerScript hard-requires the tool-level idempotencyKey (runKey)", async () => {
    const http = new MockHttp();
    const r = rpc({
      http, mode: "admin_script", signing: true,
      mutation: mutationDeps({ runContext: { requestId: "r-nokey", reason: "rotate" } }), // no runKey
    });
    await expect(
      r.runServerScript({ script: SCRIPT }),
    ).rejects.toMatchObject({ code: "capability_denied" });
    expect(http.calls.filter((c) => c.method === "POST")).toHaveLength(0);
  });

  it("runServerScript trips outboundBytesSent before the guarded executor POST without accruing sent bytes", async () => {
    const http = new MockHttp();
    const budget = new RunBudget({ ...BUDGETS.perRun, maxOutboundBytes: 100 });
    const r = rpc({
      http, mode: "admin_script", signing: true, runBudget: budget,
      mutation: mutationDeps({
        runContext: { requestId: "r-script-outbound-cap", runKey: "k1", reason: "rotate" },
        approval: APPROVED,
      }),
    });
    await expect(r.runServerScript({ script: "x".repeat(500) })).rejects.toMatchObject({
      code: "budget_exceeded",
      detail: { dimension: "outboundBytesSent" },
    });
    expect(http.calls.filter((c) => c.method === "POST")).toHaveLength(0);
    expect(budget.outboundBytesSent).toBe(0);
  });
});

describe("P4 — write field-mask + update-key validation hold on the guarded path", () => {
  function maskRpc(): { rpc: ServiceNowRPC; http: MockHttp } {
    const http = new MockHttp();
    const r = new ServiceNowRPC({
      http, instanceHost: INSTANCE, effectiveMode: "write",
      actorPolicy: {
        allowedInstances: [INSTANCE], tables: {}, fieldMasks: { incident: ["caller_id"] },
        maxMode: "admin_script", maxRowsPerRun: 1000, maxBytesPerRun: 1_000_000,
      },
      runBudget: new RunBudget(),
      mutation: mutationDeps({ runContext: { requestId: "r-mask", runKey: "k1" } }),
    });
    return { rpc: r, http };
  }

  it("denies writing a masked field (exact-match caller_id) via the actor-policy mask", async () => {
    const { rpc: r, http } = maskRpc();
    await expect(
      r.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { caller_id: "x" } }),
    ).rejects.toMatchObject({ code: "actor_policy_denied" });
    expect(http.calls.filter((c) => c.method === "PATCH")).toHaveLength(0);
  });

  it("rejects a dot-walk update key (caller_id.value) at update-field validation (path_denied)", async () => {
    // The dot-walk write key is killed by P1's validateUpdateFields (no-dot UPDATE_KEY regex)
    // BEFORE the mask gate is ever consulted — so the rejection is path_denied, not the mask.
    const { rpc: r, http } = maskRpc();
    await expect(
      r.tableUpdate({ table: "incident", sys_id: SYS_ID, fields: { "caller_id.value": "x" } }),
    ).rejects.toMatchObject({ code: "path_denied" });
    expect(http.calls.filter((c) => c.method === "PATCH")).toHaveLength(0);
  });
});

// ─── §6b — the resolved per-user SN principal sys_id reaches the SIGNED actor ──
// Option (b) wiring: in per_user_oauth, signing.resolveEffectiveUserSysId() fills the
// `snow_effective_user_sys_id` claim lazily at sign time. integration_user (no resolver) keeps
// the base "" claim. These assert the NEW behavior end-to-end through signActor → POST body.
describe("§6b runServerScript binds the resolved effective-user sys_id into the signed actor", () => {
  const SCRIPT = "return gs.getUserName();";
  const APPROVED = { adminScriptAllowlist: ["userA"], requiredAccessGroup: "mcp-admins", actorAccessGroups: ["mcp-admins"] };

  function signingRpc(resolver?: () => Promise<string>): { rpc: ServiceNowRPC; http: MockHttp } {
    const http = new MockHttp();
    const r = new ServiceNowRPC({
      http, instanceHost: INSTANCE, effectiveMode: "admin_script",
      actorPolicy: permissivePolicy([INSTANCE]),
      runBudget: new RunBudget(),
      signing: {
        claims: { ...SIGNING.claims }, // base snow_effective_user_sys_id: ""
        hmacKey: SIGNING.hmacKey,
        nonce: SIGNING.nonce,
        now: SIGNING.now,
        ...(resolver ? { resolveEffectiveUserSysId: resolver } : {}),
      },
      executorPath: "/api/x_1793136_mcp/x_mcp/executor/run",
      mutation: mutationDeps({ runContext: { requestId: "r-eff", runKey: "k1", reason: "rotate" }, approval: APPROVED }),
    });
    return { rpc: r, http };
  }

  it("per_user_oauth: the signed actor carries the resolved sys_id (not the base \"\")", async () => {
    const { rpc: r, http } = signingRpc(async () => "EFFECTIVE_SYS_ID");
    await r.runServerScript({ script: SCRIPT });
    const post = http.calls.find((c) => c.method === "POST")!;
    expect((JSON.parse(post.bodyJson!) as { actor: { snow_effective_user_sys_id: string } }).actor.snow_effective_user_sys_id).toBe("EFFECTIVE_SYS_ID");
  });

  it("integration_user (no resolver): the signed actor keeps snow_effective_user_sys_id \"\"", async () => {
    const { rpc: r, http } = signingRpc(); // no resolveEffectiveUserSysId
    await r.runServerScript({ script: SCRIPT });
    const post = http.calls.find((c) => c.method === "POST")!;
    expect((JSON.parse(post.bodyJson!) as { actor: { snow_effective_user_sys_id: string } }).actor.snow_effective_user_sys_id).toBe("");
  });

  it("per_user_oauth: an unresolved principal fails closed before the executor POST", async () => {
    const { rpc: r, http } = signingRpc(async () => "");
    await expect(r.runServerScript({ script: SCRIPT })).rejects.toMatchObject({
      code: "reauth_required",
    });
    expect(http.calls.filter((c) => c.method === "POST")).toHaveLength(0);
  });
});
