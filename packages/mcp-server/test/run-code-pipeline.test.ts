import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { runCode, type RunCodeDeps } from "../src/tools/run_code.js";
import { ServiceNowRPC } from "../src/sn/rpc.js";
import { RunBudget } from "../src/sn/run-budget.js";
import { permissivePolicy, type ActorPolicy } from "../src/authz/actor-policy.js";
import type { SnHttpClient, SnRequest, SnResponse } from "../src/sn/http.js";
import type { Mode } from "@servicenow-codemode/shared";

// ─── Phase 4 — run_code pipeline against a MOCK ServiceNowRPC ──────────────────
// Proves the §3.1 enforced order end-to-end in workerd. ServiceNow itself is mocked;
// live behavior is out of scope (OPEN_QUESTIONS.md). Verifies S1/S4-shape guardrails,
// B3/B4 mode capping, capability gating, ActorPolicy denial, and per-run budget.

interface TestEnv { LOADER: WorkerLoader; }
const LOADER = (env as unknown as TestEnv).LOADER;
const INSTANCE = "inst1.service-now.com";

class MockHttp implements SnHttpClient {
  calls: SnRequest[] = [];
  async request(req: SnRequest): Promise<SnResponse> {
    this.calls.push(req);
    if (req.method === "GET" && req.path.startsWith("/api/now/table/incident")) {
      return { status: 200, json: { result: [{ sys_id: "a1", number: "INC0001", caller_id: "u9" }] } };
    }
    if (req.method === "PATCH") return { status: 200, json: { result: { sys_id: "a1", updated: true } } };
    return { status: 200, json: { result: [] } };
  }
}

function deps(opts: {
  scope?: Mode; tenant?: Mode; instance?: Mode; policy?: ActorPolicy; http?: MockHttp;
}): RunCodeDeps {
  const http = opts.http ?? new MockHttp();
  const policy = opts.policy ?? permissivePolicy([INSTANCE]);
  return {
    loader: LOADER,
    scopeMaxMode: opts.scope ?? "admin_script",
    tenantMaxMode: opts.tenant ?? "admin_script",
    instanceMaxMode: opts.instance ?? "admin_script",
    timeoutMs: 5000,
    buildRpc: (effectiveMode, runBudget: RunBudget) =>
      new ServiceNowRPC({ http, instanceHost: INSTANCE, effectiveMode, actorPolicy: policy, runBudget }),
  };
}

describe("Phase 4 — run_code pipeline", () => {
  it("happy read path: snippet queries incident and returns rows", async () => {
    const res = await runCode(
      { code: `async () => { const r = await servicenow.tableQuery({ table: "incident", limit: 5 }); return r.rows.length; }` },
      deps({ scope: "read_only", tenant: "read_only", instance: "read_only" }),
    );
    expect(res.isError).toBe(false);
    expect(res.content[0]!.text).toBe("1");
    expect(res.structuredContent?.mode).toBe("read_only");
  });

  it("B4 — a read_only-scoped client requesting mode:write is denied pre-transpile", async () => {
    const res = await runCode(
      { code: `async () => 1`, mode: "write" },
      deps({ scope: "read_only", tenant: "admin_script", instance: "admin_script" }),
    );
    expect(res.isError).toBe(true);
    expect(res.structuredContent?.code).toBe("mode_not_permitted");
  });

  it("capability gate fires INSIDE the sandbox when read_only calls a write method", async () => {
    const res = await runCode(
      // sys_id is a valid 32-hex id so P1 input validation passes and the run reaches
      // the capability gate (the actual subject of this test).
      { code: `async () => { await servicenow.tableUpdate({ table: "incident", sys_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", fields: { state: 2 }, idempotencyKey: "k1" }); return "did-write"; }` },
      deps({ scope: "read_only", tenant: "read_only", instance: "read_only" }),
    );
    expect(res.isError).toBe(true);
    expect(res.content[0]!.text).toMatch(/not permitted/i);
    // The typed code survives the sandbox boundary (§3.5 auditability).
    expect(res.structuredContent?.code).toBe("capability_denied");
  });

  it("ActorPolicy denies a table outside the actor's allowlist", async () => {
    const policy: ActorPolicy = {
      allowedInstances: [INSTANCE],
      tables: { allow: [/^incident$/] },
      fieldMasks: {},
      maxMode: "admin_script",
      maxRowsPerRun: 1000,
      maxBytesPerRun: 1_000_000,
    };
    const res = await runCode(
      { code: `async () => { await servicenow.tableQuery({ table: "sys_user" }); return "read"; }` },
      deps({ scope: "read_only", tenant: "read_only", instance: "read_only", policy }),
    );
    expect(res.isError).toBe(true);
    expect(res.content[0]!.text).toMatch(/not allowed/i);
  });

  it("masks forbidden fields in the returned rows", async () => {
    const policy: ActorPolicy = {
      allowedInstances: [INSTANCE],
      tables: {},
      fieldMasks: { incident: ["caller_id"] },
      maxMode: "read_only",
      maxRowsPerRun: 1000,
      maxBytesPerRun: 1_000_000,
    };
    const res = await runCode(
      { code: `async () => { const r = await servicenow.tableQuery({ table: "incident" }); return r.rows[0]; }` },
      deps({ scope: "read_only", tenant: "read_only", instance: "read_only", policy }),
    );
    expect(res.isError).toBe(false);
    const row = JSON.parse(res.content[0]!.text);
    expect(row.number).toBe("INC0001");
    expect(row.caller_id).toBeUndefined();
  });

  it("P1 — a bad sys_id from inside the sandbox surfaces typed path_denied", async () => {
    // The validation throw must survive the sandbox boundary with its typed code intact
    // (McpToolError -> coded() -> [[path_denied]] -> parseSandboxError), the same way the
    // capability gate above does.
    const res = await runCode(
      { code: `async () => { await servicenow.tableGet({ table: "incident", sys_id: "../sys_user/x" }); return "got"; }` },
      deps({ scope: "read_only", tenant: "read_only", instance: "read_only" }),
    );
    expect(res.isError).toBe(true);
    expect(res.structuredContent?.code).toBe("path_denied");
  });

  it("rejects oversize code as code_size (pre-transpile)", async () => {
    const big = `async () => { /* ${"x".repeat(70_000)} */ return 1; }`;
    const res = await runCode({ code: big }, deps({}));
    expect(res.isError).toBe(true);
    expect(res.structuredContent?.code).toBe("code_size");
  });

  it("maps a TypeScript syntax error to transpile_error", async () => {
    const res = await runCode({ code: `async () => { const = ; }` }, deps({}));
    expect(res.isError).toBe(true);
    expect(res.structuredContent?.code).toBe("transpile_error");
  });

  it("admin_script without a reason is denied", async () => {
    const res = await runCode(
      { code: `async () => 1`, mode: "admin_script" },
      deps({ scope: "admin_script", tenant: "admin_script", instance: "admin_script" }),
    );
    expect(res.isError).toBe(true);
    expect(res.structuredContent?.code).toBe("capability_denied");
  });

  it("daily budget reserve-before-load blocks BEFORE transpile (no billable Worker)", async () => {
    const base = deps({});
    // Invalid code would normally transpile_error; an exhausted reserve must win first.
    const res = await runCode(
      { code: `async () => { const = ; }` },
      { ...base, reserveDailyBudget: async () => ({ ok: false, dimension: "uniqueWorkers" }) },
    );
    expect(res.isError).toBe(true);
    expect(res.structuredContent?.code).toBe("budget_exceeded");
  });

  it("per-run RPC budget trips budget_exceeded mid-snippet", async () => {
    // Force a tiny limit by exhausting via many calls; default rpcCallLimit is 200.
    const code = `async () => { for (let i = 0; i < 250; i++) { await servicenow.tableQuery({ table: "incident" }); } return "done"; }`;
    const res = await runCode({ code }, deps({ scope: "read_only", tenant: "read_only", instance: "read_only" }));
    expect(res.isError).toBe(true);
    // Per-run RPC budget tripped mid-snippet (code budget_exceeded; surfaced message).
    expect(res.content[0]!.text).toMatch(/limit \(200\) exceeded/i);
  });
});
