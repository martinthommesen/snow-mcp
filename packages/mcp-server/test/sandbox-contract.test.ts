import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { transpileTs } from "../src/sandbox/transpile.js";
import { createExecutor, executeSnippet, type SandboxProvider } from "../src/sandbox/executor.js";

// ─── Phase 0.8a — Code Mode execution-contract proof (REQUIRED before Phase 4) ───
// Proves the keystone contract every run_code sample depends on (plan §8 risk #1,
// ADR-0001): esbuild-wasm transform(TS->JS string) -> DynamicWorkerExecutor.execute().

interface TestEnv {
  LOADER: WorkerLoader;
}
const LOADER = (env as unknown as TestEnv).LOADER;

/** Mock ServiceNow RPC surface (no real network; the sandbox can only see this). */
function mockProvider(calls: unknown[][]): SandboxProvider {
  return {
    name: "servicenow",
    fns: {
      tableQuery: async (...args: unknown[]) => {
        calls.push(args);
        return { rows: [{ sys_id: "abc", number: "INC0001" }], partial: false };
      },
    },
  };
}

async function run(ts: string, providers: SandboxProvider[], timeoutMs?: number) {
  const js = await transpileTs(ts);
  const executor = createExecutor(LOADER, timeoutMs === undefined ? {} : { timeoutMs });
  return executeSnippet(executor, js, providers);
}

describe("Phase 0.8a — execute() contract", () => {
  it("(a) snippet calls servicenow.* via typed RPC and (f) execute() accepts the transformed string", async () => {
    const calls: unknown[][] = [];
    const res = await run(
      `async () => {
         const r = await servicenow.tableQuery({ table: "incident", limit: 1 });
         return r.rows.length;
       }`,
      [mockProvider(calls)],
    );
    expect(res.error).toBeUndefined();
    expect(res.result).toBe(1);
    expect(calls).toEqual([[{ table: "incident", limit: 1 }]]);
  });

  it("(b) global fetch is blocked under globalOutbound:null (S1 isolation)", async () => {
    const res = await run(
      `async () => {
         let blocked = false;
         try { await fetch("https://example.com/"); } catch { blocked = true; }
         return blocked;
       }`,
      [mockProvider([])],
    );
    expect(res.error).toBeUndefined();
    expect(res.result).toBe(true);
  });

  it("(c) console.log/warn/error are captured into logs", async () => {
    const res = await run(
      `async () => { console.log("hello"); console.warn("careful"); console.error("oops"); return 1; }`,
      [mockProvider([])],
    );
    expect(res.logs?.join("\n")).toContain("hello");
    expect(res.logs?.join("\n")).toContain("careful");
    expect(res.logs?.join("\n")).toContain("oops");
  });

  it("(d) a thrown runtime error is returned in .error, not thrown", async () => {
    const res = await run(
      `async () => { throw new Error("boom from snippet"); }`,
      [mockProvider([])],
    );
    expect(res.result).toBeUndefined();
    expect(res.error).toContain("boom from snippet");
  });

  it("(d2) a tool-call error propagates as a thrown error inside the sandbox", async () => {
    const provider: SandboxProvider = {
      name: "servicenow",
      fns: { tableQuery: async () => { throw new Error("rpc denied"); } },
    };
    const res = await run(
      `async () => { try { await servicenow.tableQuery({}); return "no-throw"; } catch (e) { return "caught:" + e.message; } }`,
      [provider],
    );
    expect(res.error).toBeUndefined();
    expect(res.result).toBe("caught:rpc denied");
  });

  it("(e) an infinite loop is killed by the timeout and surfaced in .error", async () => {
    const res = await run(
      `async () => { while (true) { await new Promise(r => setTimeout(r, 5)); } }`,
      [mockProvider([])],
      200, // 200ms timeout
    );
    expect(res.error?.toLowerCase()).toContain("timed out");
  });
});
