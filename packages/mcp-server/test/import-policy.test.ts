import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { transpileTs } from "../src/sandbox/transpile.js";
import { createExecutor, executeSnippet } from "../src/sandbox/executor.js";

// ─── Phase 0.8b — allowed-import proof + v1 import policy ─────────────────────
// Records the import strategy in ADR-0001:
//   MECHANISM: the executor's `modules` map is injected into the sandbox module
//   map, reachable via dynamic import("<key>"). This is proven below.
//   v1 POLICY: pass NO modules — arbitrary npm imports are DISABLED. The only
//   capability is the `servicenow` provider. Keeps the supply-chain surface zero.

interface TestEnv { LOADER: WorkerLoader; }
const LOADER = (env as unknown as TestEnv).LOADER;

describe("Phase 0.8b — sandbox import policy", () => {
  it("MECHANISM: an explicitly injected module is importable via dynamic import()", async () => {
    const js = await transpileTs(
      `async () => { const m = await import("greet.js"); return m.greet("ada"); }`,
    );
    const executor = createExecutor(LOADER, {
      modules: { "greet.js": "export const greet = (n) => 'hi ' + n;" },
    });
    const res = await executeSnippet(executor, js, []);
    expect(res.error).toBeUndefined();
    expect(res.result).toBe("hi ada");
  });

  it("v1 POLICY: with no injected modules, an arbitrary import fails (no npm in sandbox)", async () => {
    const js = await transpileTs(
      `async () => { try { await import("zod"); return "imported"; } catch { return "blocked"; } }`,
    );
    const executor = createExecutor(LOADER, {}); // no modules — v1 default
    const res = await executeSnippet(executor, js, []);
    expect(res.error === undefined ? res.result : res.error).toBe("blocked");
  });
});
