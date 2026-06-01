import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { transpileTs } from "../src/sandbox/transpile.js";
import { createExecutor, executeSnippet } from "../src/sandbox/executor.js";

// ─── Phase 0.8b — v1 import policy ────────────────────────────────────────────
// v1 POLICY: pass NO modules — arbitrary npm imports are DISABLED. The only capability is the
// `servicenow` provider. Keeps the supply-chain surface zero.

interface TestEnv { LOADER: WorkerLoader; }
const LOADER = (env as unknown as TestEnv).LOADER;

describe("Phase 0.8b — sandbox import policy", () => {
  it("v1 POLICY: with no injected modules, an arbitrary import fails (no npm in sandbox)", async () => {
    const js = await transpileTs(
      `async () => { try { await import("zod"); return "imported"; } catch { return "blocked"; } }`,
    );
    const executor = createExecutor(LOADER);
    const res = await executeSnippet(executor, js, []);
    expect(res.error === undefined ? res.result : res.error).toBe("blocked");
  });
});
