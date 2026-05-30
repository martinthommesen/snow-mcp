import { describe, expect, it } from "vitest";
import { transpileTs, TranspileFailure } from "../src/sandbox/transpile.js";

// Phase 0.8b (partial) — prove esbuild-wasm initializes and transforms inside workerd.
describe("Phase 0.8 — esbuild-wasm TS transform inside workerd", () => {
  it("strips types from a no-import TS snippet", async () => {
    const js = await transpileTs(
      `const x: number = 41; const y: string = "z"; return (x + 1) + y.length;`,
    );
    expect(js).not.toContain(": number");
    expect(js).toContain("41");
  });

  it("does NOT type-check (transform only) — a type error still transpiles", async () => {
    // 'const s: number = "str"' is a TYPE error but valid syntax; transform must succeed.
    const js = await transpileTs(`const s: number = "actually a string"; return s;`);
    expect(js).toContain('"actually a string"');
  });

  it("throws a structured TranspileFailure with line info on a SYNTAX error", async () => {
    await expect(transpileTs(`const = ;`)).rejects.toBeInstanceOf(TranspileFailure);
  });
});
