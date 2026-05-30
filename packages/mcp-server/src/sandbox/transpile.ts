// Primary TS pipeline (plan §2.2, ADR-0001): esbuild-wasm `transform` strips types
// and lowers syntax to a single JS string handed to DynamicWorkerExecutor.execute().
//
// IMPORTANT: `transform` STRIPS types, it does NOT type-check, and it does NOT bundle
// imports (that is 0.8b). esbuild-wasm runs inside workerd, so this module is only
// exercised under @cloudflare/vitest-pool-workers, never plain Node.

import * as esbuild from "esbuild-wasm";
// Vendored next to source (regenerate via `npm run copy-wasm`). A RELATIVE import is
// required so both the wrangler/vitest bundler AND Alchemy's bundler resolve it — Alchemy
// mis-resolves the bare `esbuild-wasm/esbuild.wasm` specifier as a relative path. The file
// is gitignored; the copy script restores it.
import esbuildWasmModule from "./esbuild.wasm";

let initPromise: Promise<void> | null = null;

/** Initialize esbuild-wasm exactly once per isolate. `worker:false` keeps it inline (no Web Worker). */
function ensureInitialized(): Promise<void> {
  if (initPromise === null) {
    initPromise = esbuild.initialize({ wasmModule: esbuildWasmModule, worker: false });
  }
  return initPromise;
}

export interface TranspileError {
  /** 1-based line within the user snippet, when esbuild reports a location. */
  line?: number;
  column?: number;
  message: string;
}

export class TranspileFailure extends Error {
  readonly errors: TranspileError[];
  constructor(errors: TranspileError[]) {
    super(errors.map((e) => `${e.line ?? "?"}:${e.column ?? "?"} ${e.message}`).join("; "));
    this.name = "TranspileFailure";
    this.errors = errors;
  }
}

/**
 * Transpile a TypeScript snippet to an ESM JS string.
 * Throws TranspileFailure on syntax errors (never leaks raw esbuild output to the host).
 */
export async function transpileTs(userTs: string): Promise<string> {
  await ensureInitialized();
  try {
    const result = await esbuild.transform(userTs, {
      loader: "ts",
      format: "esm",
      // Keep it conservative; the sandbox runtime is modern workerd.
      target: "es2022",
    });
    // ADR-0001: esbuild emits the user's `async () => {...}` as a STATEMENT with a
    // trailing `;`. codemode's executor wraps the code as `( <code> )()`, so a
    // trailing semicolon produces `(async () => {...};)()` — a syntax error. Strip
    // the single trailing `;` (and surrounding whitespace) so the output is a bare
    // expression that normalizeCode() recognizes as an arrow function.
    return result.code.trim().replace(/;\s*$/, "");
  } catch (e: unknown) {
    const errs = (e as { errors?: Array<{ text: string; location?: { line: number; column: number } }> }).errors;
    if (Array.isArray(errs) && errs.length > 0) {
      throw new TranspileFailure(
        errs.map((er) => ({
          message: er.text,
          ...(er.location ? { line: er.location.line, column: er.location.column } : {}),
        })),
      );
    }
    throw new TranspileFailure([{ message: e instanceof Error ? e.message : String(e) }]);
  }
}
