// DynamicWorkerExecutor factory (plan §3.4, ADR-0001).
//
// The sandbox sees ONLY the typed RPC surface exposed as a provider namespace —
// never `env`, a token, or a Fetcher to ServiceNow. `globalOutbound: null` makes
// fetch()/connect() throw inside the sandbox (plan §2.2, T3/S1).

import { DynamicWorkerExecutor, type ExecuteResult } from "@cloudflare/codemode";

/** A tool provider exposed to the sandbox as a single-level global `name.tool(...)`. */
export interface SandboxProvider {
  /** Sandbox global identifier, e.g. "servicenow". Must be a valid JS identifier. */
  name: string;
  fns: Record<string, (...args: unknown[]) => Promise<unknown>>;
}

export const DEFAULT_TIMEOUT_MS = 30_000;

export interface ExecutorOptions {
  timeoutMs?: number;
  /**
   * Allowlisted modules injected into the sandbox module map, importable via
   * dynamic `import("<key>")`. v1 policy is to pass NOTHING here (no arbitrary
   * imports — the only capability is the `servicenow` provider). The parameter
   * exists so a future, vetted allowlist (0.8b) is a config change, not a rewrite.
   */
  modules?: Record<string, string>;
}

/** Construct an isolated, network-less executor bound to the Worker Loader. */
export function createExecutor(loader: WorkerLoader, options: ExecutorOptions = {}): DynamicWorkerExecutor {
  return new DynamicWorkerExecutor({
    loader,
    timeout: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    globalOutbound: null, // §2.2 — no network from the sandbox
    ...(options.modules ? { modules: options.modules } : {}),
  });
}

/**
 * Execute an already-transpiled JS snippet against the given providers.
 * Returns the executor's ExecuteResult ({ result, error?, logs? }); never throws
 * (codemode contract — errors are returned in `.error`).
 */
export function executeSnippet(
  executor: DynamicWorkerExecutor,
  jsCode: string,
  providers: SandboxProvider[],
): Promise<ExecuteResult> {
  return executor.execute(jsCode, providers);
}
