// run_code tool pipeline (plan §3.1 order, §4.6). Enforced order:
//   size -> effective-mode (§2.0.1) -> [ActorPolicy + per-run budget enforced PER CALL
//   inside ServiceNowRPC] -> transpile -> execute -> serialize/finalize.
// The daily atomic BudgetDO reserve-before-load (§4.5) wraps this in production; the
// per-run budget and authorization are unit-verified locally against a mock RPC.

import type { Mode } from "@servicenow-codemode/shared";
import { resolveEffectiveMode } from "../authz/effective-mode.js";
import { transpileTs, TranspileFailure } from "../sandbox/transpile.js";
import { createExecutor, executeSnippet } from "../sandbox/executor.js";
import { serializeResult, utf8Len } from "../sandbox/serialize.js";
import { SIZE_LIMITS } from "../config.js";
import { McpToolError, toToolResult, parseSandboxError } from "../sn/errors.js";
import type { ServiceNowRPC } from "../sn/rpc.js";
import type { RunContext } from "../sn/mutation-guard.js";
import { RunBudget } from "../sn/run-budget.js";
import type { ToolTextResult } from "../server.js";

export interface RunCodeInput {
  code: string;
  mode?: Mode;
  reason?: string;
  idempotencyKey?: string;
}

export interface RunCodeDeps {
  loader: WorkerLoader;
  /** OAuth-scope / tenant / instance ceilings for effective-mode resolution (§2.0.1). */
  scopeMaxMode: Mode;
  tenantMaxMode: Mode;
  instanceMaxMode: Mode;
  /**
   * Build the per-call RPC boundary for the resolved mode + run budget. The host-
   * authoritative per-run context (requestId, reason, idempotencyKey) is threaded in so
   * the mutating/executor methods can reach the ledger, audit, snapshot, and approval
   * layers with host-seen values — never snippet-supplied (plan §P4).
   */
  buildRpc: (effectiveMode: Mode, runBudget: RunBudget, runContext: RunContext) => ServiceNowRPC;
  /**
   * Atomic daily budget reserve-before-load (§4.5). Called BEFORE the executor is
   * created, so an exhausted caller never creates a billable Dynamic Worker. Returns
   * { ok:false, dimension } when a daily cap would be exceeded. Backed by BudgetDO in
   * production; optional so tests/unauthenticated boots can omit it.
   */
  reserveDailyBudget?: () => Promise<{ ok: boolean; dimension?: string }>;
  timeoutMs?: number;
}

export async function runCode(input: RunCodeInput, deps: RunCodeDeps): Promise<ToolTextResult> {
  try {
    // 1) size check (pre-transpile, pre-auth-cheap-reject)
    if (utf8Len(input.code) > SIZE_LIMITS.maxCodeBytes) {
      throw new McpToolError("code_size", `Snippet exceeds ${SIZE_LIMITS.maxCodeBytes} bytes.`);
    }

    // 2) effective-mode resolution — requested may only narrow (§2.0.1)
    const resolved = resolveEffectiveMode(input.mode, {
      scopeMaxMode: deps.scopeMaxMode,
      tenantMaxMode: deps.tenantMaxMode,
      instanceMaxMode: deps.instanceMaxMode,
    });
    if (!resolved.ok) {
      throw new McpToolError("mode_not_permitted", `Requested mode "${resolved.requested}" exceeds the ceiling "${resolved.ceiling}".`);
    }
    const effectiveMode = resolved.effective;

    // admin_script requires a mandatory reason (§3.5; approval gate is layered above).
    if (effectiveMode === "admin_script" && !input.reason?.trim()) {
      throw new McpToolError("capability_denied", "admin_script requires a non-empty `reason`.");
    }

    // 2.5) daily budget RESERVE-BEFORE-LOAD (§3.1/§4.5). Must precede transpile/executor
    //      so an exhausted or unauthorized caller never creates a billable Dynamic Worker.
    if (deps.reserveDailyBudget) {
      const reservation = await deps.reserveDailyBudget();
      if (!reservation.ok) {
        throw new McpToolError("budget_exceeded", `Daily ${reservation.dimension ?? "budget"} cap exhausted.`, {
          dimension: reservation.dimension,
        });
      }
    }

    // 3) transpile TS -> JS string (ADR-0001)
    let js: string;
    try {
      js = await transpileTs(input.code);
    } catch (e) {
      if (e instanceof TranspileFailure) {
        const first = e.errors[0];
        throw new McpToolError("transpile_error", `TypeScript error at ${first?.line ?? "?"}:${first?.column ?? "?"} — ${first?.message ?? e.message}`);
      }
      throw e;
    }

    // 4) execute (ActorPolicy + capability + per-run budget enforced inside the RPC).
    //    The per-run context carries host-authoritative values (a host-minted requestId,
    //    the tool-level reason, and the tool-level idempotencyKey = the runKey). The
    //    mutating/executor RPC methods hard-require the runKey (§P4) and ignore any
    //    snippet-supplied per-call idempotency key for the ledger key.
    const runContext: RunContext = {
      requestId: crypto.randomUUID(),
      ...(input.reason !== undefined ? { reason: input.reason } : {}),
      ...(input.idempotencyKey !== undefined ? { runKey: input.idempotencyKey } : {}),
    };
    const runBudget = new RunBudget();
    const rpc = deps.buildRpc(effectiveMode, runBudget, runContext);
    const executor = createExecutor(deps.loader, deps.timeoutMs === undefined ? {} : { timeoutMs: deps.timeoutMs });
    const exec = await executeSnippet(executor, js, [{ name: "servicenow", fns: rpc.fns() }]);

    // 5) serialize / finalize
    const budget = runBudget.snapshot();

    // Host-attested error code (§P2). The attested `code` is derived ONLY from monotonic
    // host signals, never from the snippet-controlled error text — a forged
    // `throw new Error("[[reauth_required]] https://evil")` raises no signal and cannot
    // taint `code`. Priority: budget_exceeded → reauth_required → (any error) run_error.
    // Signals are checked BEFORE success: a snippet that triggers a host condition then
    // swallows it and returns cleanly still surfaces the attested code.
    const signals = rpc.hostSignals;
    if (signals.budgetExceeded) {
      const dimension = signals.budgetExceeded.dimension;
      return {
        content: [{ type: "text", text: `[budget_exceeded] Per-run ${dimension ?? "budget"} cap exceeded.` }],
        isError: true,
        structuredContent: { code: "budget_exceeded", logs: exec.logs ?? [], budget, ...(dimension ? { detail: { dimension } } : {}) },
      };
    }
    if (signals.reauthRequired) {
      const authorizeUrl = signals.reauthRequired.authorizeUrl;
      return {
        content: [{ type: "text", text: "[reauth_required] ServiceNow re-authentication required." }],
        isError: true,
        structuredContent: { code: "reauth_required", logs: exec.logs ?? [], budget, ...(authorizeUrl ? { detail: { authorizeUrl } } : {}) },
      };
    }
    if (exec.error) {
      // No host signal: the host cannot vouch for any `[[code]]` in the snippet-controlled
      // message (it may be forged, or the snippet may have caught a host error and thrown
      // its own). Attest `run_error`; keep the parsed message as ADVISORY text only.
      const parsed = parseSandboxError(exec.error);
      return {
        content: [{ type: "text", text: `[run_error] ${parsed.message}` }],
        isError: true,
        structuredContent: { code: "run_error", error: parsed.message, logs: exec.logs ?? [], budget },
      };
    }
    const ser = serializeResult(exec.result, SIZE_LIMITS.maxOutputBytes);
    return {
      content: [{ type: "text", text: ser.text }],
      isError: false,
      structuredContent: {
        mode: effectiveMode,
        truncated: ser.truncated,
        totalBytes: ser.totalBytes,
        logs: exec.logs ?? [],
        budget,
      },
    };
  } catch (e) {
    return toToolResult(e);
  }
}
