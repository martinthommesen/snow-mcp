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
   * Pre-sandbox per-user auth preflight (§6b). Called BEFORE the daily reserve / transpile /
   * executor so a per_user_oauth caller with no usable ServiceNow token short-circuits with a
   * host-attested `reauth_required` (+authorizeUrl) before any billable Dynamic Worker spins.
   * Throws McpToolError on a missing/corrupt token; resolves quietly when a usable token exists
   * or in integration_user (a no-op there). Optional so tests/non-OAuth boots can omit it.
   */
  preflightAuth?: () => Promise<void>;
  /**
   * Atomic daily budget reserve-before-load (§4.5). Called BEFORE the executor is
   * created, so an exhausted caller never creates a billable Dynamic Worker. Returns
   * { ok:false, dimension } when a daily cap would be exceeded. Backed by BudgetDO in
   * production; optional so tests/unauthenticated boots can omit it.
   */
  reserveDailyBudget?: () => Promise<{ ok: boolean; dimension?: string }>;
  /**
   * Build the per-run budget meter (§P5). Handlers backs this with the actor's
   * maxRowsPerRun/maxBytesPerRun caps from ActorPolicy; absent (tests/read-only boots) =>
   * an uncapped RunBudget (observability-only, legacy behavior). The instance is held by
   * run_code so its `snapshot()` of actual spend can be accrued post-run.
   */
  makeRunBudget?: () => RunBudget;
  /**
   * Post-run daily accrual of ACTUAL spend (§P5 tier 3). Called on EVERY exit path (success
   * AND error, in a finally) with the per-run snapshot, so spent rows/requests/bytes are
   * always accrued into the daily BudgetDO. Backed by BUDGET_DO.increment in production;
   * optional so tests/unauthenticated boots can omit it.
   */
  accrueDailyBudget?: (snapshot: Record<string, number>) => Promise<void>;
  timeoutMs?: number;
}

export async function runCode(input: RunCodeInput, deps: RunCodeDeps): Promise<ToolTextResult> {
  // Held at function scope so the finally can accrue actual spend (§P5 tier 3). Undefined
  // when an early throw (size/mode/reason/reserve/transpile) fires before the budget exists
  // — nothing was spent, so accrual is skipped.
  let runBudget: RunBudget | undefined;
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

    // 2.6) per-user auth preflight (§6b). Must precede the daily reserve + executor so a
    //      per_user_oauth caller with no usable ServiceNow token reauths BEFORE any billable
    //      Worker (or budget reservation) — host-attested reauth_required, carrying authorizeUrl
    //      via the McpToolError detail (toToolResult propagates it). No-op in integration_user.
    if (deps.preflightAuth) {
      await deps.preflightAuth();
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
    runBudget = deps.makeRunBudget?.() ?? new RunBudget();
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
  } finally {
    // POST-RUN ACCRUAL (§P5 tier 3): accrue ACTUAL spend on EVERY exit path (success AND
    // error) so the daily BudgetDO always reflects what was spent. Skip when no budget was
    // ever created (early throw — nothing spent). Best-effort: an accrual failure must never
    // mask the real return value / thrown error, so it is swallowed here.
    if (runBudget && deps.accrueDailyBudget) {
      try {
        await deps.accrueDailyBudget(runBudget.snapshot());
      } catch (e) {
        // Swallow so accrual failure never masks the real run result/error — BUT this is NOT
        // merely a metering gap: budget.ts's admission check reads dim:rowsReturned/
        // dim:bytesReturned, which are written ONLY by this (now-failed) accrual. So a
        // PERSISTENT BUDGET_DO failure silently DISABLES the daily rows/bytes ceiling — it
        // degrades to per-run enforcement, backstopped only by the hard uniqueWorkers daily
        // cap (reserved pre-run). Emit an observable signal so that silent disable is detectable.
        console.error("accrueDailyBudget failed:", e instanceof Error ? e.message : String(e));
      }
    }
  }
}
