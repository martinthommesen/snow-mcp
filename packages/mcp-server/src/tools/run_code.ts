// run_code tool pipeline (plan §3.1 order, §4.6). Enforced order:
//   size -> effective-mode (§2.0.1) -> [ActorPolicy + per-run budget enforced PER CALL
//   inside ServiceNowRPC] -> transpile -> execute -> serialize/finalize.
// The daily atomic BudgetDO reserve-before-load (§4.5) wraps this in production; the
// per-run budget and authorization are unit-verified locally against a mock RPC.

import type { Mode } from "@servicenow-codemode/shared";
import { resolveEffectiveMode } from "../authz/effective-mode.js";
import { transpileTs, TranspileFailure } from "../sandbox/transpile.js";
import { createExecutor, executeSnippet } from "../sandbox/executor.js";
import { serializeResult, utf8Len, capLogs, type CappedLogs } from "../sandbox/serialize.js";
import { SIZE_LIMITS } from "../config.js";
import { McpToolError, toToolResult, parseSandboxError } from "../sn/errors.js";
import { redactString } from "../observability/redact.js";
import { validateApprovalToken, validateIdempotencyKey, validateReason } from "../sn/validate.js";
import type { ServiceNowRPC } from "../sn/rpc.js";
import type { RunContext } from "../sn/mutation-guard.js";
import { RunBudget } from "../sn/run-budget.js";
import type { ToolTextResult } from "../server.js";

export interface RunCodeInput {
  code: string;
  mode?: Mode;
  reason?: string;
  idempotencyKey?: string;
  approvalToken?: string;
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
   * an uncapped RunBudget for local harnesses only. The instance is held by
   * run_code so its `snapshot()` of actual spend can be accrued post-run.
   */
  makeRunBudget?: () => RunBudget;
  /**
   * Post-run daily RECONCILIATION of ACTUAL spend (§P5 tier 3 / finding 5). Called on EVERY
   * exit path AFTER a successful reserve (success AND error, in a finally). Because the
   * pre-run reserve commits the per-run MAXIMUMS (so concurrent runs can't collectively
   * overshoot), this folds the per-run snapshot back into the daily BudgetDO by REFUNDING the
   * unused reservation and accruing the unreserved dimensions. `snapshot` is undefined when a
   * post-reserve early exit (e.g. transpile failure) fired before the RunBudget existed —
   * meaning nothing was spent, so the full reservation is refunded. Backed by
   * BUDGET_DO.reconcile in production; optional so tests/unauthenticated boots can omit it.
   */
  reconcileDailyBudget?: (snapshot?: Record<string, number>) => Promise<void>;
  timeoutMs?: number;
}

function hostSignalResult(
  code: "budget_exceeded" | "reauth_required",
  text: string,
  cappedLogs: CappedLogs,
  budget: Record<string, number>,
  detail?: Record<string, string>,
): ToolTextResult {
  return {
    content: [{ type: "text", text }],
    isError: true,
    structuredContent: {
      code,
      logs: cappedLogs.logs,
      ...(cappedLogs.truncated ? { logsTruncated: true } : {}),
      budget,
      ...(detail ? { detail } : {}),
    },
  };
}

export async function runCode(input: RunCodeInput, deps: RunCodeDeps): Promise<ToolTextResult> {
  // Held at function scope so the finally can reconcile actual spend (§P5 tier 3). Undefined
  // when an early throw (size/mode/reason/reserve/transpile) fires before the budget exists.
  let runBudget: RunBudget | undefined;
  // True once the pre-run reserve COMMITTED the per-run maximums. The finally must then
  // reconcile/refund on EVERY post-reserve exit — including a transpile failure that throws
  // before `runBudget` exists (finding 5) — or the reserved maximums leak and starve the cap.
  let reserved = false;
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
      throw new McpToolError("mode_not_permitted", `Requested mode "${resolved.requested}" exceeds the ceiling "${resolved.ceiling}".`, {
        ceiling: resolved.ceiling,
        ceilingSource: resolved.ceilingSource,
      });
    }
    const effectiveMode = resolved.effective;

    // admin_script requires a mandatory reason (§3.5; approval gate is layered above).
    if (effectiveMode === "admin_script" && !input.reason?.trim()) {
      throw new McpToolError("precondition_required", "admin_script requires a non-empty `reason`.");
    }
    const reason = input.reason !== undefined ? validateReason(input.reason) : undefined;
    const runKey = input.idempotencyKey !== undefined ? validateIdempotencyKey(input.idempotencyKey) : undefined;
    const approvalToken = input.approvalToken !== undefined ? validateApprovalToken(input.approvalToken) : undefined;

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
        // All-or-nothing: a denied reserve committed NOTHING, so `reserved` stays false and the
        // finally skips reconciliation (no phantom refund).
        throw new McpToolError("budget_exceeded", `Daily ${reservation.dimension ?? "budget"} cap exhausted.`, {
          dimension: reservation.dimension,
        });
      }
      reserved = true;
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
    //    the tool-level reason, the tool-level idempotencyKey = the runKey, and any
    //    host-level approvalToken). The mutating/executor RPC methods hard-require the
    //    runKey (§P4); snippet calls no longer carry per-call idempotency or reason fields.
    const runContext: RunContext = {
      requestId: crypto.randomUUID(),
      ...(reason !== undefined ? { reason } : {}),
      ...(runKey !== undefined ? { runKey } : {}),
      ...(approvalToken !== undefined ? { approvalToken } : {}),
    };
    runBudget = deps.makeRunBudget?.() ?? new RunBudget();
    const rpc = deps.buildRpc(effectiveMode, runBudget, runContext);
    const executor = createExecutor(deps.loader, deps.timeoutMs === undefined ? {} : { timeoutMs: deps.timeoutMs });
    const exec = await executeSnippet(executor, js, [{ name: "servicenow", fns: rpc.fns() }]);

    // 5) serialize / finalize
    const budget = runBudget.snapshot();
    // M-3: cap snippet logs (entry count + cumulative bytes) ONCE for every return path below —
    // exec.logs was previously spliced in verbatim, bypassing the output byte cap.
    const cappedLogs = capLogs(exec.logs ?? [], SIZE_LIMITS.maxLogEntries, SIZE_LIMITS.maxLogBytes);

    // Host-attested error code (§P2). The attested `code` is derived ONLY from monotonic
    // host signals, never from the snippet-controlled error text — a forged
    // `throw new Error("[[reauth_required]] https://evil")` raises no signal and cannot
    // taint `code`. Priority: budget_exceeded → reauth_required → (any error) run_error.
    // Signals are checked BEFORE success: a snippet that triggers a host condition then
    // swallows it and returns cleanly still surfaces the attested code.
    const signals = rpc.hostSignals;
    if (signals.budgetExceeded) {
      const dimension = signals.budgetExceeded.dimension;
      return hostSignalResult(
        "budget_exceeded",
        `[budget_exceeded] Per-run ${dimension ?? "budget"} cap exceeded.`,
        cappedLogs,
        budget,
        dimension ? { dimension } : undefined,
      );
    }
    if (signals.reauthRequired) {
      const authorizeUrl = signals.reauthRequired.authorizeUrl;
      return hostSignalResult(
        "reauth_required",
        "[reauth_required] ServiceNow re-authentication required.",
        cappedLogs,
        budget,
        authorizeUrl ? { authorizeUrl } : undefined,
      );
    }
    if (exec.error) {
      // No host signal: the host cannot vouch for any `[[code]]` in the snippet-controlled
      // message (it may be forged, or the snippet may have caught a host error and thrown
      // its own). Attest `run_error`; keep the parsed message as ADVISORY text only.
      const parsed = parseSandboxError(exec.error);
      // L-1: redact the advisory message — a raw (non-McpToolError) host throw can reach this
      // in-band path (e.g. servicenow_oauth_failed:), and unlike toToolResult() it is otherwise
      // returned to the model unredacted. Mirror the catch-path redaction for symmetry.
      const safeMessage = redactString(parsed.message);
      return {
        content: [{ type: "text", text: `[run_error] ${safeMessage}` }],
        isError: true,
        structuredContent: { code: "run_error", error: safeMessage, logs: cappedLogs.logs, ...(cappedLogs.truncated ? { logsTruncated: true } : {}), budget },
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
        logs: cappedLogs.logs, ...(cappedLogs.truncated ? { logsTruncated: true } : {}),
        budget,
      },
    };
  } catch (e) {
    return toToolResult(e);
  } finally {
    // POST-RUN RECONCILIATION (§P5 tier 3 / finding 5): the pre-run reserve committed the per-run
    // MAXIMUMS, so reconcile on EVERY post-reserve exit — success, error, AND a transpile failure
    // that threw before `runBudget` existed (snapshot undefined => full refund) — to release the
    // unused reservation. Gated on `reserved`, NOT on `runBudget`, so the transpile-failure path
    // still refunds. Best-effort: a reconcile failure must never mask the real return/throw, so it
    // is swallowed here.
    if (reserved && deps.reconcileDailyBudget) {
      try {
        await deps.reconcileDailyBudget(runBudget?.snapshot());
      } catch (e) {
        // Swallow so a reconcile failure never masks the real run result/error. The failure
        // direction is SAFE/fail-closed (finding 5): the pre-run reserve already committed the
        // per-run MAXIMUMS, so a dropped reconcile leaves those maximums reserved — the day
        // OVER-counts and denies the next run EARLY rather than under-counting. (rows/bytes are
        // reserved at 0, so a dropped reconcile under-accrues them — the documented residual,
        // backstopped by the deny-next-run admission check and the uniqueWorkers cap.)
        // M-2: emit a STRUCTURED, alertable signal so an SRE log-metric can page on a sustained
        // streak. We deliberately do NOT fail the next run closed here: that would require
        // cross-DO streak state and could turn a transient blip into a self-inflicted outage.
        console.error(
          JSON.stringify({
            event: "budget_reconcile_failed",
            severity: "alert",
            note: "daily reservation not refunded (over-counts, denies early) and rows/bytes under-accrued until BUDGET_DO recovers; uniqueWorkers cap still bounds worst case",
            error: e instanceof Error ? e.message : String(e),
          }),
        );
      }
    }
  }
}
