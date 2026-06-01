// Per-mutation safety orchestration for the LIVE mutating/executor path (plan §P4).
//
// This is the wiring that puts the already-unit-tested safety modules in front of every
// host-mediated mutation (tableUpdate) and executor call (runServerScript):
//   idempotency ledger (do/mutation-ledger.ts) → approval gate (authz/approval.ts) →
//   recovery snapshot (recovery/snapshots.ts) → AUDIT-BEFORE-EFFECT (observability/audit.ts)
//   → the effect → audit update with result.
//
// It does NOT re-implement any of those modules — it composes them via injected callbacks
// so ServiceNowRPC stays readable and the orchestration is independently testable against
// fakes (no live SN, no real DO/KV needed).
//
// Exactly-once semantics (S17): a PRE-SEND failure (validation, gate, snapshot-persist,
// audit-write) is a clean `fail()` — the effect never left the host, so a retry is safe.
// A POST-SEND unknown outcome (transport timeout / 5xx / abort, where the PATCH or executor
// POST MAY have applied) is `markIndeterminate()` — NEVER `fail()` — so a retry is BLOCKED.

import { McpToolError } from "./errors.js";
import { buildAuditRecord, emitAudit, hashValue, type AuditSink, type MutationOp } from "../observability/audit.js";
import type { Mode } from "@servicenow-codemode/shared";

export type { AuditSink } from "../observability/audit.js";

// ── Logical-effect request hashes (idempotency key, plan §P4) ──
// The hash captures the LOGICAL EFFECT only — it EXCLUDES volatile signing fields
// (nonce, issued_at, signature) so the SAME logical mutation retried with a fresh nonce
// dedups, while a DIVERGENT effect (different fields/script/reason) is a conflict.

/** Stable key-ordered serialization for hashing (effect fields are a flat string map). */
function canonicalFields(fields: Record<string, unknown>): string {
  const keys = Object.keys(fields).sort();
  return JSON.stringify(keys.map((k) => [k, fields[k] ?? null]));
}

/** tableUpdate effect hash: method, table, sys_id, canonical(fields), mode, reason. */
export async function tableUpdateRequestHash(input: {
  table: string;
  sysId: string;
  fields: Record<string, unknown>;
  mode: Mode;
  reason?: string;
}): Promise<string> {
  return hashValue([
    "tableUpdate",
    input.table,
    input.sysId,
    canonicalFields(input.fields),
    input.mode,
    input.reason ?? "",
  ]);
}

/** runServerScript effect hash: method, script, reason, effectiveMode, instance, actor —
 *  EXCLUDING the volatile nonce/issued_at/signature the signing layer adds per send. */
export async function runServerScriptRequestHash(input: {
  script: string;
  reason: string;
  mode: Mode;
  instance: string;
  actorUserId: string;
}): Promise<string> {
  return hashValue([
    "runServerScript",
    input.script,
    input.reason,
    input.mode,
    input.instance,
    input.actorUserId,
  ]);
}

/** A claimed idempotency slot for one logical mutation (one ordinal of one run). */
export interface LedgerHandle {
  /** Claim execution: new=execute, replay=return stored result, blocked=throw conflict. */
  begin(requestHash: string): Promise<LedgerBegin>;
  /** Record the effect's result (only after a confirmed post-send success). */
  complete(result: unknown): Promise<void>;
  /** Clean pre-send failure — retry is safe. */
  fail(): Promise<void>;
  /** Post-send unknown outcome — retry is BLOCKED (S17). */
  markIndeterminate(): Promise<void>;
}

export type LedgerBegin =
  | { state: "new" }
  | { state: "replay"; result: unknown }
  | { state: "blocked"; status: string };

/** Host-authoritative per-run context threaded from run_code (never snippet-supplied). */
export interface RunContext {
  requestId: string;
  /** Tool-level idempotencyKey (the runKey). Mutations HARD-REQUIRE this. */
  runKey?: string;
  /** Tool-level reason (admin_script mandatory; audited + hashed into requestHash). */
  reason?: string;
  /** Tool-level second-approval token, never snippet-supplied. */
  approvalToken?: string;
}

/** Audit attribution carried from the signed/authenticated actor (no secrets). */
export interface AuditIdentity {
  mcpActorUserId: string;
  mcpActorEmail?: string;
  snowEffectiveUser?: string;
}

/**
 * The capabilities ServiceNowRPC needs to guard a mutation. Durable layers are optional
 * for focused unit contexts; live handler wiring sets `durabilityRequired` so missing
 * ledger/audit bindings fail closed before any ServiceNow effect.
 */
export interface MutationGuard {
  run: RunContext;
  instance: string;
  identity: AuditIdentity;
  now: () => number;
  /** Live mutating/executor paths require both ledger and durable audit. */
  durabilityRequired?: boolean;
  /** Build the ledger handle for this run+ordinal. Absent => no durable ledger (tests). */
  ledger?: (ordinal: number) => LedgerHandle;
  /** Durable audit sink (AUDIT_KV-backed). Absent => no durable audit (tests). */
  audit?: AuditSink;
}

/** Inputs describing ONE logical mutation effect to guard. */
export interface GuardedEffect<T> {
  ordinal: number;
  op: MutationOp;
  table?: string;
  sysId?: string;
  /** Human justification, stored on the audit row (attribution only — never the script). */
  reason?: string;
  /** Method-specific logical-effect hash (excludes volatile signing fields). */
  requestHash: string;
  /** Optional gate run BEFORE the effect (approval). Throws to deny. */
  preflight?: () => void | Promise<void>;
  /** Optional before-state capture + durable persist; throws => DENY (fail closed). */
  snapshot?: () => Promise<void>;
  /** before/after content for audit hashing (hashes only — never raw). */
  before?: unknown;
  /** The actual ServiceNow effect. Resolves with the result + after-content for audit. */
  effect: () => Promise<{ result: T; after?: unknown }>;
  /** Classify whether a thrown effect error is POST-SEND unknown (indeterminate) or
   *  a clean PRE/at-send failure. Defaults to treating all effect throws as indeterminate
   *  (the effect call already left the host). */
  isIndeterminate?: (err: unknown) => boolean;
}

const AUDIT_REQUEST_ID_SEP = "/"; // requestId/ordinal — never overwrites across a run

/** AUDIT_KV key for one audit EVENT (per ordinal; denials get their own key too). */
export function auditKey(utcDateKey: string, requestId: string, ordinal: number): string {
  return `${utcDateKey}${AUDIT_REQUEST_ID_SEP}${requestId}${AUDIT_REQUEST_ID_SEP}${ordinal}`;
}

/**
 * Orchestrate one guarded mutation. Order is a security property:
 *   1. ledger.begin (idempotency) — replay first re-checks the current preflight, then returns
 *      stored result; blocked throws.
 *   2. preflight gate (approval) — throw => fail() (pre-send) + denial audit.
 *   3. snapshot persist — throw => fail() (pre-send) + denial audit + DENY (fail closed).
 *   4. AUDIT-BEFORE-EFFECT: write the intent row (status "intent"); if the audit WRITE
 *      throws => fail() + DENY.
 *   5. effect — pre-send throw => fail(); post-send unknown => markIndeterminate().
 *   6. supersede the same ordinal key with the OUTCOME: "ok" on success (here), "error" on a
 *      thrown effect (emitOutcomeError). A post-effect audit-update failure does NOT undo the
 *      effect (it already applied) and does NOT mark indeterminate (the result IS known) — but
 *      the durable row then stays "intent", reading as unresolved, never a false success.
 */
export async function guardMutation<T>(guard: MutationGuard, eff: GuardedEffect<T>): Promise<T> {
  // L-2: pin the audit-key date ONCE at intent time and reuse it for the outcome (ok/error) row, so
  // intent + outcome share an AUDIT_KV key even if the effect straddles UTC midnight (deriving the
  // date from each row's own write-time `ts` would leave the day-D intent row orphaned/unresolved).
  const auditDateKey = new Date(guard.now()).toISOString().slice(0, 10);
  if (guard.durabilityRequired && (!guard.ledger || !guard.audit)) {
    throw new McpToolError(
      "internal_error",
      "mutation durability is not fully configured — refusing to mutate (fail closed).",
      { ledger: Boolean(guard.ledger), audit: Boolean(guard.audit) },
    );
  }
  // The tool-level idempotencyKey is mandatory for any mutation (no host-generated
  // fallback). A missing key is itself a DENIAL and is audited as such.
  if (!guard.run.runKey) {
    const err = new McpToolError("capability_denied", "mutations require an idempotencyKey.");
    await emitDenial(guard, eff, err);
    throw err;
  }
  const ledger = guard.ledger?.(eff.ordinal);

  // 1) Idempotency claim.
  if (ledger) {
    const claim = await ledger.begin(eff.requestHash);
    if (claim.state === "replay") {
      try {
        await eff.preflight?.();
      } catch (e) {
        await emitDenial(guard, eff, e);
        throw e;
      }
      return claim.result as T;
    }
    if (claim.state === "blocked") {
      const err = new McpToolError("capability_denied", `Idempotency conflict (${claim.status}) — retry blocked.`, {
        idempotencyKey: guard.run.runKey,
        ordinal: eff.ordinal,
      });
      await emitDenial(guard, eff, err);
      throw err;
    }
  }

  // Emit a denial audit row + clean the ledger, then re-throw (DENY, fail closed).
  const denyAndThrow = async (err: unknown): Promise<never> => {
    await ledger?.fail();
    await emitDenial(guard, eff, err);
    throw err;
  };

  // 2) Approval / preflight gate.
  try {
    await eff.preflight?.();
  } catch (e) {
    return denyAndThrow(e);
  }

  // 3) Recovery snapshot — fail closed if it can't persist (no recovery row => no mutate).
  try {
    await eff.snapshot?.();
  } catch (e) {
    return denyAndThrow(
      e instanceof McpToolError
        ? e
        : new McpToolError("internal_error", "recovery snapshot could not be persisted — refusing to mutate (fail closed)."),
    );
  }

  // 4) AUDIT-BEFORE-EFFECT — write the intent row. A failed audit WRITE denies the op
  //    (mirrors the executor's audit-first invariant). No durable sink => skip (tests).
  if (guard.audit) {
    try {
      const intent = await buildAuditRecord({
        ts: guard.now(),
        dateKey: auditDateKey,
        requestId: guard.run.requestId,
        ordinal: eff.ordinal,
        instance: guard.instance,
        actor: guard.identity,
        op: eff.op,
        ...(eff.table !== undefined ? { table: eff.table } : {}),
        ...(eff.sysId !== undefined ? { sysId: eff.sysId } : {}),
        ...(eff.before !== undefined ? { before: eff.before } : {}),
        ...(eff.reason !== undefined ? { reason: eff.reason } : {}),
        // Distinct PRE-effect state: superseded by "ok"/"error" at the same ordinal key once
        // the effect resolves. A dropped outcome row leaves "intent" — an unresolved intent,
        // never a false success (plan §P4).
        status: "intent",
      });
      await emitAudit(guard.audit, intent);
    } catch {
      return denyAndThrow(
        new McpToolError("internal_error", "audit record could not be written — refusing to mutate (fail closed)."),
      );
    }
  }

  // 5) The effect. Pre-send throws are clean fail(); post-send unknown is indeterminate.
  let outcome: { result: T; after?: unknown };
  try {
    outcome = await eff.effect();
  } catch (e) {
    const indeterminate = eff.isIndeterminate ? eff.isIndeterminate(e) : true;
    if (indeterminate) {
      await ledger?.markIndeterminate();
    } else {
      await ledger?.fail();
    }
    // AUDIT THE OUTCOME: the effect threw — the durable intent row at this ordinal key must
    // NOT stay "ok". Supersede it with an "error" row (same key) carrying the error class +
    // whether the outcome was indeterminate. Best-effort: the effect already left the host,
    // so a dropped error-audit is a durability gap, not a safety one (mirrors the success path).
    await emitOutcomeError(guard, eff, e, indeterminate, auditDateKey);
    // The effect throw is NOT a host-side denial — surface it as-is (it may carry a typed code).
    throw e;
  }

  // 6) Confirmed success — record the result, then audit the outcome.
  await ledger?.complete(outcome.result);
  if (guard.audit) {
    try {
      const done = await buildAuditRecord({
        ts: guard.now(),
        dateKey: auditDateKey,
        requestId: guard.run.requestId,
        ordinal: eff.ordinal,
        instance: guard.instance,
        actor: guard.identity,
        op: eff.op,
        ...(eff.table !== undefined ? { table: eff.table } : {}),
        ...(eff.sysId !== undefined ? { sysId: eff.sysId } : {}),
        ...(eff.before !== undefined ? { before: eff.before } : {}),
        ...(outcome.after !== undefined ? { after: outcome.after } : {}),
        ...(eff.reason !== undefined ? { reason: eff.reason } : {}),
        status: "ok",
      });
      await emitAudit(guard.audit, done);
    } catch {
      // The effect already applied and its result is known — do not undo / re-block.
      // A dropped success-audit row is a durability gap, not a correctness one.
    }
  }
  return outcome.result;
}

async function emitDenial<T>(guard: MutationGuard, eff: GuardedEffect<T>, err: unknown): Promise<void> {
  if (!guard.audit) return;
  try {
    const rec = await buildAuditRecord({
      ts: guard.now(),
      requestId: guard.run.requestId,
      ordinal: eff.ordinal,
      instance: guard.instance,
      actor: guard.identity,
      op: eff.op,
      ...(eff.table !== undefined ? { table: eff.table } : {}),
      ...(eff.sysId !== undefined ? { sysId: eff.sysId } : {}),
      ...(eff.reason !== undefined ? { reason: eff.reason } : {}),
      status: "denied",
      errorClass: err instanceof McpToolError ? err.code : "internal_error",
    });
    await emitAudit(guard.audit, rec);
  } catch {
    // best-effort denial audit; the deny still propagates.
  }
}

/** Supersede the intent row with an "error" outcome row (same ordinal key) when the effect
 *  threw. Best-effort — the effect already left the host. `indeterminate` distinguishes a
 *  post-send-unknown (retry blocked) from a clean failure (retry-safe). */
async function emitOutcomeError<T>(guard: MutationGuard, eff: GuardedEffect<T>, err: unknown, indeterminate: boolean, dateKey: string): Promise<void> {
  if (!guard.audit) return;
  const code = err instanceof McpToolError ? err.code : "internal_error";
  try {
    const rec = await buildAuditRecord({
      ts: guard.now(),
      dateKey, // L-2: reuse the intent-time date so this outcome row supersedes its intent row
      requestId: guard.run.requestId,
      ordinal: eff.ordinal,
      instance: guard.instance,
      actor: guard.identity,
      op: eff.op,
      ...(eff.table !== undefined ? { table: eff.table } : {}),
      ...(eff.sysId !== undefined ? { sysId: eff.sysId } : {}),
      ...(eff.reason !== undefined ? { reason: eff.reason } : {}),
      status: "error",
      errorClass: indeterminate ? `${code}:indeterminate` : code,
    });
    await emitAudit(guard.audit, rec);
  } catch {
    // best-effort outcome audit; the original effect error still propagates.
  }
}
