import { DurableObject } from "cloudflare:workers";
import { MUTATION_REPLAY_MAX_BYTES, replaySafeResult } from "../sn/replay-payload.js";

// MutationLedgerDO (plan §2.10, §7.3) — leveled idempotency, keyed by
// idFromName("<userId>|<instanceHost>|<idempotencyKey>:<ordinal>"), so each
// (actor, instance, key, ordinal) has a stable object across deploys. Verified locally (S17).
//
//  Level 1 (host-mediated tableCreate/Update/Delete/importSet/attachment): fully
//          ledgered — a replay returns the original result.
//  Level 2 (runServerScript): dedupe by request-hash before execution; an INDETERMINATE
//          (timed-out/unknown) outcome must NOT silently re-execute on retry (S17).
//  Level 3 (internal mutations inside arbitrary script): not individually idempotent —
//          documented limitation, not enforced here.

export type LedgerStatus = "started" | "completed" | "failed" | "indeterminate";
export const MUTATION_LEDGER_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
export const MUTATION_LEDGER_MAX_REPLAY_BYTES = MUTATION_REPLAY_MAX_BYTES;

export type BeginResult =
  | { state: "new" } // caller should execute
  | { state: "replay"; result: unknown } // return the original result, do NOT re-execute
  | { state: "blocked"; status: LedgerStatus }; // in-flight or indeterminate — do NOT execute

export interface LedgerRecord {
  status: LedgerStatus;
  requestHash: string;
  expiresAt: number;
  result?: unknown;
}

const RECORD_KEY = "rec";
const ledgerStatuses = new Set<LedgerStatus>(["started", "completed", "failed", "indeterminate"]);

function nextExpiry(): number {
  return Date.now() + MUTATION_LEDGER_RETENTION_MS;
}

export type NormalizedLedgerRecord =
  | { kind: "missing" | "expired" }
  | { kind: "migrated"; record: LedgerRecord }
  | { kind: "active"; record: LedgerRecord };

export function normalizeLedgerRecordForStorage(
  rec: Partial<LedgerRecord> | undefined,
  now: number = Date.now(),
): NormalizedLedgerRecord {
  if (!rec || !ledgerStatuses.has(rec.status as LedgerStatus) || typeof rec.requestHash !== "string") {
    return { kind: "missing" };
  }
  if (typeof rec.expiresAt === "number") {
    if (rec.expiresAt <= now) {
      if (rec.status === "started" || rec.status === "indeterminate") {
        return {
          kind: "migrated",
          record: {
            status: rec.status,
            requestHash: rec.requestHash,
            expiresAt: now + MUTATION_LEDGER_RETENTION_MS,
          },
        };
      }
      return { kind: "expired" };
    }
    if (rec.status === "completed") {
      return {
        kind: "migrated",
        record: {
          status: "completed",
          requestHash: rec.requestHash,
          expiresAt: rec.expiresAt,
          result: replaySafeResult(rec.result),
        },
      };
    }
    return { kind: "active", record: rec as LedgerRecord };
  }
  if (rec.status === "failed") return { kind: "expired" };
  const retainedStatus = rec.status as Exclude<LedgerStatus, "failed">;
  return {
    kind: "migrated",
    record: {
      status: retainedStatus,
      requestHash: rec.requestHash,
      expiresAt: now + MUTATION_LEDGER_RETENTION_MS,
      ...(retainedStatus === "completed" ? { result: replaySafeResult(rec.result) } : {}),
    },
  };
}

export class MutationLedgerDO extends DurableObject {
  private chain: Promise<unknown> = Promise.resolve();

  private enqueue<T>(task: () => Promise<T>): Promise<T> {
    const run = this.chain.then(task);
    this.chain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  private runCritical<Args extends unknown[], T>(
    task: (...args: Args) => Promise<T>,
    ...args: Args
  ): Promise<T> {
    return this.enqueue(() => task.apply(this, args));
  }

  private async getActiveRecord(): Promise<LedgerRecord | undefined> {
    const rec = await this.ctx.storage.get<Partial<LedgerRecord>>(RECORD_KEY);
    const normalized = normalizeLedgerRecordForStorage(rec);
    if (normalized.kind === "missing" || normalized.kind === "expired") {
      if (rec) await this.ctx.storage.delete(RECORD_KEY);
      return undefined;
    }
    if (normalized.kind === "active") return normalized.record;
    if (normalized.kind === "migrated") {
      await this.ctx.storage.put(RECORD_KEY, normalized.record);
      await this.ctx.storage.setAlarm(normalized.record.expiresAt);
      return normalized.record;
    }
    return undefined;
  }

  private async putRecord(rec: Omit<LedgerRecord, "expiresAt">): Promise<void> {
    const record = { ...rec, expiresAt: nextExpiry() } satisfies LedgerRecord;
    await this.ctx.storage.put(RECORD_KEY, record);
    await this.ctx.storage.setAlarm(record.expiresAt);
  }

  /**
   * Claim execution for this idempotency key. Returns:
   *  - "new"     when the caller should execute (first time, or retry after a clean failure),
   *  - "replay"  with the stored result (already completed) — return it, do not re-run,
   *  - "blocked" when an attempt is in-flight ("started") or "indeterminate" (S17).
   * A request-hash mismatch on an existing key is treated as a conflict ("blocked").
   */
  async begin(requestHash: string): Promise<BeginResult> {
    return this.runCritical(this.beginCritical, requestHash);
  }

  private async beginCritical(requestHash: string): Promise<BeginResult> {
    const rec = await this.getActiveRecord();
    if (!rec) {
      await this.putRecord({ status: "started", requestHash });
      return { state: "new" };
    }
    if (rec.requestHash !== requestHash) return { state: "blocked", status: rec.status };
    switch (rec.status) {
      case "completed":
        return { state: "replay", result: rec.result };
      case "failed":
        // Clean failure — safe to retry.
        await this.putRecord({ status: "started", requestHash });
        return { state: "new" };
      case "started":
      case "indeterminate":
        return { state: "blocked", status: rec.status }; // S17: never silently re-execute
    }
  }

  async complete(result: unknown): Promise<void> {
    return this.runCritical(this.completeCritical, result);
  }

  private async completeCritical(result: unknown): Promise<void> {
    // Only a key with an in-flight ("started") attempt may be completed. A missing row
    // means complete() was called without a matching begin() — it must NOT invent a
    // record (which would stamp a result under an empty requestHash, replaying it for
    // ANY future hash). A stray complete() is a no-op (P4 fix of the :56 fabrication bug).
    const rec = await this.getActiveRecord();
    if (!rec || rec.status !== "started") return;
    await this.putRecord({ status: "completed", requestHash: rec.requestHash, result: replaySafeResult(result) });
  }

  async fail(): Promise<void> {
    return this.runCritical(this.failCritical);
  }

  private async failCritical(): Promise<void> {
    const rec = await this.getActiveRecord();
    if (rec?.status === "started") await this.putRecord({ status: "failed", requestHash: rec.requestHash });
  }

  /** Mark an outcome unknown (e.g. runServerScript timed out). Blocks future retries (S17). */
  async markIndeterminate(): Promise<void> {
    return this.runCritical(this.markIndeterminateCritical);
  }

  private async markIndeterminateCritical(): Promise<void> {
    const rec = await this.getActiveRecord();
    if (rec?.status === "started") await this.putRecord({ status: "indeterminate", requestHash: rec.requestHash });
  }

  async status(): Promise<LedgerStatus | "none"> {
    return (await this.getActiveRecord())?.status ?? "none";
  }

  override async alarm(): Promise<void> {
    const rec = await this.getActiveRecord();
    if (rec) await this.ctx.storage.setAlarm(rec.expiresAt);
  }
}
