import { DurableObject } from "cloudflare:workers";

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

export type BeginResult =
  | { state: "new" } // caller should execute
  | { state: "replay"; result: unknown } // return the original result, do NOT re-execute
  | { state: "blocked"; status: LedgerStatus }; // in-flight or indeterminate — do NOT execute

interface LedgerRecord {
  status: LedgerStatus;
  requestHash: string;
  result?: unknown;
}

export class MutationLedgerDO extends DurableObject {
  /**
   * Claim execution for this idempotency key. Returns:
   *  - "new"     when the caller should execute (first time, or retry after a clean failure),
   *  - "replay"  with the stored result (already completed) — return it, do not re-run,
   *  - "blocked" when an attempt is in-flight ("started") or "indeterminate" (S17).
   * A request-hash mismatch on an existing key is treated as a conflict ("blocked").
   */
  async begin(requestHash: string): Promise<BeginResult> {
    const rec = await this.ctx.storage.get<LedgerRecord>("rec");
    if (!rec) {
      await this.ctx.storage.put("rec", { status: "started", requestHash } satisfies LedgerRecord);
      return { state: "new" };
    }
    if (rec.requestHash !== requestHash) return { state: "blocked", status: rec.status };
    switch (rec.status) {
      case "completed":
        return { state: "replay", result: rec.result };
      case "failed":
        // Clean failure — safe to retry.
        await this.ctx.storage.put("rec", { status: "started", requestHash } satisfies LedgerRecord);
        return { state: "new" };
      case "started":
      case "indeterminate":
        return { state: "blocked", status: rec.status }; // S17: never silently re-execute
    }
  }

  async complete(result: unknown): Promise<void> {
    // Only a key with an in-flight ("started") attempt may be completed. A missing row
    // means complete() was called without a matching begin() — it must NOT invent a
    // record (which would stamp a result under an empty requestHash, replaying it for
    // ANY future hash). A stray complete() is a no-op (P4 fix of the :56 fabrication bug).
    const rec = await this.ctx.storage.get<LedgerRecord>("rec");
    if (!rec) return;
    await this.ctx.storage.put("rec", { ...rec, status: "completed", result } satisfies LedgerRecord);
  }

  async fail(): Promise<void> {
    const rec = await this.ctx.storage.get<LedgerRecord>("rec");
    if (rec) await this.ctx.storage.put("rec", { ...rec, status: "failed" } satisfies LedgerRecord);
  }

  /** Mark an outcome unknown (e.g. runServerScript timed out). Blocks future retries (S17). */
  async markIndeterminate(): Promise<void> {
    const rec = await this.ctx.storage.get<LedgerRecord>("rec");
    if (rec) await this.ctx.storage.put("rec", { ...rec, status: "indeterminate" } satisfies LedgerRecord);
  }

  async status(): Promise<LedgerStatus | "none"> {
    return (await this.ctx.storage.get<LedgerRecord>("rec"))?.status ?? "none";
  }
}
