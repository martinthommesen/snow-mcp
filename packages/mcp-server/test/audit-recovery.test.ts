import { describe, expect, it } from "vitest";
import { buildAuditRecord, emitAudit, hashValue, type AuditRecord } from "../src/observability/audit.js";
import { takeSnapshot, readSnapshot, reversalFields, isSnapshotEnabled, isExpired, type SnapshotConfig } from "../src/recovery/snapshots.js";
import { recoverability, isDeletePermitted } from "../src/recovery/policy.js";
import { auditKey } from "../src/sn/mutation-guard.js";
import type { KekRing } from "../src/auth/crypto.js";

// ─── §7.2 — host-side audit ───────────────────────────────────────────────────
describe("§7.2 audit", () => {
  it("records actor + op + before/after HASHES (never raw values)", async () => {
    const rec = await buildAuditRecord({
      ts: 1, requestId: "r1", instance: "inst1",
      actor: { mcpActorUserId: "u1", snowEffectiveUser: "svc" },
      op: "update", table: "incident", sysId: "abc",
      before: { state: 1, password: "p@ss" }, after: { state: 2 }, status: "ok",
    });
    expect(rec.op).toBe("update");
    expect(rec.beforeHash).toBe(await hashValue({ state: 1, password: "p@ss" }));
    expect(rec.afterHash).toBe(await hashValue({ state: 2 }));
    // No raw before/after on the record.
    expect((rec as unknown as Record<string, unknown>).before).toBeUndefined();
  });

  it("emitAudit redacts stray sensitive strings", async () => {
    const captured: AuditRecord[] = [];
    const rec = await buildAuditRecord({ ts: 1, requestId: "Bearer abcdef1234567890", instance: "i", actor: { mcpActorUserId: "u" }, op: "delete", status: "ok" });
    await emitAudit((r) => { captured.push(r); }, rec);
    expect(captured[0]!.requestId).toContain("[REDACTED]");
  });

  // ─── §P4 — records carry ordinal + reason (attribution); key never overwrites ──
  it("carries the per-run ordinal + reason and survives emit (reason is attribution, not a secret)", async () => {
    const captured: AuditRecord[] = [];
    const rec = await buildAuditRecord({
      ts: 1, requestId: "req-1", ordinal: 2, instance: "i",
      actor: { mcpActorUserId: "u" }, op: "runServerScript",
      reason: "rotate the cache", status: "ok",
    });
    await emitAudit((r) => { captured.push(r); }, rec);
    expect(captured[0]!.ordinal).toBe(2);
    expect(captured[0]!.reason).toBe("rotate the cache");
  });

  it("auditKey gives each (requestId, ordinal) its own per-day key — distinct mutations never collide", () => {
    expect(auditKey("2026-05-31", "req-1", 1)).toBe("2026-05-31/req-1/1");
    expect(auditKey("2026-05-31", "req-1", 1)).not.toBe(auditKey("2026-05-31", "req-1", 2));
    expect(auditKey("2026-05-31", "req-1", 1)).not.toBe(auditKey("2026-05-31", "req-2", 1));
  });
});

// ─── §7.7 — encrypted recovery snapshots ──────────────────────────────────────
const ring: KekRing = { current: { version: "2026-05", keyBytes: new Uint8Array(32).fill(3) } };
const config: SnapshotConfig = { enabledTables: ["incident"], retentionMs: 30 * 24 * 3600 * 1000 };

describe("§7.7 recovery snapshots", () => {
  it("takes an encrypted snapshot for a configured table and round-trips", async () => {
    const snap = await takeSnapshot(config, ring, {
      table: "incident", sysId: "abc", takenAt: 1000,
      before: { state: "1", short_description: "old" }, after: { state: "2", short_description: "new" },
    });
    expect(snap).not.toBeNull();
    expect(snap!.envelope.alg).toBe("AES-256-GCM");
    const { before, after } = await readSnapshot(ring, snap!);
    expect(before.state).toBe("1");
    expect(after.state).toBe("2");
    expect(await reversalFields(ring, snap!)).toEqual({ state: "1", short_description: "old" });
  });

  it("returns null (narrows the recovery claim) for non-configured tables", async () => {
    expect(isSnapshotEnabled(config, "change_request")).toBe(false);
    const snap = await takeSnapshot(config, ring, { table: "change_request", sysId: "x", takenAt: 1, before: {}, after: {} });
    expect(snap).toBeNull();
  });

  it("fails closed on a tampered/wrong-table AAD", async () => {
    const snap = await takeSnapshot(config, ring, { table: "incident", sysId: "abc", takenAt: 1, before: { a: 1 }, after: { a: 2 } });
    const tampered = { ...snap!, table: "problem" }; // AAD no longer matches
    await expect(readSnapshot(ring, tampered)).rejects.toThrow();
  });

  it("flags snapshots past the retention window for purge", () => {
    const snap = { table: "incident", sysId: "a", takenAt: 0, envelope: {} as never };
    expect(isExpired(config, snap, config.retentionMs + 1)).toBe(true);
    expect(isExpired(config, snap, config.retentionMs - 1)).toBe(false);
  });
});

// ─── §7.7 / S18 — recovery evidence: honest per-op recoverability ─────────────
describe("§7.7 / S18 recoverability classification", () => {
  it("classifies each operation honestly (claim narrowed without a snapshot)", () => {
    expect(recoverability("update", "incident", config)).toBe("reversible_from_snapshot");
    expect(recoverability("update", "change_request", config)).toBe("non_recoverable"); // not configured
    expect(recoverability("delete", "incident", config)).toBe("soft_delete_only");
    expect(recoverability("runServerScript", undefined, config)).toBe("non_recoverable");
    expect(recoverability("importSet", "incident", config)).toBe("idempotent_cleanup");
  });

  it("tableDelete is admin_script-only (disallowed by default)", () => {
    expect(isDeletePermitted({ mode: "read_only" })).toBe(false);
    expect(isDeletePermitted({ mode: "write" })).toBe(false);
    expect(isDeletePermitted({ mode: "admin_script" })).toBe(true);
  });
});
