// Recovery snapshots (plan §7.7, T20). Encrypted before/after field snapshots for
// CONFIGURED tables, so a `tableUpdate` is reversible. Reuses the AES-GCM envelope
// (auth/crypto.ts) under a dedicated SNAPSHOT_KEK. The snapshot store is itself
// sensitive (RETENTION.md): retention window, KEK rotation, access control, PII class,
// and explicit table enablement. Pure host logic (crypto) — unit-verified; persistent
// storage retention is enforced by the KV write TTL in tools/handlers.ts.

import { seal, open, type KekRing, type TokenEnvelope } from "../auth/crypto.js";

export interface SnapshotConfig {
  /** Tables for which before/after snapshots are stored. Others: no snapshot (claim narrowed). */
  enabledTables: readonly string[];
}

export interface Snapshot {
  table: string;
  sysId: string;
  takenAt: number;
  /** Encrypted JSON of { before, after } field maps. */
  envelope: TokenEnvelope;
}

const AAD = (table: string, sysId: string) => `snapshot|${table}|${sysId}`;

export function isSnapshotEnabled(config: SnapshotConfig, table: string): boolean {
  return config.enabledTables.includes(table);
}

/** Take an encrypted before/after snapshot for a configured table. Returns null when
 *  snapshots are disabled for the table (the recovery claim is then narrowed). */
export async function takeSnapshot(
  config: SnapshotConfig,
  ring: KekRing,
  input: { table: string; sysId: string; takenAt: number; before: Record<string, unknown>; after: Record<string, unknown> },
): Promise<Snapshot | null> {
  if (!isSnapshotEnabled(config, input.table)) return null;
  const plaintext = JSON.stringify({ before: input.before, after: input.after });
  const envelope = await seal(plaintext, AAD(input.table, input.sysId), ring);
  return { table: input.table, sysId: input.sysId, takenAt: input.takenAt, envelope };
}

/** Decrypt a snapshot to its before/after maps (admin/key-holder only). */
export async function readSnapshot(
  ring: KekRing,
  snap: Snapshot,
): Promise<{ before: Record<string, unknown>; after: Record<string, unknown> }> {
  const plaintext = await open(snap.envelope, AAD(snap.table, snap.sysId), ring);
  return JSON.parse(plaintext);
}

/** The field map to write to revert `tableUpdate` to its pre-change state. */
export async function reversalFields(ring: KekRing, snap: Snapshot): Promise<Record<string, unknown>> {
  return (await readSnapshot(ring, snap)).before;
}
