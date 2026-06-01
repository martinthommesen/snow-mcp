// Recoverability classification (plan §7.7; gate S18). Makes "recoverable" honest per
// operation — and narrows the claim where snapshots aren't stored. Pure host logic.

import { isSnapshotEnabled, type SnapshotConfig } from "./snapshots.js";
import type { MutationOp } from "../observability/audit.js";

export type Recoverability =
  | "reversible_from_snapshot" // tableUpdate on a snapshot-configured table
  | "non_recoverable"; // runServerScript, or update with no snapshot configured

export function recoverability(op: MutationOp, table: string | undefined, config: SnapshotConfig): Recoverability {
  switch (op) {
    case "runServerScript":
      return "non_recoverable"; // no general rollback guarantee (§7.7, SNOW_EGRESS)
    case "update":
      return table && isSnapshotEnabled(config, table) ? "reversible_from_snapshot" : "non_recoverable";
  }
}
