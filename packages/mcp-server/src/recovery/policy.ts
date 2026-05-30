// Recoverability classification (plan §7.7; gate S18). Makes "recoverable" honest per
// operation — and narrows the claim where snapshots aren't stored. Pure host logic.

import { isSnapshotEnabled, type SnapshotConfig } from "./snapshots.js";
import type { MutationOp } from "../observability/audit.js";

export type Recoverability =
  | "reversible_from_snapshot" // tableUpdate on a snapshot-configured table
  | "soft_delete_only" // tableDelete: admin_script-only, soft-delete preferred
  | "idempotent_cleanup" // importSet/catalog: dedupe + created-record refs
  | "non_recoverable"; // runServerScript, or update with no snapshot configured

export function recoverability(op: MutationOp, table: string | undefined, config: SnapshotConfig): Recoverability {
  switch (op) {
    case "runServerScript":
      return "non_recoverable"; // no general rollback guarantee (§7.7, SNOW_EGRESS)
    case "delete":
      return "soft_delete_only";
    case "update":
      return table && isSnapshotEnabled(config, table) ? "reversible_from_snapshot" : "non_recoverable";
    case "importSet":
    case "attachmentWrite":
      return "idempotent_cleanup";
    case "create":
      return "idempotent_cleanup"; // created-record reference enables cleanup
  }
}

/** Is a tableDelete permitted? Disallowed by default — admin_script only (§7.7). */
export function isDeletePermitted(opts: { mode: "read_only" | "write" | "admin_script" }): boolean {
  return opts.mode === "admin_script";
}
