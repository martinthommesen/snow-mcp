# Recovery model (plan §7.7)

"Recoverable" needs more than hashes. Per operation:

| Operation | Recovery posture |
|---|---|
| `tableUpdate` | Store encrypted before/after field snapshots for **configured** tables (`recovery/snapshots.ts`, `SNAPSHOT_KEK`), or rely on `sys_audit` where sufficient. |
| `tableDelete` | **Disallowed by default** (`admin_script` only); soft-delete where possible, or store an encrypted preimage with a retention window. |
| `runServerScript` | **No general rollback guarantee** — labeled high-risk `admin_script`, non-recoverable (see SNOW_EGRESS.md). |
| `importSet` / catalog | Idempotency (MutationLedgerDO, §7.3) + created-record references for cleanup. |

If raw snapshots are too sensitive for a tenant, **say so and narrow the recovery claim**
for that tenant rather than implying full reversibility. Snapshot store policy →
`RETENTION.md`.

## Status

- Leveled idempotency (L1 replay / L2 indeterminate-blocks-retry / L3 documented limit) is
  **implemented + tested** (`do/mutation-ledger.ts`, S17).
- Encrypted snapshots (`recovery/snapshots.ts`) reuse the AES-GCM envelope (`auth/crypto.ts`,
  unit-verified) with a dedicated `SNAPSHOT_KEK`. The snapshot wiring into the mutating RPC
  path is **not yet built** (mutations are gated but the live mutate path needs the auth
  layer). The crypto primitive it depends on is verified.
