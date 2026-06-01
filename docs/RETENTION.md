# Retention & snapshot-store policy (plan §7.7, §11 T20)

A recovery snapshot store is **itself sensitive data** — "recoverable" must not silently
become "we built a second unmanaged sensitive database."

| Control | Policy |
|---|---|
| **Retention period** | Default 30 days, then auto-expiry (Cloudflare KV `expirationTtl`). |
| **Encryption** | AES-256-GCM (`auth/crypto.ts`) under a dedicated `SNAPSHOT_KEK`, versioned + rotated (current+previous window). |
| **Who can decrypt** | `x_1793136_mcp.admin` role + the key holder; never the integration user. |
| **Deletion workflow** | Cloudflare KV auto-expires each key at its 30-day `expirationTtl` — no separate scheduled purge job is needed on the host side (the executor nonce-table purge is a separate executor-side concern, P7). |
| **PII classification** | Snapshots may contain PII — classified accordingly; access audited. |
| **Table enablement** | `SNAPSHOT_ENABLED_TABLES` selects snapshot-backed tables. Empty means no snapshots, and the recovery claim is **narrowed** for that tenant (RECOVERY.md). |

Audit retention (`x_1793136_mcp_audit_log`) follows the same purge cadence; audit rows store
**hashes + attribution only** (no script body, no raw output, §10) so they are far less
sensitive than snapshots.

## Status

Policy defined and the host stores are now wired (P4): the recovery snapshot store is
`SNAPSHOT_KV` and the host audit trail is `AUDIT_KV`, both written with a **30-day Cloudflare
KV `expirationTtl`** (`tools/handlers.ts`). KV auto-expires each key at its TTL, so **no
separate scheduled purge job is needed on the host side** for either store (the executor
nonce-table purge is a separate, executor-side P7 concern). Snapshots are AES-256-GCM
sealed (`recovery/snapshots.ts`) under the versioned `SNAPSHOT_KEK` ring (`buildKekRing`,
P3); the integration user never holds the ring. `SNAPSHOT_ENABLED_TABLES` selects which
tables get snapshots; empty means none and narrows the recovery claim.
`TOKEN_KEK`/`SNAPSHOT_KEK` are declared in `.dev.vars.example`.
