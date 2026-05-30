# Retention & snapshot-store policy (plan §7.7, §11 T20)

A recovery snapshot store is **itself sensitive data** — "recoverable" must not silently
become "we built a second unmanaged sensitive database."

| Control | Policy |
|---|---|
| **Retention period** | Default 30 days, then scheduled purge. |
| **Encryption** | AES-256-GCM (`auth/crypto.ts`) under a dedicated `SNAPSHOT_KEK`, versioned + rotated (current+previous window). |
| **Who can decrypt** | `x_mcp.admin` role + the key holder; never the integration user. |
| **Deletion workflow** | Scheduled purge job removes snapshots past retention. |
| **PII classification** | Snapshots may contain PII — classified accordingly; access audited. |
| **Tenant opt-out** | A tenant may disable snapshots; the recovery claim is then **narrowed** for that tenant (RECOVERY.md). |

Audit retention (`x_mcp_audit_log`) follows the same purge cadence; audit rows store
**hashes + attribution only** (no script body, no raw output, §10) so they are far less
sensitive than snapshots.

## Status

Policy defined; the snapshot store + purge job are not yet built (the crypto envelope it
would use is unit-verified). `TOKEN_KEK`/`SNAPSHOT_KEK` are declared in `.dev.vars.example`.
