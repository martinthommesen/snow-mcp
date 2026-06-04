# Retention & snapshot-store policy (plan §7.7, §11 T20)

A recovery snapshot store is **itself sensitive data** — "recoverable" must not silently
become "we built a second unmanaged sensitive database."

| Control | Policy |
|---|---|
| **Retention period** | Default 30 days, then auto-expiry (Cloudflare KV `expirationTtl`). |
| **Encryption** | AES-256-GCM (`auth/crypto.ts`) under a dedicated `SNAPSHOT_KEK_CURRENT`, versioned + rotated (current+previous window). |
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
sealed (`recovery/snapshots.ts`) under the versioned `SNAPSHOT_KEK_CURRENT` ring (`buildKekRing`,
P3); the integration user never holds the ring. `SNAPSHOT_ENABLED_TABLES` selects which
tables get snapshots; empty means none and narrows the recovery claim.

## Token lifecycles and revocation

There are three independent token lifecycles:

| Token | Store | Revocation / refresh behavior |
|---|---|---|
| MCP client grant/access token | `workers-oauth-provider` storage (`OAUTH_KV`) | Revoked by deleting the MCP grant/client state; OIDC access-token props never contain the IdP refresh token. |
| OIDC IdP refresh token | OAuth-provider grant props, encrypted by the provider | Used only during MCP refresh-token exchange to re-check IdP groups and update `maxMode` / `actorPolicyName`; revoke at the IdP to stop renewal. |
| ServiceNow user token | `TokenStoreDO`, encrypted under `TOKEN_KEK_CURRENT` | Revoked by the IdP/ServiceNow OAuth client or by deleting the per `(user, instance)` token envelope. |

Group removal is bounded by the MCP access-token lifetime and refresh cadence: the Worker
re-evaluates OIDC claims when the MCP refresh token is exchanged, then writes new grant props and
strips IdP secrets from the next MCP access token. For high-risk `admin_script` use, keep MCP access
tokens short-lived and prefer the required-group approval branch so the current access token's OIDC
group set is checked again at the executor gate.

Production cutover rejects existing non-OIDC MCP grants because production `/mcp` requires grant
props with `authMode="oidc"` and a non-empty OIDC subject. Before switching a Worker to
`DEPLOYMENT_PROFILE=production`, purge pilot/operator-secret MCP grants and have clients
reauthorize through OIDC. A stale client token will fail closed with `invalid_auth_context`; it is
not migrated in place.
