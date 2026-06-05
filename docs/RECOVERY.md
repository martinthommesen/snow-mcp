# Recovery model (plan §7.7)

"Recoverable" needs more than hashes. Per operation:

| Operation | Recovery posture |
|---|---|
| `tableUpdate` | Store encrypted before/after field snapshots for **configured** tables (`recovery/snapshots.ts`, `SNAPSHOT_KEK_CURRENT`), or rely on `sys_audit` where sufficient. |
| `tableDelete` | **Disallowed by default** (`admin_script` only); soft-delete where possible, or store an encrypted preimage with a retention window. |
| `runServerScript` | **No general rollback guarantee** — labeled high-risk `admin_script`, non-recoverable (see SNOW_EGRESS.md). |
| `importSet` / catalog | Idempotency (MutationLedgerDO, §7.3) + created-record references for cleanup. |

If raw snapshots are too sensitive for a tenant, **say so and narrow the recovery claim**
for that tenant rather than implying full reversibility. Snapshot store policy →
`RETENTION.md`.

## KEK rotation runbook (P3)

Token (and, in P4, snapshot) envelopes are sealed under a **versioned KEK ring** built by
`buildKekRing(currentSecret, prevSecret?)` (`auth/crypto.ts`). Each key's version label is
**content-addressed** — `kek-${hex(sha256(keyBytes)).slice(0,8)}` — so distinct keys are
overwhelmingly unlikely to share a label (32-bit address), eliminating the constant-`"current"`
same-label collision that defeated rotation before P3. A label collision is harmless anyway:
GCM authentication, not the label, decides decryption (a wrong key can never produce a valid
`open()`).

**Secrets**

| Secret | Role |
|---|---|
| `TOKEN_KEK_CURRENT` | the key new envelopes are sealed under |
| `TOKEN_KEK_PREV` | optional; accepted during a rotation window |

(`SNAPSHOT_KEK_CURRENT`/`SNAPSHOT_KEK_PREV` follow the identical scheme; P4 wires the snapshot
store via the same `buildKekRing` helper.)

**First deploy.** Set `TOKEN_KEK_CURRENT` and `SNAPSHOT_KEK_CURRENT` to fresh
CSPRNG-generated 32-byte values. Do not set the `*_PREV` values until you are actively rotating.

**Rotating later.**
1. Move the in-use passphrase to `TOKEN_KEK_PREV` (`TOKEN_KEK_PREV` = old `TOKEN_KEK_CURRENT`).
2. Set `TOKEN_KEK_CURRENT` to the new passphrase.
3. Deploy. New seals use the new key; existing envelopes decrypt via `previous` (or the
   matching stamped key). Once all live tokens have re-minted/refreshed under the new key, drop
   `TOKEN_KEK_PREV` on a subsequent deploy. Envelopes stamped with unknown KEK versions fail closed.

**Fail-closed re-mint.** If a stored token can no longer be decrypted (e.g. a botched
rotation that drops the key without a window), `getServiceNowBearer` recovers per credential
mode instead of propagating the decrypt error: `integration_user` re-mints via ROPC;
`per_user_oauth` raises `reauth_required` (never ROPC) so the user re-authenticates.

## Status

- Leveled idempotency (L1 replay / L2 indeterminate-blocks-retry / L3 documented limit) is
  **implemented + tested** (`do/mutation-ledger.ts`, S17).
- Pre-wrapper completed mutation-ledger rows from pilot/dev builds are intentionally not replayed
  after the replay-safe wrapper cutover. They fail closed as `internal_error` until retention expiry;
  do not reuse old idempotency keys across the deploy. If an operator must preserve a specific
  pilot retry, migrate that row into the replay-safe wrapper shape before cutting over.
- Encrypted snapshots (`recovery/snapshots.ts`) reuse the AES-GCM envelope (`auth/crypto.ts`,
  unit-verified) with a dedicated `SNAPSHOT_KEK_CURRENT`. **Wired into the live `tableUpdate` path
  (P4):** for a `reversible_from_snapshot`-class update (a table in `SNAPSHOT_ENABLED_TABLES`)
  the host fetches the real before-state, seals a before/after snapshot under the versioned
  `SNAPSHOT_KEK_CURRENT` ring, and persists it to `SNAPSHOT_KV` (30-day `expirationTtl`) **before**
  issuing the PATCH. If the snapshot cannot be persisted the update **fails closed** (no
  recovery row => no mutate). The mutating path is also wrapped by the idempotency ledger,
  host audit (audit-before-effect, fail-closed), and the second-approval gate
  (`sn/mutation-guard.ts`).

## Incident controls

| Control | Procedure |
|---|---|
| `MUTATION_FREEZE=true` | Set the Worker binding and redeploy to deny new `tableUpdate` and `runServerScript` calls before ledger claims or ServiceNow effects. Read-only tools remain available. Clear only after audit, ledger, and ServiceNow state are reconciled. |
| Executor kill switch | Set `x_1793136_mcp.executor.enabled=false` and/or `x_1793136_mcp.executor.run_server_script_enabled=false` in ServiceNow. The Fluent app also re-arms both disabled on every deploy. |
| Account loss | Revoke the affected IdP user/session, delete that user's ServiceNow token envelope from `TokenStoreDO`, and rotate ServiceNow/OIDC credentials if token misuse is suspected. Production posture rejects shared `MCP_OPERATOR_SECRET`. |
| HMAC secret exposure | Rotate `X_MCP_EXECUTOR_HMAC_KEY`, set optional `X_MCP_EXECUTOR_HMAC_KEY_PREV` for the bounded overlap window, and rerun `scripts/executor-install.mjs` so the global verifier helper and admin-only HMAC properties move together. Clear `_prev` by removing it from `.dev.vars` or by rerunning with `X_MCP_EXECUTOR_HMAC_KEY_PREV=` in the environment. Executor-role principals must never read either property. |
| DO blast radius | `TokenStoreDO` is partitioned by `userId|instanceHost`; `MutationLedgerDO` by `userId|instanceHost|runKey:ordinal`; `BudgetDO` is one daily tenant-wide cap with per-user visibility counters; `McpAdmissionDO` is one object per authenticated user. |

## Ledger-safe recovery

1. Freeze mutations with `MUTATION_FREEZE=true` before manual repair if any side effect may be
   duplicated or partially applied.
2. Inspect `AUDIT_KV` / SIEM for the requestId, ordinal, op, status, and `errorClass`.
3. Treat `status="intent"` or `errorClass` ending in `:indeterminate` as unknown outcome. Do not
   replay the same logical effect until ServiceNow state has been inspected and either manually
   reconciled or explicitly abandoned.
4. If a table update has a snapshot, decrypt with the snapshot KEK ring and apply the previous
   reversible fields through a new, justified mutation with a new idempotency key.
5. Leave old ledger rows in place until retention expiry unless an operator has source-backed proof
   that deleting a row cannot double-apply an effect.

## Drills before GA

- Rollback: deploy the previous known-good Worker and confirm `/health/ready` posture plus read-only
  MCP calls.
- Key rotation: rotate `TOKEN_KEK_CURRENT`, `SNAPSHOT_KEK_CURRENT`, and executor HMAC with previous
  keys configured only during the overlap window.
- Kill switch: disable executor toggles, prove signed execution fails, restore, and prove execution
  succeeds.
- SIEM receipt: run one denied and one successful mutation and record the Logpush/SIEM event ids for
  `event="mcp_audit_record"`.
- Secret escrow: verify current recovery holders can retrieve Cloudflare, IdP, ServiceNow OAuth,
  KEK, and executor HMAC secrets without exposing them in logs or tickets.
