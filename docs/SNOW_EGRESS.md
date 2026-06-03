# ServiceNow-side egress (plan §5.7, §11 T19)

**`globalOutbound: null` is a Cloudflare-side control only.** It makes `fetch()`/`connect()`
throw inside the Dynamic Worker sandbox — it says **nothing** about what a server-side
script does **inside** ServiceNow. Treat `runServerScript` (the `x_mcp` executor) as an
**egress-capable primitive**: a script running there can

- call `RESTMessageV2` / outbound integrations,
- send email, fire events/notifications,
- move or exfiltrate data between records,

none of which the sandbox network block constrains.

## Controls (organizational + tenant-scoped — NOT a sandbox)

1. **Tenant kill switches** — properties `x_1793136_mcp.executor.enabled=false` and
   `x_1793136_mcp.executor.run_server_script_enabled=false` return 503 before execution
   (checked in the resource, audit-first). Fresh installs create both scoped toggles disabled;
   upgrades preserve any operator-set value.
2. **Mandatory `reason` + second approval** for `admin_script` (§3.5, §7.9 — implemented:
   `authz/approval.ts`, allowlist + token/access-group).
3. **Change-ticket/SIEM discipline** — every production `admin_script` run must carry a
   change-ticket-quality `reason`; host and ServiceNow audit rows should be forwarded to the
   production SIEM/append-only audit sink before enabling the toggles for broad use.
4. **Best-effort outbound-API denylist scan** (optional, documented as *not* a sandbox):
   a static scan of obvious outbound APIs in the submitted script before execution.
5. **Separate executor budget dimension** — executor calls are metered distinctly.
6. **Non-recoverable labeling** — `runServerScript` has **no general rollback guarantee**
   (§7.7); it is the highest-risk capability and is `admin_script`-only.

## admin_script privilege model (P4)

The host controls now wired around `runServerScript` (`sn/rpc.ts` → `sn/mutation-guard.ts`)
do **not** change *who* the script runs as. State it plainly:

- **Executor HMAC signing is ALWAYS host-signed when the executor is configured**
  (`X_MCP_EXECUTOR_HMAC_KEY` + `SNOW_EXECUTOR_PATH`), **orthogonal to the credential mode** —
  the host signs the actor payload regardless of `integration_user` / `per_user_oauth`.
- The script runs at the **executor app's** privilege, governed by HMAC + the executor's
  role ACL + the second-approval gate (`authz/approval.ts`) + host audit + the
  signed/audited `reason` — **not** bounded by the caller's per-user ServiceNow ACLs.
- The host controls (audit, idempotency ledger, recovery snapshots, budgets) wrap the
  **top-level `runServerScript` call + its response**, **NOT** the script's internal
  `GlideRecord` operations (Level 3 in `do/mutation-ledger.ts` — a documented limitation).

The **second-approval gate** is configured via `ADMIN_SCRIPT_ALLOWLIST` /
`ADMIN_SCRIPT_APPROVAL_TOKENS` / `ADMIN_SCRIPT_REQUIRED_GROUP`. Empty settings deny
`admin_script`; a request passes only when the actor is allowlisted and has either a valid
approval token or the required current access-group membership. The
interactive dry-run→approve branch remains **documented-unsupported** (the stateless
`createMcpHandler` shape cannot elicit, §3.5).

`DEPLOYMENT_PROFILE=pilot` is not an executor safety gate: it skips production posture checks,
including secret-entropy checks and `X_MCP_EXECUTOR_HMAC_KEY` length validation. Do not enable the
executor in a pilot profile unless the environment is isolated and the HMAC key has been generated
and reviewed out of band. Production executor use must pass the production posture preflight.

## Status

**Executor (`sn-executor-app/`) — hardened in source/build; live PDI proof is a release gate.**
The scoped Fluent app `x_1793136_mcp` + its global `x_mcp_verify` core are source/build verified
locally, but post-hardening live PDI verification still requires a coordinated host+executor
redeploy and `scripts/executor-scoped-verify.mjs`. Landed source hardenings:

- **Instance-claim enforcement** — `verify()` rejects a payload whose signed `actor.instance`
  does not name this instance (cross-instance replay → clean 401).
- **Null-safe MAC** — `_constantTimeEquals` treats a null/undefined MAC (from `_hmacBase64`/
  `generateMac`) as a clean `false`; the audit row closes to `rejected` (never stuck `running`).
- **Signed + audited `reason`** — `reason` is the LAST key of the executor `_canonical` (mirrors
  the host `auth/actor.ts` `CANONICAL_KEYS`), so the audited justification can't be forged
  independent of the HMAC; the wrapper persists the signed `reason` to a new audit column.
- **Byte-safe `result_sample`** — a GlideScript UTF-8 back-off slice (mirrors host `truncateUtf8`),
  replacing the code-unit slice against a byte cap.
- **Nonce replay race-close** — the live scoped Fluent wrapper consumes nonces via a bare
  INSERT into the **DB-unique-indexed scoped `x_1793136_mcp_nonce` table** (INSERT-as-arbiter: a
  duplicate insert = replay → reject), plus a 15-minute scheduled nonce-purge job whose
  `run_period` is checked by `scripts/executor-scoped-verify.mjs`.
- **Admin ACLs** — the audit table + properties are restricted to `x_1793136_mcp.admin`.
- **Executor defaults OFF** — fresh installs create the scoped `enabled` and
  `run_server_script_enabled` properties as `false`; the runtime defaults fail closed if either
  scoped property is absent. The legacy `x_mcp.executor.*` defaults remain neutral so an explicit
  pre-scoped disable still survives upgrade.
- **Deprecated global-REST endpoint REMOVED (M-4, 2026-05-31)** — the un-ACL'd HMAC-only
  global-REST install path has been deleted
  from `scripts/executor-install.mjs`; the installer now ships only the global `x_mcp_verify` core
  + properties. The canonical surface is the scoped, role-ACL-gated Fluent REST.

**Breaking payload change:** P7 added the signed `reason` key + the instance claim, so the host
and executor **must be redeployed together** before live approval; the earlier live executor
proofs (B1 HMAC match, S8/S9/T8/S16) predate this and are re-run by the P8 live gate. P8-live
gates: the `instance_name` property shape (fail-closed; an FQDN/empty value is a total 401
brick), the `GlideDigest` SHA-256 UTF-8 encoding (0.13a), the `x_1793136_mcp_nonce` unique-index
DB enforcement, and the scheduled nonce-purge `run_period`.

**Host-side: wired + locally tested (P4).** The mutating/executor path runs through the
idempotency ledger, host audit (AUDIT_KV, 30-day TTL, audit-before-effect fail-closed), recovery
snapshots (SNAPSHOT_KV, 30-day TTL, fail-closed), and the fail-closed second-approval gate — all on
every host `runServerScript` (`sn/rpc.ts` → `sn/mutation-guard.ts`); `runServerScript` requires a
tool-level `idempotencyKey`.
