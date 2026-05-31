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

1. **Tenant kill switch** — property `x_mcp.executor.run_server_script_enabled=false`
   returns 503 `run_server_script_disabled` (checked in the resource, audit-first).
2. **Mandatory `reason` + second approval** for `admin_script` (§3.5, §7.9 — implemented:
   `authz/approval.ts`, allowlist + token/access-group).
3. **Best-effort outbound-API denylist scan** (optional, documented as *not* a sandbox):
   a static scan of obvious outbound APIs in the submitted script before execution.
4. **Separate executor budget dimension** — executor calls are metered distinctly.
5. **Non-recoverable labeling** — `runServerScript` has **no general rollback guarantee**
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
`ADMIN_SCRIPT_APPROVAL_TOKENS` / `ADMIN_SCRIPT_REQUIRED_GROUP`. When **none** is set the gate
is **skipped** (single-operator default keeps working); when **any** is set it **enforces**
(an `admin_script` call without a valid token/group is denied with no executor POST). The
interactive dry-run→approve branch remains **documented-unsupported** (the stateless
`createMcpHandler` shape cannot elicit, §3.5).

## Status

The executor scoped app (`sn-executor-app/`) is **source-only / unverified** — it must be
installed on the instance and proven (S8/S9/S16, B1, B6) before any of the above are live.
Until then `runServerScript` is unreachable (no executor endpoint exists on `dev374488`).
Host-side: the mutating/executor path is now wired through the idempotency ledger, host
audit (AUDIT_KV, 30-day TTL), recovery snapshots (SNAPSHOT_KV, 30-day TTL, fail-closed), and
the second-approval gate (P4); `runServerScript` requires a tool-level `idempotencyKey`.
