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

## Status

The executor scoped app (`sn-executor-app/`) is **source-only / unverified** — it must be
installed on the instance and proven (S8/S9/S16, B1, B6) before any of the above are live.
Until then `runServerScript` is unreachable (no executor endpoint exists on `dev374488`).
