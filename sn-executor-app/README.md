# `x_mcp` — ServiceNow scoped-app executor (source)

This directory holds the **source** for the `x_mcp` scoped application: the arbitrary
server-side-script executor that `run_code`'s `admin_script` mode reaches via
`runServerScript()`. It is the reference implementation from `DEVELOPMENT_PLAN.md` §10.

## ⚠️ Status: UNVERIFIED — requires a live PDI

These files are **source artifacts**, not a proven, installed app. The real
verification (does the in-scope HMAC verify reject forged actors? does plain
`GlideRecord` achieve cross-scope reach? does the kill switch return 503 + audit?) can
**only** be done on a live ServiceNow instance — Phase 1.8 spike / Phase 5; gates
S8/S9/S16, B1, B6. Until then, treat everything here as a draft to install and prove.
The canonical update-set XML (`update-set/x_mcp.xml`) must be **exported from a PDI
after building**, since valid `sys_update_xml` cannot be authored offline. See
`docs/OPEN_QUESTIONS.md`.

## Deliberate code execution is the feature — the boundary is governance

The executor resource runs LLM/host-supplied script via
`new Function('gs','GlideRecord',…, code)`. A generic security scanner flags this as
code injection. **Here it is the intended capability**, not a bug: the entire point is
"maximum reach — any table, any record, arbitrary server-side code." Removing execution
would remove the tool.

Safety does **not** come from blocking execution. It comes from making every use
**attributable, auditable, gateable, and revocable** (plan Overview, §10):

| Control | Where | Effect |
|---|---|---|
| `x_mcp.executor` role + **REST_Endpoint ACL** | `acl/`, `roles/` | Only that role can hit the endpoint; revoke it to kill executor reach without touching other capabilities |
| **Signed-actor verification** (`x_mcp_verify`) | `script-include/` | Rejects forged / missing / stale / replayed actor signatures, fail-closed (B1) |
| **Audit-first** row (no script body, no raw output) | `scripted-rest/` | Every call attributed to MCP actor + SN effective user + `actor_verified` |
| **Kill switch** + **egress toggle** properties | `properties/` | `enabled=false` → 503; `run_server_script_enabled=false` → blocks SN-side egress (§11) |
| **UTF-8 byte caps**, **safe serialize** | `scripted-rest/` | Bounded input; never `JSON.parse` a truncated result (B6) |
| Audit-table ACLs → `x_mcp.admin` only | `acl/` | The executor identity cannot read/alter other audit rows or flip the switch (separation of duty) |

`globalOutbound:null` sandboxes only the **Cloudflare** side; a server-side script can
still reach ServiceNow outbound APIs/email/events — hence the egress toggle, mandatory
`reason` + approval for `admin_script`, and the non-recoverable labeling (`SNOW_EGRESS.md`).

## Contract: the verifier must match the host signer byte-for-byte

`script-include/x_mcp_verify.js` rebuilds the canonical payload in the **exact** key
order used by `packages/mcp-server/src/auth/actor.ts` (`CANONICAL_KEYS`):
`mcp_actor_user_id, mcp_actor_email, snow_effective_user_sys_id, instance, request_id,
script_sha256, issued_at, nonce` → `JSON.stringify` → `base64(HMAC-SHA256(key, …))`.
If either side reorders keys or changes encoding, **all** signatures fail. The host
signer is unit-tested (`test/actor-and-policy.test.ts`); the in-scope verify is the
open Phase 0.13a proof.

## Install runbook (on a PDI)

1. Create scoped app `x_mcp`; roles `x_mcp.executor`, `x_mcp.admin` (admin ≠ integration user).
2. Create Scripted REST API `executor` with resource `run` (POST) using
   `scripted-rest/x_mcp.executor.run.js`.
3. Add a **REST_Endpoint ACL** on the resource requiring `x_mcp.executor` (replace the
   default `Scripted REST External Default`).
4. Create the `x_mcp_audit_log` and `x_mcp_nonce` tables; set audit-table ACLs to
   `x_mcp.admin` read/manage (the executor role may only create/close its own row).
5. Add Script Include `x_mcp_verify` (`script-include/x_mcp_verify.js`).
6. Create properties: `enabled`, `run_server_script_enabled`, `max_bytes`,
   `max_output_bytes`, `timeout_ms`, `hmac_secret`, `hmac_secret_prev`.
7. Set `hmac_secret` to the **same** value as the Worker secret `X_MCP_EXECUTOR_HMAC_KEY`.
8. Schedule a job to prune `x_mcp_nonce` entries older than the freshness window.
9. Export the app as an update set into `update-set/x_mcp.xml`.
10. Assign `x_mcp.executor` to `mcp_integration_user`. **No `sys_trigger` fallback** (unsupported).

## Layout

```
sn-executor-app/
├─ scripted-rest/x_mcp.executor.run.js   # §10 corrected resource script (audit-first, verify, byte cap, safe serialize)
├─ script-include/x_mcp_verify.js        # HMAC verify (current+prev key) + freshness + nonce replay
├─ update-set/x_mcp.xml                   # EXPORT FROM PDI — not authorable offline
└─ README.md                             # this file
```
