# Installing the `x_mcp` executor

Two paths. The **REST install is proven end-to-end**; the **Studio scoped app** is the
production hardening (adds the role ACL + dedicated tables).

## A. Proven REST install (global scope) — `scripts/executor-install.mjs`

Run from the repo root with `.dev.vars` populated (instance host, admin creds, HMAC key):

```bash
node scripts/executor-install.mjs
```

Installs the properties, the `x_mcp_verify` Script Include, and the `x_mcp` Scripted REST
API (`/api/<namespace>/x_mcp/executor/run`), then **verifies 7/7 on the live instance**:

- **B1** valid signed actor → executes server-side script; **forged email → 401**, **bad sig → 401**
  (the host WebCrypto signer and ServiceNow `GlideCertificateEncryption.generateMac` agree —
  the cross-engine HMAC contract holds)
- **S16** cross-scope reach (GlideAggregate on global `incident`)
- **T8** nonce replay rejected
- **B6** over-cap output → `{ result:null, result_sample, truncated:true }`
- **S9** kill switch disabled → 503, re-enabled → 200 (audit-first)

This install uses `syslog` (audit) + `sys_user_preference` (nonce) because **custom tables
can't be created via the Table API** (DELTAS D10), and `requires_acl_authorization:false`,
so the **HMAC signature is the execution gate** (no valid sig → audited + 401).

After install, set the Worker bindings: `X_MCP_EXECUTOR_HMAC_KEY` (already a Cloudflare
secret) and `SNOW_EXECUTOR_PATH` (the printed `/api/<namespace>/x_mcp/executor/run`). The
deployed Worker's `admin_script` `run_code` → `runServerScript` then drives this executor
(proven by `npm run deploy:e2e`, the FULL CHAIN check).

## B. Production scoped app (Studio) — adds role ACL + real tables

The REST install proves the *mechanism*; production should ship a proper **scoped app** for
the role boundary and dedicated audit/nonce tables:

1. In a PDI, **Studio → Create Application** → scope `x_mcp`.
2. Create the artifacts from this folder:
   - Roles `x_mcp.executor`, `x_mcp.admin` (admin ≠ integration user).
   - Tables `x_mcp_audit_log` (+ columns per `update-set/x_mcp.xml`) and `x_mcp_nonce`
     (value unique index, created; scheduled TTL prune).
   - Script Include `x_mcp_verify` (`script-include/x_mcp_verify.js`, scoped: `new x_mcp.x_mcp_verify()`).
   - Scripted REST API `x_mcp`, resource `executor/run` (`scripted-rest/x_mcp.executor.run.js`),
     `requires_acl_authorization = true`.
   - **REST_Endpoint ACL** on the operation requiring `x_mcp.executor` (replaces the default
     `Scripted REST External Default` / `snc_internal`).
   - Audit-table ACLs → `x_mcp.admin` only (the executor role creates/closes only its own row).
   - Properties (`update-set/x_mcp.xml`); set `x_mcp.executor.hmac_secret` = the Cloudflare
     secret `X_MCP_EXECUTOR_HMAC_KEY`.
3. **Export the update set** over `update-set/x_mcp.xml`.
4. Assign `x_mcp.executor` to `mcp_integration_user`. **No `sys_trigger` fallback** (unsupported).

The scoped app adds the **role ACL** as a second gate (identity) on top of the HMAC signature
(cryptographic) and the dedicated audit table (vs `syslog`). Mechanism is identical — already
proven live.
