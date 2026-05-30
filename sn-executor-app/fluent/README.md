# `x_1793136_mcp` — production executor (ServiceNow SDK + Fluent)

The production scoped app, defined as **code** with the ServiceNow SDK (now-sdk 4.7.1) and
**Fluent** (TypeScript metadata) and deployed via `now-sdk install` — **no XML update set**.
Installed + verified live on `dev374488` (4/4, `scripts/executor-scoped-verify.mjs`):
S8 role-ACL enforced, B1 valid executes, forged→401, audit-first row written.

## What it defines (`src/fluent/x_mcp.now.ts`)

- **Roles** `x_1793136_mcp.executor` (REST endpoint gate) + `x_1793136_mcp.admin` (audit/SoD).
- **Tables** `x_1793136_mcp_audit_log` (attribution + hashes, no script body) + `x_1793136_mcp_nonce`.
- **REST_Endpoint ACL** requiring `x_1793136_mcp.executor` (S8), enforced by the API (`enforceAcl`).
- **Scripted REST API** `x_mcp`, resource `executor/run` (`src/server/x_mcp_executor.js`).
- **Properties** `x_mcp.executor.*` (kill switch, egress toggle, byte caps).

## Architecture: scoped wrapper + global core (plan §0.13a)

`new Function` (eval) and `GlideCertificateEncryption` (HMAC) are **global-only** — not
permitted in scoped apps. So the scoped `executor/run` does what scope allows — audit-first,
kill switch, byte cap, the role-gated endpoint — and **delegates verify + execute** to the
GLOBAL `x_mcp_verify.run()` (installed by `scripts/executor-install.mjs`). The global core
does the HMAC verification (cross-engine-equal to the host signer, B1) and the `new Function`
execution.

## Build / deploy

```bash
cd sn-executor-app/fluent
npm install
npx now-sdk auth --add https://<instance> --type basic --alias dev   # or --type oauth
npx now-sdk build
npx now-sdk install -a dev
# then: node ../../scripts/executor-install.mjs   # global core (x_mcp_verify) + properties
#       node ../../scripts/executor-scoped-verify.mjs   # verify 4/4
```

Set property `x_mcp.executor.hmac_secret` = the Cloudflare secret `X_MCP_EXECUTOR_HMAC_KEY`,
and the Worker's `SNOW_EXECUTOR_PATH` = `/api/x_1793136_mcp/x_mcp/executor/run`. Assign
`x_1793136_mcp.executor` to `mcp_integration_user`.
