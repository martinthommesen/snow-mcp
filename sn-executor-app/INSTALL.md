# Installing the production executor

The canonical production executor is the Fluent scoped app in `sn-executor-app/fluent`.
Legacy `x_mcp` update-set and scripted-REST artifacts have been removed; do not recreate them
for production.

## Canonical Path

```bash
cd sn-executor-app/fluent
npm install
npx now-sdk auth --add https://<instance> --type basic --alias dev
npx now-sdk build
npx now-sdk install -a dev
cd ../..
node scripts/executor-install.mjs
node scripts/executor-scoped-verify.mjs
```

After install:

- Set ServiceNow property `x_1793136_mcp.executor.hmac_secret` to the Cloudflare
  `X_MCP_EXECUTOR_HMAC_KEY` value.
- Set Worker binding `SNOW_EXECUTOR_PATH` to `/api/x_1793136_mcp/x_mcp/executor/run`.
- Assign `x_1793136_mcp.executor` to the integration user.

## What Gets Installed

- Roles: `x_1793136_mcp.executor`, `x_1793136_mcp.admin`.
- Tables: `x_1793136_mcp_audit_log`, `x_1793136_mcp_nonce`.
- REST endpoint: `/api/x_1793136_mcp/x_mcp/executor/run`.
- Properties: `x_1793136_mcp.executor.*`.
- Global helper: `x_mcp_verify` for ServiceNow-only HMAC/eval primitives.

The scoped endpoint is role-ACL-gated and HMAC-gated. `scripts/executor-scoped-verify.mjs`
checks the live endpoint and restores the admin role assignment to its starting state.
