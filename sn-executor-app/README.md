# ServiceNow Executor App

The production executor is the Fluent scoped app in `sn-executor-app/fluent`.
It installs as scope `x_1793136_mcp` and exposes the role-ACL-gated endpoint:

```text
/api/x_1793136_mcp/x_mcp/executor/run
```

The global `script-include/x_mcp_verify.js` helper is installed by `scripts/executor-install.mjs`.
Legacy scripted-REST and update-set artifacts have been removed; the Fluent app is the only
supported executor install path.

## Production Controls

| Control | Current production location |
|---|---|
| REST endpoint role gate | `x_1793136_mcp.executor` REST_Endpoint ACL |
| Audit and nonce tables | `x_1793136_mcp_audit_log`, `x_1793136_mcp_nonce` |
| Admin separation of duty | `x_1793136_mcp.admin` |
| Kill switch and byte caps | `x_1793136_mcp.executor.*` properties |
| HMAC/eval primitives | Global `x_mcp_verify` helper called by the scoped wrapper |

Use [INSTALL.md](INSTALL.md) or [fluent/README.md](fluent/README.md) for the live install path.
