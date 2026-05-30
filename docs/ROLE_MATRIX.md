# Role matrix (Phase 6 / plan §12)

Goal: **maximum reach with attribution** — reach stays high, but it travels via a named
identity with an inspectable role footprint, never a shared `admin` login. Which column
applies depends on the credential mode (§2.0, Decision 2).

| Identity / Role | Where | Grants | Why |
|---|---|---|---|
| `mcp_integration_user` (integration_user mode) | ServiceNow `sys_user` | `rest_api_explorer`, `itil`, `sn_customerservice_agent`, `import_transformer`, `snc_platform_rest_api_access`, + read ACLs on `sys_db_object`/`sys_dictionary`/`sys_glide_object` | Primary integration identity; high aggregate access via well-known roles, not literal admin. Revocable. |
| `x_mcp.executor` (scoped app) | ServiceNow scoped app | Required by the executor REST_Endpoint ACL. May create/close its OWN audit row; cannot read/alter other rows, change properties, or grant roles. | Decouples "run arbitrary script" from "hit Table API". Revoke this one role to kill executor reach. |
| `x_mcp.admin` (scoped app) | ServiceNow scoped app | Manages `x_mcp_audit_log`, kill-switch + egress properties, role assignments. **Not the integration user.** | Separation of duty: the executor identity cannot read/disable the audit trail. |
| Cloudflare deploy identity | Cloudflare account | wrangler / Alchemy IaC | Per-engineer scoped tokens; rotate. |
| MCP-client OAuth identity (per end user) | Cloudflare (OAuthProvider) | Maps end user → signed actor metadata (§2.0); in `per_user_oauth`, → that user's ServiceNow tokens | Per-user attribution propagates into `x_mcp_audit_log`. |

## Credential-mode branch (Decision 2, §2.0)

- **`integration_user` (single-operator default):** the broad role set applies to
  `mcp_integration_user`; host-side actor attribution is **mandatory + signed-and-verified**
  (§2.0). In **multi-user** deployments this mode additionally requires the **`ActorPolicy`**
  layer (§2.12, enforced before every RPC — implemented + live-verified, B5) because the
  broad identity otherwise lets any MCP user read anything.
- **`per_user_oauth` (multi-user default):** the matrix applies to the human users/groups;
  ServiceNow ACLs bound access natively and attribution is native.
- **Reversible elevation:** to write system tables in global scope, grant `admin` to
  `mcp_integration_user` **explicitly and document it** — visible and reversible, not implicit.

## Current build status

- The MCP-client OAuth layer and `mcp_integration_user`/scoped-app roles are **not yet
  provisioned** on the test instance (`dev374488`); the dev path uses Basic Auth (admin).
- `ActorPolicy` enforcement (instance/table/field/mode) is implemented and **live-verified**
  (B5, field masking) — so the host-side half of the integration_user bounding is real today.
- The `admin_script` approval gate (allowlist + second approval, §7.9) is implemented + tested.
