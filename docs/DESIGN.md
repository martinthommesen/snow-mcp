# DESIGN — ServiceNow Code Mode MCP Server

The durable design: what this builds, why it is shaped this way, and the decisions that are
settled. The per-control threat reasoning is in [`THREAT_MODEL.md`](THREAT_MODEL.md).

## What this builds

A Code Mode MCP server for ServiceNow, deployed as a stateless Cloudflare Worker
(`createMcpHandler`) that exposes exactly three MCP tools — `run_code`, `describe_table`,
`list_tables`. Instead of one tool per ServiceNow operation, the model authors **TypeScript**
against a typed `servicenow.*` surface; the host transpiles it (`esbuild-wasm`) and runs it in a
**per-call Worker Loader sandbox** with no network (`globalOutbound: null`) and no credentials. The
sandbox reaches ServiceNow only through a typed RPC binding (`ServiceNowRPC`) the host holds — the
OAuth/Basic header is injected host-side, never inside the sandbox. The two discovery tools feed the
model the live schema it needs to write that code.

## The safety thesis — "maximum access, achieved safely"

The connected identity is meant to reach **any table, any REST API, any record, and to run
arbitrary server-side code** in ServiceNow. Safety does **not** come from removing capabilities; it
comes from making that reach **recoverable, attributable, auditable, individually gateable, and
revocable**. The ceiling stays high while every use of it is named, logged, and reversible.

Concretely:

- **Credentials never enter the sandbox** — the Dynamic Worker sees only the typed `servicenow.*`
  RPC binding; the auth header is injected host-side. This is the single most important invariant.
- The arbitrary-script "executor" is a first-class capability but lives in a **dedicated scoped
  ServiceNow application** with a custom role, a REST_Endpoint ACL, audit-first logging (code hash +
  actor attribution, never the script body), and a system-property **kill switch**.
- Every mutating call carries **host-signed** actor metadata that the executor **verifies**.
- Destructive intent is **declared per call** via an enforced `mode` argument (read-only default).

## Architecture

### Request / data flow

```
MCP client ──Streamable HTTP (Origin-validated)──▶
OAuthProvider (workers-oauth-provider)            ← client↔Worker OAuth 2.1
  ├─ /authorize /token /register  → pilot operator-secret consent OR enterprise OIDC RP flow
  ├─ /oidc/callback               → IdP code exchange + ID-token validation + grant props
  └─ apiRoute /mcp → apiHandler → createMcpHandler(createServer()) [per request]
        ├─ getMcpAuthContext() → mcp_actor {userId, email}; instanceHost
        ├─ Tools: run_code, describe_table, list_tables
        ├─ Schema cache  → KV (user-aware, discoverability only)
        ├─ TokenStoreDO / BudgetDO / MutationLedgerDO / AuthCorrelationDO
        └─ ServiceNowRPC (RpcTarget; HOLDS the ServiceNow credential per the credential mode)
              │ run_code:  esbuild-wasm transform(TS→JS string)
              ▼            → executor.execute(jsString, fns)  [globalOutbound:null]
           Dynamic Worker (per call) — sees ONLY servicenow.* (no env/token/fetch)
              ▼ Workers RPC
           ServiceNowRPC → ServiceNow REST (OAuth header host-side)
                           └─ runServerScript → scoped executor (role-gated, signed+verified actor,
                                                audited, kill-switchable)
```

### Enforced per-call pipeline (the order is a security property)

```
size check
→ auth-context check (valid MCP token; audience/issuer/scope)
→ effective-mode resolution (min(requested, scope, tenant, instance))
→ ActorPolicy check (instance/table/mode/field/row)
→ typed RPC path guards
→ budget reserve (daily atomic, per-run init)
→ transpile (esbuild-wasm TS→JS string)
→ execute (sandbox; per-call actor signing for mutations/executor)
→ RPC-call + ServiceNow-request budget accounting (per-run)
→ audit / ledger finalize
```

Authorization happens **before** transpile/execute, and budget reserve happens **before** `load()`
— so an exhausted or unauthorized caller never creates a billable Worker.

### The three tools

- **`run_code`** — `{ code: TS, mode?: "read_only"|"write"|"admin_script", reason?, idempotencyKey? }`.
  Default `read_only`. The model writes TS against `servicenow.*`.
- **`describe_table`** — `{ table }`, read-only, user-aware KV cache.
- **`list_tables`** — `{ filter? }`, read-only, paginated.

There is **no generic `scriptedRest` tool**: the executor endpoint is reachable **only** via
`runServerScript()`, and only after the full pipeline above. Any future generic adapter must
reintroduce the path deny-policy (no executor/config/audit/OAuth paths) with tests.

### The `ServiceNowRPC` binding — the security boundary

`ServiceNowRPC` is a plain class — **not** a Cloudflare `RpcTarget`. codemode's `ToolDispatcher` is
itself the RpcTarget over Workers RPC, so the host just hands it `fns()` (see [`DELTAS.md`](DELTAS.md)
D8; extending `RpcTarget` here would be unnecessary coupling the code deliberately avoids). Its public
methods are the **only** ServiceNow capabilities reachable from the sandbox; no token appears in any
method signature or return. Every
method — **reads included** — first enforces `ActorPolicy` and the effective-mode capability gate,
then meters the per-run budget, then calls ServiceNow. Host outbound fetch uses `redirect:'manual'`
and the SSRF allowlist (`canonicalizeInstanceHost`) so the bearer never follows a 3xx to an
off-allowlist host. Mutating methods additionally take an idempotency key and route through the
mutation ledger.

### Capability / mode layer (enforced, not advisory)

```ts
export const DEFAULT_MODE = "read_only"; // flip for private demos (changes the floor, not the ceiling)
export const MODE_CAPABILITIES = {
  read_only:   ["readTables"],
  write:       ["readTables", "writeTables"],
  admin_script:["readTables", "writeTables", "runServerScript"],
} as const;
```

`effectiveMode = min(requested, OAuth-scope, tenant, instance)`; an **unknown mode resolves to
maximum risk (fail-closed)**. The requested `mode` can only **narrow**, never grant — so the
read-only default cannot be bypassed by asking for `admin_script`. `admin_script` is itself
**fail-closed**: empty `ADMIN_SCRIPT_*` settings deny it; it additionally requires an allowlisted
actor plus a Cloudflare Access-group membership or a tenant approval token, and a mandatory `reason`.

Mutations **hard-require a tool-level `idempotencyKey`** (fail-closed, no host-generated key) —
this is the exactly-once anchor. The ledger is leveled: L1 replays return the original result; L2
`indeterminate` blocks the retry; L3 is a documented limit (the host wraps the top-level call, not
the script's internal GlideRecord operations).

### The scoped executor + global core (why it is split)

`new Function` (eval) and `GlideCertificateEncryption` (HMAC) are **global-scope only** — not
permitted inside a scoped app. So the executor is a **scoped, role-ACL-gated REST wrapper** that
delegates the eval/HMAC primitives to a **global `x_mcp_verify` core** via a `verify()` / `execute()`
split. The global core is rendered by `scripts/executor-install.mjs` with the Worker HMAC key
material; it does not read executor-role-visible scoped properties at request time. Single-use
**nonce** consumption stays in the scoped wrapper: it `INSERT`s into a scoped nonce table
**between** `verify()` and `execute()`, and that table's **DB UNIQUE INDEX** on the nonce value is
the concurrency arbiter — a duplicate INSERT is a replay and is rejected. `execute()` re-verifies
the fresh HMAC-bound actor and refuses eval unless the wrapper-created audit row is still `running`
and the nonce row already exists, so a direct cross-scope caller cannot replay a fresh signed tuple
outside the audit/nonce wrapper.

The host **HMAC-signs a canonical actor payload** and the executor **verifies** it (freshness +
single-use nonce + instance claim, fail-closed). A claimed `body.actor` is forgeable by anyone
holding the executor role, so **sign-AND-verify** is what makes integration-mode attribution real.
The HMAC signing properties are scoped-app admin-only inventory; `x_1793136_mcp.executor`
authorizes REST endpoint invocation, not access to the Worker signing secret or `_prev` rotation key.
`reason` is the **last** canonical key, so the audited justification can't be forged independently of
the HMAC.

> **Cautionary tale (why the scoped role-ACL path is the only canonical surface).** A now-deleted
> *global* numeric REST endpoint had a dead verify-reject branch (`if (!verify(...))` is always false
> because `verify()` returns an object), so it executed every request with **no signature check and
  > no role ACL**. That global install path was removed, and production preflight now requires
  > `SNOW_EXECUTOR_PATH` to point at the two-segment scoped path
  > `/api/<scope>/x_mcp/executor/run`.

Role separation of duty and the credential-mode role footprint are in
[`ROLE_MATRIX.md`](ROLE_MATRIX.md); the ServiceNow-side egress controls in
[`SNOW_EGRESS.md`](SNOW_EGRESS.md).

## Confirmed technology decisions

Settled. If evidence contradicts one, stop and record it in [`DELTAS.md`](DELTAS.md) before deviating.

| Concern | Decision | Rationale |
|---|---|---|
| MCP server shape | Stateless `createMcpHandler` (`agents/mcp`) | Cloudflare's current recommended shape |
| MCP client auth | `@cloudflare/workers-oauth-provider` (OAuth 2.1); identity via `getMcpAuthContext()` | Distinct layer from ServiceNow OAuth; Worker issues its own client token |
| Enterprise identity | In-Worker OIDC authorization-code + PKCE (`AUTH_MODE=oidc`) | MCP OAuth grants are backed by IdP `sub` + group-derived ceilings/policies |
| ServiceNow credential mode | `integration_user` (pilot/single-operator) or `per_user_oauth` (enterprise/multi-user) | Production preflight requires `per_user_oauth`; pilot still supports `integration_user`+`ActorPolicy` |
| Actor attribution | Host HMAC-signs the actor payload; the scoped executor verifies it (freshness + nonce, fail-closed) | A claimed `body.actor` is forgeable; sign+verify makes integration-mode attribution real |
| Authorization (mode) | `effectiveMode = min(requested, OAuth-scope, tenant, instance)`; `admin_script` gated by allowlist + approval | A requested mode must only narrow, never grant |
| Per-actor policy | `ActorPolicy` enforced host-side before every RPC (instances / tables / fields / rows / bytes / mode) | In `integration_user` mode, audit ≠ access control; reads need a real boundary |
| MCP-client OAuth storage | dedicated `OAUTH_KV` binding (fail-closed if missing) | ServiceNow tokens never live in OAuth props |
| Sandbox | Worker Loader (`env.LOADER`), one-shot `load()` per call, `globalOutbound: null` | Isolation at the runtime level; cost handled by budgets |
| TS in sandbox | `esbuild-wasm` `transform` → JS string, passed to `execute(code, fns)` | The executor takes a string, not a module map; esbuild strips types, it does not type-check |
| Transport | Streamable HTTP; SSE deprecated; **Origin validation required** | MCP 2025-11-25 transport spec |
| IaC / deploy | Alchemy (`alchemy.run.ts`), `WorkerLoader` binding | One config for local + deploy |
| Schema cache | Workers KV, ~24h TTL, **user-aware** keys; discoverability only; never cache records | ACL visibility is user-dependent |
| Token store | dedicated `TokenStoreDO`, AES-GCM versioned envelope with AAD, per `(user, instance)` | Isolation + rotation |
| Budgets | dedicated `BudgetDO`, atomic reserve-before-load; **multi-dimensional** (unique Workers + RPC + SN requests + rows/bytes), per-run + daily | Dynamic Workers bill workers, requests, and CPU |
| Server-side executor | scoped app: custom role, REST_Endpoint ACL, audit table, kill switch; synchronous; **no `allow_unsafe`** | Attributable, gateable, revocable arbitrary-code reach |

## Credential mode

```ts
type ServiceNowCredentialMode = "integration_user" | "per_user_oauth";
```

- **`integration_user` (explicit pilot/single-operator mode).** The Worker authenticates as one broad service
  identity. This delivers maximum access, but ServiceNow-side audit then shows the service identity,
  not the human — so every mutating/executor call **must** record host-signed actor metadata, and
  **`ActorPolicy` gates every read**, because a broad identity otherwise lets any MCP user read
  anything (audit does not prevent disclosure). Field masks are checked on query **predicates**, not
  just on requested fields/response rows, so a masked column cannot be inferred via a row-selection
  or aggregate oracle. Per-actor `maxMode` is re-checked **at the `runServerScript` sink**, not
  inherited.
- **`per_user_oauth` (multi-user default).** ServiceNow ACLs bound access natively and attribution is
  native (ServiceNow sees the real user). "Maximum access" then depends on each human's roles.

## MCP Client Identity

```ts
type AuthMode = "operator_secret" | "oidc";
```

- **`operator_secret` (pilot/dev only).** `/authorize` renders the local consent form and requires
  `MCP_OPERATOR_SECRET` plus `MCP_OPERATOR_USER_ID`. `DEPLOYMENT_PROFILE=production` rejects this
  mode and any configured `MCP_OPERATOR_SECRET`.
- **`oidc` (enterprise).** `/authorize` redirects to the configured IdP with PKCE, `state`, and
  `nonce`; `/oidc/callback` consumes the stored state once, validates the signed ID token, and
  completes the MCP OAuth grant with a `userId` derived from `sub` (`oidc-<sub>`). `props.maxMode`
  is `min(granted MCP scopes, OIDC group policy maxMode)` (each access token is further narrowed to
  its requested scopes), and `props.actorPolicyName` selects a
  named host-side `ActorPolicy` loaded from `ACTOR_POLICIES_JSON`.

OIDC `email` is treated as a ServiceNow-linking hint only when the signed ID token also carries
`email_verified=true`. Users whose IdP does not emit verified email can still get MCP grants keyed
by OIDC `sub`, but first-time ServiceNow account binding needs an admin-seeded expected sys_id/token
or an IdP-side verified-email configuration.

OIDC grants persist the IdP refresh token in OAuth-provider grant props, but strip it from MCP
access-token props. On MCP refresh-token exchange the Worker refreshes the IdP token and
re-evaluates group-derived `maxMode` and `actorPolicyName`, so group removal downgrades both the
capability ceiling and the table/row/field policy at the next MCP refresh. Re-evaluation is bound
to the access-token lifetime (the OAuth provider's default TTL, ~1h): a removed group keeps its
prior `maxMode` until the access token expires and the client refreshes, so revocation is
eventually-consistent within that window, not instantaneous. Removal from ALL mapped groups
DOWNGRADES to `read_only`/`default` (not a hard deny); a hard deny requires the IdP to deprovision
the user so the refresh itself fails. Equal-risk group mappings must agree on the named
`ActorPolicy`; conflicting policies at the same risk are rejected instead of depending on
JSON/object iteration order.

## ServiceNow OAuth

Inbound OAuth 2.0, Auth Code + PKCE for human/remote; ROPC for a disposable PDI dev / CI service
identity (MFA-exempt; leave unset in production). The confidential client (Auth Code + PKCE +
secret) is what makes refresh tokens available.

> **B9 — this OAuth client type does not rotate the refresh token on refresh** (the same refresh
> token is reused). Token-store rotation logic must **not** assume rotation.

## Sandbox Globals

The sandbox runs with `globalOutbound: null`. Platform globals such as `fetch` may still exist in
the JavaScript environment, but outbound network calls are blocked by the Worker Loader runtime and
fail immediately. Treat the supported sandbox API as the typed `servicenow.*` surface only.

## Testing model — why two harnesses

`npm test` (vitest) runs inside **workerd** via `@cloudflare/vitest-pool-workers`, because the Code
Mode path depends on Worker Loader and `esbuild-wasm`, which only behave correctly there. But
workerd's **outbound `fetch` is blocked** in the dev environment, so **live** ServiceNow calls run in
**Node** (`scripts/live-rpc-verify.mjs`) against the **same compiled modules**. The combined
sandbox → host → live ServiceNow path therefore can only be exercised against a **real deployment** —
it is not a code limitation, it is the one seam the local environment blocks. See
[`FORK.md`](FORK.md) for which checks are offline vs. live-only.

## Per-API prerequisites & PDI notes

The roles/plugins and gotchas each `ServiceNowRPC` method depends on:

| API | Path | Roles / plugins | Gotchas |
|---|---|---|---|
| Table API | `/api/now/table/{table}` | Read/write ACLs; `snc_platform_rest_api_access` under strict REST security | `sysparm_limit` default is **10000** (host cap **1000**); limit applies **before** ACL → pages can be empty after filtering; `display_value` triples response size |
| Aggregate API | `/api/now/stats/{table}` | Read access | Server-side `sysparm_count` / `group_by` / `avg_fields` |
| Attachment API | `/api/now/attachment` | Read ACL on the parent; 1024 MB cap | Stream; never buffer base64 in Worker memory |
| Import Set API | `/api/now/import/{staging}` | `import_transformer` or write ACL | Staging extends `sys_import_set_row`; user fields are `u_*` unless scoped |
| CMDB Instance API | `/api/now/cmdb/instance/{class}/{sys_id}` | `itil` typical; one record per call | Relationships are separate calls |
| Knowledge Mgmt | `/api/sn_km_api/knowledge/articles` | KB user-criteria + read ACL on `kb_knowledge` | Honors KB ACLs strictly |
| Service Catalog | `/api/sn_sc/servicecatalog/*` | Catalog roles for variables | `add_to_cart → checkout → submit_order`, or `order_now` |
| Scripted REST | `/api/{scope}/{api}/{resource}` | Whatever the resource's REST_Endpoint ACL requires | Default ACL is `snc_internal` — override it; `GlideRecord` bypasses ACLs server-side |

**PDI notes (dev/demo only).** Personal Developer Instances hibernate after ~6h of inactivity and
are reclaimed after 10 days of Developer-Portal inactivity (creating records does **not** reset the
timer). Never point staging or pre-prod at a PDI; ship **no** keepalive (against Developer Program
policy) — a `/health` probe is the supported pattern; and the GA evidence base must be a
**sub-production instance, not a PDI**.

## Where the rest lives

- [`THREAT_MODEL.md`](THREAT_MODEL.md) — the full T1–T20 threat/mitigation table and per-control rationale.
- [`ROLE_MATRIX.md`](ROLE_MATRIX.md) — the role footprint and separation of duty, per credential mode.
- [`SNOW_EGRESS.md`](SNOW_EGRESS.md) — why `runServerScript` is a ServiceNow-side egress channel.
- [`RECOVERY.md`](RECOVERY.md) — the KEK ring, the migration-not-rename rule, and per-operation recovery posture.
- [`RETENTION.md`](RETENTION.md) — the recovery snapshot store as a second sensitive database.
- [`ADR/0001-codemode-integration.md`](ADR/0001-codemode-integration.md) — the Code Mode execution contract.
- [`DELTAS.md`](DELTAS.md) — where the installed reality differs from this design.
- [`FORK.md`](FORK.md) — clone, re-scope, and deploy your own instance.
- [`archive/`](archive) — phase-by-phase build history and dated reviews.
