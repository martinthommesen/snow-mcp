# ServiceNow Code Mode MCP Server — Development Plan (v4, authorization-hardened)

**Audience:** Claude Code (autonomous agent) building the project end to end.
**As of:** May 30, 2026. Re-verify versions and beta statuses at Phase 0 (Task 0.1).

> **This document is the single source of truth, and it is self-contained.** Everything needed to build the project is here: overview and rationale (Overview), settled decisions (§1), verified APIs and facts (§2), architecture (§3), the phased build with a definition of done per unit of work (§6), the GA gate (§7), the threat model (§11), the role matrix (§12), per-API prerequisites (§13), and the corrected executor reference implementation (§10). No external report is required to build from this plan. **If an installed package's API no longer matches what is documented here, trust the installed package and official docs, and record the delta in `docs/DELTAS.md`.**

**Revision note (v4 — "authorization-hardened").** This pass resolves a fourth review that approved Phase 0 but blocked Phase 1/4/5 implementation. The core finding: several properties were *claimed* ("signed", "enforced", "recoverable") but the implementation did not yet make them true. The material changes: (1) the executor now **verifies** the host-signed actor payload (HMAC + freshness + nonce replay, fail-closed) instead of trusting `body.actor` — without this, any `x_mcp.executor` caller could forge attribution (§2.0, §10, B1); (2) **`mode` is bounded by authorization, not requested freely** — `effectiveMode = min(requested, OAuth-scope, tenant, instance)`, and `admin_script` needs a tenant allowlist plus second approval (§2.0.1, §3.5, B3/B4); (3) **`integration_user` is a read-confidentiality risk in multi-user deployments** — an `ActorPolicy` layer now gates every RPC (instances/tables/fields/rows/bytes/mode), and `per_user_oauth` is the default unless ActorPolicy is implemented (§2.12, B5); (4) the executor **serializes safely** — it never `JSON.parse`es a truncated string and catches `JSON.stringify` failures (§10, B6); (5) a **concrete ACL-filtered pagination strategy** replaces the deferred one (§2.13, S5/B7); (6) generic `scriptedRest` is **explicitly denylisted** from the executor and sensitive paths so it cannot bypass `runServerScript()` (§3.2, B2); (7) budgets are **multi-dimensional** (unique Workers + RPC calls + ServiceNow requests + rows/bytes, per-run and daily) since Dynamic Workers also bill requests and CPU (§2.5); (8) ServiceNow OAuth is configured as a **confidential client** and refresh-token behavior is a proof gate (§2.8, B9); (9) **`OAUTH_KV` is a first-class binding** from day one (§2.4, §2.11, B8); (10) the TS-pipeline proof is **split** into no-import and allowed-import (bundle vs `modules`) and the type-check consequence is made actionable (§Phase 0.8a/0.8b). Also added: a ServiceNow-side **egress** threat for `runServerScript`, explicit **snapshot retention/encryption** policy, audit-table **role hardening**, and a **bypass-test** group (B1–B9). New hard-stop proofs are in Phase 0.13; full mapping in the changelog (§15).

**Revision note (v3 — "execution-safe").** This pass resolves the blockers from the third review. The material changes: (1) an explicit **ServiceNow credential mode** (`integration_user` vs `per_user_oauth`) replaces the previous ambiguity, with host-signed **actor attribution** required in integration mode; (2) `run_code` now **defaults to read-only**, with an **enforceable** (not advisory) mode→capability map — this reverses v2's permissive default (see §0.9, and confirm or override); (3) the TypeScript pipeline is corrected — with `DynamicWorkerExecutor` the right tool is an **esbuild-wasm transform to a JS string**, not `@cloudflare/worker-bundler`'s module map (§2.2, §3.4); (4) Durable Object storage is **split** into purpose-specific objects so global budgets and token isolation are actually enforceable (§2.10); (5) budget enforcement is an **atomic reserve-before-load** transaction (§2.5, Phase 4); (6) the executor's denied-attempt audit expectation is **corrected** (ACL-denied calls cannot write the app audit table) (§Phase 1.8, S8); (7) `allow_unsafe` is **removed** from v1 unless proven on the target family; (8) **idempotency is leveled** (host-mediated vs `runServerScript` vs internal) and a **recovery model** for destructive ops is added (§7.3, §7.7); (9) MCP **Origin validation** and a full **OAuth-negative** test suite are added; (10) compatibility date and local port are **unified**. Full mapping in the changelog (§14).

---

## Overview — what this builds and why

**What.** A Code Mode MCP server for ServiceNow, deployed as a stateless Cloudflare Worker (`createMcpHandler`) that exposes exactly three MCP tools — `run_code`, `describe_table`, `list_tables`. The LLM authors **TypeScript** against a typed `codemode.servicenow.*` surface; the host transpiles it (esbuild-wasm) and runs it in a **per-call Worker Loader sandbox** with no network (`globalOutbound: null`) and no credentials. The sandbox reaches ServiceNow only through a typed RPC binding (`ServiceNowRPC`) that the host holds — the OAuth header is injected host-side, never inside the sandbox. Two discovery tools (`describe_table`, `list_tables`) feed the model the schema it needs to write code.

**Why this design (the safety thesis — the spine of the whole plan).** The connected identity is meant to reach **any table, any REST API, any record, and to run arbitrary server-side code** in ServiceNow. Safety does **not** come from removing capabilities; it comes from making that reach **recoverable, attributable, auditable, individually gateable, and revocable**. Concretely: credentials never enter the sandbox (only a typed RPC binding does); the arbitrary-script "executor" is a first-class capability but lives in a dedicated **scoped application (`x_mcp`)** with a custom role, a REST_Endpoint ACL, per-request audit logging (code hash + actor attribution, no script body), and a system-property **kill switch**; every mutating call carries host-signed actor metadata; destructive intent is declared per call via an enforced `mode` argument. "Maximum access, achieved safely" means the ceiling stays high while every use of it is named, logged, and reversible.

**Why this project exists (differentiator vs. ServiceNow MCP Server Console).** ServiceNow's own MCP Server Console (v1.4: Knowledge Graph, Subflows, Scripted REST, AI Agents) exposes Scripted REST for GET/POST/PUT only and **deliberately excludes the Table API**; it does not run arbitrary developer-supplied code. This project differentiates on five axes: (1) **Code Mode native** — one `run_code` plus two discovery helpers, ~1k tokens of tool surface, versus one tool per Skill/Subflow/endpoint; (2) **dynamic code execution against a typed RPC** — the model writes TypeScript that we transpile, sandbox, and run; (3) **full Table / Aggregate / Attachment / Import-Set / CMDB access** that Server Console omits; (4) **open-source, self-hosted, version-pinnable**, with no Now Assist licensing dependency; (5) **Cloudflare-edge deployment** with a different latency/geo/quota profile. Where Server Console wins (governed Now Assist Skills, ACL-aware Knowledge Graph traversal, native AI Agent exposure) the two are complementary, not exclusive.

**Key facts that commonly trip people up** (each is load-bearing and detailed later):

- **Dynamic Workers daily billing is ACTIVE** as of 2026-05-26 (§2.5). Cloudflare also bills Dynamic Worker **requests and CPU**, so budgets are **multi-dimensional** (unique Workers + RPC calls + ServiceNow requests + rows/bytes, per-run and daily), not just unique-Worker counts.
- **`run_code` defaults to `read_only`, and the requested `mode` can only narrow.** Effective mode = `min(requested, OAuth-scope, tenant-policy, instance-policy)`; `admin_script` additionally needs a tenant allowlist and a second approval. The map is **enforced**, not advisory (§0.9 Decision 1, §2.0.1, §3.5).
- **ServiceNow identity is an explicit credential mode** (`integration_user` or `per_user_oauth`, §2.0). In `integration_user` mode every mutating/executor call carries a **host-signed actor payload that the executor verifies** (HMAC + freshness + nonce, fail-closed) — and an **`ActorPolicy`** layer (§2.12) gates every read, because audit alone does not prevent a broad identity from over-reading. For multi-user deployments `per_user_oauth` is the default unless ActorPolicy is implemented.
- **Schema cache keys are user-aware**, not merely role-aware — ACL-filtered field visibility is per user (§2.6).
- **The scoped-app executor is synchronous**, writes an audit row first (audit-first), then **verifies the signed actor**, checks the kill switch, enforces a UTF-8 **byte** cap, **serializes safely** (never parses a truncated result), and ships **no `allow_unsafe`** knob (§10, Phase 5).
- **`runServerScript` is a ServiceNow-side egress channel.** `globalOutbound: null` only sandboxes the Cloudflare side; a server-side script can still call ServiceNow outbound APIs, so it carries its own tenant toggle, approval, and egress controls (§11, §13), and is labeled non-recoverable.
- **The TypeScript path is `esbuild-wasm` transform → JS string → `DynamicWorkerExecutor.execute(...)`** (worker-bundler is a fallback only); esbuild **strips types, it does not type-check** — broken-type handling is decided in ADR-0001 (§2.2, §Phase 0.8).
- **The MCP-client OAuth provider requires an `OAUTH_KV` binding** (separate from ServiceNow token storage; ServiceNow tokens never live in OAuth token props) (§2.4, §2.11).
- **Table API `sysparm_limit` defaults to 10000** (we impose a host-side safety cap of 1000), and the limit is applied **before ACL evaluation** — so pages can be empty after filtering; the cursor strategy accounts for this (§2.13).
- **Local MCP dev port is 8787** everywhere.

**Where to find the rest.** Threat model: §11. Role matrix: §12. Per-API prerequisites and PDI notes: §13. Corrected executor reference implementation: §10. Confirmed decisions: §1. Verified APIs/facts: §2. Architecture: §3. Phased build: §6. GA gate: §7.

---

## 0. How to use this plan (read first)

The **Overview** establishes **what** and **why**; the rest of this plan establishes **how**, file by file, phase by phase, with a definition of done (DoD) for each unit of work.

**Operating rules for the building agent:**

1. **Work phase by phase, in order.** Do not start a phase until the previous phase's DoD is green. Phases end at committable, testable states.
2. **Verify before you build.** Several dependencies are pre-1.0/beta and change on a 4–8 week cadence. Phase 0 re-confirms every version and API. **If a documented API here no longer matches the installed package, trust the installed package and official docs, and record the delta in `docs/DELTAS.md`.**
3. **Pin exact versions for every runtime-critical package.** Commit the lockfile; `npm ci` in CI (§5).
4. **The sandbox must never receive credentials.** The single most important invariant. The Dynamic Worker sees only the typed `codemode.*` RPC surface — never `env`, never a token, never a `Fetcher` to ServiceNow.
5. **Maximum access, achieved safely.** The system is meant to *reach* any table, any REST API, any record, and run arbitrary server-side code. "Safe" = recoverable, attributable, auditable, individually gateable, revocable — **not** a lowered ceiling. The mechanism that reconciles this with a read-only default is in §0.9: defaulting to read-only does not lower the ceiling, it makes destructive intent explicit per call.
6. **Cost is a live constraint.** Dynamic Workers bill per unique Worker created per day as of May 26, 2026 (§2.5). Atomic budget enforcement is a Phase 4 acceptance gate.
7. **Tests encode the security invariants.** A feature is not done until its test is green. S1, S2, S2-auth, S8, S9, S11–S18 and the bypass group **B1–B9** are gates (§6 Phase 9). The **Phase 0.13 hard-stop proofs** gate Phase 1/4/5.
8. **Commit discipline; never commit secrets.** `.dev.vars`, `.env`, `*.local` git-ignored from Phase 0.
9. **When blocked**, prefer official Cloudflare docs → package npm README → ServiceNow product docs → cited community sources. Record unknowns in `docs/OPEN_QUESTIONS.md`; do not guess in code.

### 0.9 Two posture decisions

The **mechanisms** below are built regardless. Two **defaults** are policy choices.

**Decision 1 — `run_code` default mode (v3 recommendation: read-only; reversal of v2).** The mode→capability layer (§3.5) is now **enforced**, not advisory. The default is **`read_only`**: a model-generated snippet can read unless the client explicitly passes `mode:"write"` or `mode:"admin_script"`. This **reverses v2's permissive default.** The reasoning that resolves the apparent tension with "maximum access": read-only-default does **not** lower the access ceiling — the integration identity *can* still do everything — it only requires the agent to *declare* destructive intent per call (a one-token `mode` argument). Two independent reviews recommended this, and the reframe shows it costs nothing the project wanted. **The flip back to permissive is a single constant (`DEFAULT_MODE`/`CAPABILITY_DEFAULT` in `config.ts`) for private/internal demos.** If you prefer permissive-by-default, change that constant and the Phase 4 acceptance; everything else is unaffected. **Confirm this choice or override it.** **The default is not a security boundary by itself** — a requested `mode` is capped by authorization (OAuth scope ∩ tenant ∩ instance policy, §2.0.1) so an agent cannot reach `write`/`admin_script` just by asking; the default only sets the floor when nothing higher is *both requested and permitted*.

**Decision 2 — ServiceNow credential mode (v4 default depends on audience).** See §2.0. `integration_user` delivers "maximum access" via a broad service identity and is the right default for a **single trusted operator** (e.g., a private engineering agent). But for any **multi-user / shared** deployment it creates a read-confidentiality problem: every authenticated MCP user would read *through* the broad identity, and audit does not prevent disclosure. So for shared deployments the default is **`per_user_oauth`**, OR `integration_user` **with the `ActorPolicy` layer (§2.12) implemented and enforced before every RPC** — pick one before Phase 1. `per_user_oauth` is the stronger-attribution / ACL-bounded alternative either way. This choice affects authorization, audit semantics, customer risk, and onboarding — decide it explicitly per deployment.

**Two runtime targets.** Remote on Cloudflare Workers (Streamable HTTP) and local under `wrangler dev --port 8787` (Miniflare emulates the Worker Loader binding). No separate Node build of the server; a thin Node/stdio shim is an optional convenience (Phase 8).

---

## 1. Confirmed technology decisions

Settled. If evidence contradicts one, stop and record it in `docs/DELTAS.md` before deviating.

| Concern | Decision | Rationale |
|---|---|---|
| MCP server shape | Stateless `createMcpHandler` (`agents/mcp`); stateful `Agent` + `WorkerTransport` only when needed | Cloudflare's current recommended shape |
| MCP client auth | `@cloudflare/workers-oauth-provider` (OAuth 2.1); identity via `getMcpAuthContext()` | Distinct layer from ServiceNow OAuth; Worker issues its own client token |
| ServiceNow credential mode | `integration_user` (single-operator) or `per_user_oauth` (multi-user default) (§2.0) | Explicit; multi-user needs `per_user_oauth` **or** `integration_user`+`ActorPolicy` (§2.0, §2.12) |
| Actor attribution | Host **HMAC-signs** the actor payload; the `x_mcp` executor **verifies** it (freshness + nonce, fail-closed) | A claimed `body.actor` is forgeable; sign+verify makes integration-mode attribution real (§2.0, §10) |
| Authorization (mode) | `effectiveMode = min(requested, OAuth-scope, tenant, instance)`; `admin_script` gated by allowlist + approval | A requested mode must only narrow, never grant (§2.0.1, §3.5) |
| Per-actor policy | `ActorPolicy` enforced host-side before every RPC (instances / tables / fields / rows / bytes / mode) | In `integration_user` mode, audit ≠ access control; reads need a real boundary (§2.12) |
| MCP-client OAuth storage | `@cloudflare/workers-oauth-provider` with a dedicated **`OAUTH_KV`** binding | Provider requires it; ServiceNow tokens never live in OAuth props (§2.4, §2.11) |
| Sandbox | Worker Loader (`env.LOADER`), one-shot `load()` per call (via the executor), `globalOutbound: null` | Isolation at the runtime level; cost handled by budgets (§2.5) |
| Code Mode SDK | `@cloudflare/codemode` — `DynamicWorkerExecutor` + type-gen; thin MCP wrapper we own | Official RPC dispatch/normalization/log/timeout |
| TS in sandbox | **esbuild-wasm `transform` → JS string**, passed to `execute(code: string, fns)`; worker-bundler only if 0.8 forces hand-rolled `load()` (§2.2) | The executor takes a string, not a module map |
| Transport | Streamable HTTP (remote), stdio (optional local); SSE deprecated; **Origin validation required** | MCP 2025-11-25 transport spec |
| MCP spec target | `2025-11-25` family | Current stable revision |
| IaC / deploy | Alchemy (`alchemy.run.ts`), `WorkerLoader` binding | One config for local + deploy |
| Schema cache | Workers KV, ~24h TTL, **user-aware** keys; discoverability only; never cache records | ACL visibility is user-dependent (§2.6) |
| Token store | **Dedicated `TokenStoreDO`**, AES-GCM versioned envelope with AAD, per `(user, instance)` | Isolation + rotation (§2.7, §2.10) |
| Budgets | **Dedicated `BudgetDO`**, atomic reserve-before-load; **multi-dimensional** (unique Workers + RPC calls + SN requests + rows/bytes), per-run + daily | Dynamic Workers bill workers, requests, and CPU; per-run caps bound one cheap Worker (§2.5, §2.10) |
| Auth (ServiceNow) | Inbound OAuth 2.0, Auth Code + PKCE (human/remote); ROPC for disposable PDI dev / CI service identity (MFA-exempt) | PKCE is the safe hosted flow |
| Server-side executor | Scoped app `x_mcp`: custom role, REST_Endpoint ACL, audit table, kill switch; **synchronous**; **no `allow_unsafe` in v1** | Attributable, gateable, revocable arbitrary-code reach |
| Mutation safety | Enforced mode→capability map; **leveled** idempotency; recovery model | Attribution + replay-safety + honest recoverability |
| Target instance | PDI for dev/demo; **sub-production instance for the GA gate** | PDIs are disposable, not a GA evidence base |

---

## 2. Confirmed APIs and facts (verified against primary sources)

### 2.0 ServiceNow credential mode (resolves the identity-model ambiguity)

```ts
type ServiceNowCredentialMode = "integration_user" | "per_user_oauth";
```

**`integration_user` (default).** The Worker authenticates to ServiceNow as one broad service identity (`mcp_integration_user`). This delivers maximum access. **Because ServiceNow-side audit then shows the service identity, not the human, every mutating and executor call MUST record host-signed actor metadata:**

```json
{ "mcp_actor_user_id": "...", "mcp_actor_email": "...",
  "snow_effective_user_sys_id": "...", "snow_effective_user_name": "...",
  "instance": "...", "request_id": "..." }
```

The actor metadata is derived from the MCP-client OAuth identity (`getMcpAuthContext().props`). **"Signed" is meaningless unless the executor verifies it** — a claimed `body.actor` is otherwise forgeable by anyone holding `x_mcp.executor`, which would defeat the entire attribution model. So the Worker HMAC-signs a canonical payload and the executor **verifies** it before trusting any actor field:

```
canonical = JSON(stableKeys({
  mcp_actor_user_id, mcp_actor_email, snow_effective_user_sys_id,
  instance, request_id, script_sha256, issued_at /* epoch ms */, nonce
}))
actor_sig = base64( HMAC-SHA256(key = X_MCP_EXECUTOR_HMAC_KEY, canonical) )
```

Verification (executor side, §10) is **fail-closed** and rejects on any of: bad/missing signature; `script_sha256` ≠ SHA-256 of the received script; `issued_at` outside a freshness window (default ±120s); or a **replayed `nonce`** (seen within the window). **Key rotation:** the Worker signs with the current key; the executor verifies against current **then** previous (`x_mcp.executor.hmac_secret` / `…_prev`). The HMAC key is a Cloudflare secret (`X_MCP_EXECUTOR_HMAC_KEY`) mirrored to a protected ServiceNow property; **the exact in-scope verification mechanism is proven in Phase 0.13a** (candidates: a global verification Script Include exposed to the scope, `GlideCertificateEncryption.generateMac`, or ServiceNow's `com.glide.tokenbased_auth` HMAC inbound auth). The audit table (§Phase 5) records the ServiceNow effective user, the MCP actor, **and** `actor_verified`.

**`per_user_oauth`.** Each human authenticates to ServiceNow with Authorization Code + PKCE; their ServiceNow tokens are stored per user in `TokenStoreDO`. ACLs are the human's ACLs and **maximum access is not guaranteed** unless each human holds broad roles. Attribution is native (ServiceNow sees the real user).

**Read-confidentiality in `integration_user` mode (multi-user).** Audit records *who asked* but does not stop a broad identity from *over-reading*. In any multi-user deployment, `integration_user` therefore requires the **`ActorPolicy`** layer (§2.12) enforced host-side before every RPC — or use `per_user_oauth`. A single trusted operator may run `integration_user` with a permissive ActorPolicy.

The MCP-client OAuth layer (§2.4) is present in **both** modes; the modes differ only in which ServiceNow credential the Worker uses after the client is authenticated.

### 2.0.1 Authorization: requested `mode` is capped, never granting

The model/client passes `mode` in the `run_code` input, but **a requested mode only narrows**; it can never grant capability. The host resolves the effective mode before execution:

```ts
// risk order: read_only < write < admin_script
effectiveMode = minByRisk(
  requestedMode ?? DEFAULT_MODE,   // what the snippet asked for
  authContext.props.maxMode,       // from the MCP OAuth scope granted to this client
  tenantPolicy.maxMode,            // per-tenant ceiling
  instancePolicy.maxMode,          // per-instance ceiling
);
if (riskOf(requestedMode) > riskOf(effectiveMode)) throw capability_denied("mode_not_permitted");
```

The MCP-client token carries explicit scopes — `servicenow:read`, `servicenow:write`, `servicenow:admin_script` — and `authContext.props.maxMode` is the highest mode those scopes allow. **`admin_script`** additionally requires a **tenant-level allowlist** and a **second approval** (§3.5: elicitation, Access-group membership, or a tenant approval token). This is what makes "read-only default" real: an agent cannot reach `write`/`admin_script` by simply asking for it in the tool input. Proven in Phase 0.13b (B3/B4).

### 2.1 Worker Loader binding (`env.LOADER`)

```jsonc
{ "worker_loaders": [ { "binding": "LOADER" } ] }
```

`load(code: WorkerCode)` → `WorkerStub`: one-off, never cached. `get(id, () => Promise<WorkerCode>)`: warm by id, callback only on miss. **In v1 we do not call `load()`/`get()` directly — the executor does (§2.2).** Worker Loader supports **JavaScript/Python only**; TS must be compiled first.

### 2.2 Code Mode SDK + the corrected TypeScript pipeline

`@cloudflare/codemode` exports `DynamicWorkerExecutor`, `ToolDispatcher`, `generateTypesFromJsonSchema`, `normalizeCode`, `sanitizeToolName`; `@cloudflare/codemode/ai` adds `generateTypes` (and `createCodeTool`, which we do not use — §3.4).

The executor interface is **`execute(code: string, fns: Record<string, Function>): Promise<ExecuteResult>`**. The `code` is a single JS source string (an async arrow the SDK normalizes); the executor builds the sandbox Worker internally and wires `codemode.*` to `fns` over Workers RPC. `DynamicWorkerExecutor` options: `loader` (required), `timeout` (default 30000ms), `globalOutbound` (`Fetcher|null`, default `null`), `modules` (`Record<string,string>` extra ES modules importable in the sandbox).

**Pipeline correction (this is a real v2 fix).** Because `execute()` takes a **string**, the TypeScript step is a **transform** (strip types, lower async/await) producing one JS string — runnable in the host Worker via **`esbuild-wasm`'s `transform`**. `@cloudflare/worker-bundler`'s `createWorker()` returns a **module map** (`mainModule`+`modules`) shaped for `env.LOADER.load()`, which is the **hand-rolled** path §3.4 rejects. So:

- **Primary path (with the executor):** `esbuild-wasm.transform(userTs, { loader: "ts", format: "esm" })` → JS string → `executor.execute(jsString, fns)`. If the snippet needs npm imports (e.g. `zod`), either bundle to a single string with esbuild's stdin→stdout bundling, or inject allowed modules via the executor's `modules` option.
- **Fallback (only if Phase 0.8 shows `execute()` cannot accept our transformed string and we must hand-roll `env.LOADER.load()`):** use `@cloudflare/worker-bundler` to produce the module map and call `load()` directly, re-implementing dispatch — explicitly the less-preferred path.

**Phase 0.8 decides empirically and records the exact shape in ADR-0001.** Both `esbuild-wasm` and `@cloudflare/worker-bundler` run inside workerd (not plain Node), so tests use `@cloudflare/vitest-pool-workers`.

### 2.3 `createMcpHandler` (from `agents/mcp`) + the CVE guard

Per-request server construction is mandatory (SDK ≥ 1.26.0 guard against cross-client response leakage):

```ts
function createServer() {
  const server = new McpServer({ name: "servicenow-codemode", version: "0.1.0" });
  // register run_code, describe_table, list_tables here
  return server;
}
// inside the apiHandler.fetch: const server = createServer(); return createMcpHandler(server)(req, env, ctx);
```

`createMcpHandler(server, options?)` returns `(req, env, ctx) => Promise<Response>`; `route` defaults to `/mcp`. With auth, it is wrapped by `OAuthProvider` via `apiRoute`/`apiHandler` (§2.4).

### 2.4 MCP client authentication (`@cloudflare/workers-oauth-provider`)

Two OAuth layers (confirmed by Cloudflare docs): client→Worker (this section) and Worker→ServiceNow (§2.8). With a third-party upstream, the Worker issues **its own** token to the MCP client.

```ts
import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
export default new OAuthProvider({
  apiRoute: "/mcp",
  apiHandler: { fetch: (req, env, ctx) => createMcpHandler(createServer())(req, env, ctx) },
  defaultHandler: ServiceNowAuthHandler,         // consent + upstream ServiceNow PKCE
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/token",
  clientRegistrationEndpoint: "/register",
});
```

Inside a stateless tool: `const auth = getMcpAuthContext(); const userId = auth?.props?.userId as string;` (backed by `AsyncLocalStorage`). The token-store key derives from `auth.props`, never assumed.

**Storage binding — `OAUTH_KV` is required from day one.** `@cloudflare/workers-oauth-provider` persists clients, grants, and its own access/refresh tokens in a Workers KV namespace **bound as `OAUTH_KV`**; it also encrypts `props` and rotates its refresh tokens. This binding is declared in `alchemy.run.ts`, `wrangler.jsonc`, and `.dev.vars.example` from the start (not discovered later) — see §2.11. **ServiceNow tokens never live in OAuth `props` or `OAUTH_KV`**; they live encrypted in `TokenStoreDO` (§2.7). Keeping the two stores separate is part of the threat model (§11). Phase 0.10 proves the round-trip and Phase 0.13d proves the isolation; a missing `OAUTH_KV` must fail deployment/tests (B8).

**Scopes.** The Worker issues client tokens carrying explicit scopes `servicenow:read` / `servicenow:write` / `servicenow:admin_script`, surfaced as `auth.props.maxMode` and used by the authorization cap in §2.0.1.

### 2.5 Dynamic Workers pricing — ACTIVE (May 26, 2026) + atomic budgeting

Workers-Paid-only; **1,000 unique Dynamic Workers/month included; +$0.002 per Dynamic Worker per day** beyond. Billing began **May 26, 2026** (the March open-beta waiver ended). A Dynamic Worker is unique by **Worker ID + code**; the count **resets daily**; same ID+code invoked many times = 1. **`load()` with no stable ID counts as one billable creation attempt per invocation.**

**Atomic reserve-before-load** is therefore the required cost-control shape (Phase 4): compute budget identity → **atomically reserve/increment** user + instance + global counters in `BudgetDO` → if any would exceed, reject with typed `budget_exceeded` **before** `load()` → if `load()` later fails, keep the conservative count (or record a failed reservation); never risk undercounting cost. The cost lever for hot/identical snippets is `get(id, cb)` (Phase 10.2), a deliberate, isolation-trading optimization — not a default.

**Unique-Worker count is necessary but not sufficient.** Cloudflare also bills Dynamic Worker **requests** (including each `fetch()`/RPC event) and **CPU** (startup + execution). A single "cheap" Worker can still make a large number of ServiceNow calls through the typed RPC boundary, so the budget is **multi-dimensional** and enforced at two scopes:

```
# daily (BudgetDO, atomic)               # per-run (ServiceNowRPC, in-process)
dailyUniqueWorkers                       perRunRpcCallLimit
dailySandboxRpcCalls                     perRunServiceNowRequestLimit
dailyServiceNowRequests                  perRunAttachmentBytes
dailyRowsReturned                        perRunWallClockMs
dailyBytesReturned
```

Per-run counters live in the request-scoped `ServiceNowRPC` and trip `budget_exceeded` mid-snippet; daily counters live in `BudgetDO` (atomic, global cap from the single date-keyed object, §2.10). Both are configured in `config.ts` and asserted by S11/S14.

### 2.6 Schema cache — user-aware, discoverability-only

```
schema:v1:{instanceHost}:{userSysId}:{roleHash}:{domainId?}:{scope?}:{table}
```

ACL evaluation can depend on roles, conditions, and scripts; REST responses omit fields the caller cannot access — so a role-only key is unsafe. **The schema cache is only a discoverability cache; record operations still rely on ServiceNow ACL enforcement and response filtering.** Narrow to role-only later only with proof recorded in `DELTAS.md`. Negative cache test required (S6).

### 2.7 Token envelope — versioned, AAD-bound

Per `(user_id, instance_host, token_type)` row in `TokenStoreDO`:

```json
{ "version": 1, "kekVersion": "2026-05", "alg": "AES-256-GCM",
  "iv": "...", "aad": "user_id|instance_host|token_type", "ciphertext": "...", "tag": "..." }
```

Encrypt before store (WebCrypto AES-GCM, DEK from `env.TOKEN_KEK`); **fail closed on AAD mismatch**; rotate refresh tokens on every refresh; decrypt under current **and** previous KEK during a rotation window; revoking one instance's token must not affect another instance for the same user (S7).

### 2.8 ServiceNow OAuth

Inbound OAuth 2.0 via Application Registry; authorize `oauth_auth.do`, token `oauth_token.do`, revoke `oauth_revoke_token.do`. Authorization Code + PKCE (`S256`, KB1645540) for human/remote. MFA applies to U2M OAuth, **not** to ROPC — so the CI service identity uses ROPC/client-credentials; humans use PKCE.

**Confidential client + refresh-token proof (Phase 0.13e / Phase 1).** The Worker is server-side, so the ServiceNow OAuth app is registered as a **confidential client** (Authorization Code + PKCE **+ client secret**) when refresh tokens are required — ServiceNow's refresh-token behavior is tied to client type, and a public-client assumption can silently yield no usable refresh token. Do not assume; **prove** before building token lifecycle: does the chosen app type **return** a `refresh_token`? Is it **rotated** on refresh? Does `oauth_revoke_token.do` **invalidate** the expected credential? What happens under **MFA** and **session timeout**? This is gate **B9**, distinct from the general token-lifecycle tests (S7), which assume the refresh token exists and behaves as configured.

### 2.9 Compatibility date — unified

**Use one compatibility date everywhere** (every `wrangler` config, `alchemy.run.ts`, the sandbox compat date, and `SANDBOX_COMPAT_DATE`). Default **`2026-05-13`** (present in current Cloudflare examples). Phase 0 may bump to the latest released date but **must apply it uniformly** and record the chosen date in `DELTAS.md`. Do not use mixed dates across files.

### 2.10 Durable Object storage — split by responsibility

A single generic session DO cannot enforce a global daily budget or cleanly isolate multi-user tokens. Split into four objects with explicit keys and data ownership:

| Durable Object | Key | Owns |
|---|---|---|
| `AuthCorrelationDO` | `oauth_state` (or transient session) | PKCE verifier, state, nonce, upstream ServiceNow OAuth correlation; short-lived |
| `TokenStoreDO` | `userId\|instanceHost` (or `credentialId`) | Encrypted ServiceNow tokens (§2.7); per-user/instance isolation |
| `BudgetDO` | `yyyy-mm-dd` (global) and `yyyy-mm-dd\|userId`, `yyyy-mm-dd\|instanceHost` | Atomic daily **multi-dimensional** counters (unique Workers + RPC + SN requests + rows/bytes, §2.5); **global cap enforced from the single global-keyed object** |
| `MutationLedgerDO` | `userId\|instanceHost\|idempotencyKey` | Per-mutation idempotency + leveled `runServerScript` state (§7.3) |

The global budget counter lives in a **single** object keyed only by date so all runs coordinate through it (or a documented sharded scheme with strict global aggregation). Phase 0.12 proves the partitioning.

Two Workers KV namespaces sit alongside these DOs: **`SCHEMA_KV`** (user-aware schema cache, §2.6) and **`OAUTH_KV`** (OAuth-provider clients/grants/tokens, §2.4). Both are **separate from `TokenStoreDO`** so ServiceNow credentials never share a store with OAuth-provider state (§11). The actor-replay **nonce** store is ServiceNow-side (`x_mcp_nonce`, §10), not a DO.

### 2.11 Alchemy bindings (verify factory in Phase 0)

```ts
import { Worker, KVNamespace, DurableObjectNamespace, WorkerLoader } from "alchemy/cloudflare";
// KV:       SCHEMA_KV (schema cache, §2.6), OAUTH_KV (provider storage, §2.4 — REQUIRED)
// bindings: LOADER: WorkerLoader(), AUTH_DO, TOKEN_DO, BUDGET_DO, LEDGER_DO,
//           SNOW_* secrets, OAUTH_PROVIDER_SECRET, TOKEN_KEK, X_MCP_EXECUTOR_HMAC_KEY (actor signing, §2.0)
// compatibilityDate: "2026-05-13", compatibilityFlags: ["nodejs_compat"]
```

Verify the `WorkerLoader` factory name/signature in the installed Alchemy version (landed v0.71.0, PR #1067; emits `"worker_loaders":[{"binding":"LOADER"}]`). Fallback: declare the binding via Alchemy's raw wrangler passthrough. **`OAUTH_KV` and `X_MCP_EXECUTOR_HMAC_KEY` are declared from the start** — `OAUTH_KV` because the provider requires it (§2.4), the HMAC key because the executor cannot verify actor signatures without it (§2.0). A missing `OAUTH_KV` must fail deploy/tests (B8).

### 2.12 `ActorPolicy` — per-actor authorization before every RPC

In `integration_user` mode the ServiceNow identity is broad, so **ServiceNow ACLs do not bound a given MCP user** — the Worker must. `ActorPolicy` is resolved from `authContext.props` (and tenant config) and enforced **host-side in `ServiceNowRPC` before every method**, on reads as well as writes:

```ts
interface ActorPolicy {
  allowedInstances: string[];                 // host allowlist for this actor
  tables:   { allow?: RegExp[]; deny?: RegExp[] };
  fieldMasks: Record<string, string[]>;       // table -> denylisted/forbidden fields
  maxMode: "read_only" | "write" | "admin_script";
  maxRowsPerRun: number; maxBytesPerRun: number;
  rowFilters?: Record<string, string>;        // table -> mandatory encoded-query AND-ed in
  domainConstraints?: string[];               // optional domain-separation scoping
}
```

Enforcement order in every RPC: resolve policy → check instance/table/mode allowed → AND-in mandatory `rowFilters` → strip masked fields from request and response → meter against `maxRows/maxBytes`. **For multi-user deployments this layer is mandatory** (or use `per_user_oauth`, where ServiceNow ACLs do the bounding natively); for a single trusted operator a permissive default is acceptable. A denied read returns typed `actor_policy_denied`. Proven by Phase 0.13c (B5).

### 2.13 Table API limits & ACL-filtered pagination (decide here, not in Phase 3)

ServiceNow's documented `sysparm_limit` **default is 10000** (not 1000); we impose a **host-side safety cap of 1000** and call it that. More importantly, **`sysparm_limit` is applied *before* ACL evaluation**, so a page can come back empty after ACL filtering even when visible rows exist further on — which can stall a naive keyset cursor that depends on a returned `sys_id`. The strategy is fixed per credential mode:

- **`integration_user` (default):** keyset on `sys_id` using the broad identity (ACL filtering is minimal for this identity), then apply `ActorPolicy` (§2.12) **host-side after fetch**. The cursor always advances on real `sys_id`s; per-actor filtering happens above the cursor. This is the primary supported path.
- **`per_user_oauth`:** ACL filtering can blank a page. Use a **bounded `sysparm_offset` fallback** (capped page count) when a keyset page returns empty-but-not-end — with the documented duplicate/skip caveats — **or** route reads through a scoped, ACL-honoring `GlideRecordSecure` read helper on the `x_mcp` app that advances the cursor internally.
- **Neither available:** declare ACL-filtered pagination **best-effort** and surface `partial: true` rather than implying completeness.

S5 exercises the empty-page-after-ACL case explicitly (B7); the choice is recorded in `DELTAS.md`.

---

## 3. Architecture

### 3.1 Request/data flow

```
MCP client ──Streamable HTTP (Origin-validated) / stdio──▶
OAuthProvider (workers-oauth-provider)            ← client↔Worker OAuth 2.1
  ├─ /authorize /token /register  → consent (CSRF/state/nonce) + upstream ServiceNow PKCE
  └─ apiRoute /mcp → apiHandler → createMcpHandler(createServer()) [per request]
        ├─ getMcpAuthContext() → mcp_actor {userId, email}; instanceHost
        ├─ Tools: run_code, describe_table, list_tables
        ├─ Schema cache  → KV (user-aware, discoverability only)
        ├─ TokenStoreDO / BudgetDO / MutationLedgerDO / AuthCorrelationDO
        └─ ServiceNowRPC (RpcTarget; HOLDS the ServiceNow credential per §2.0 mode)
              │ run_code:  esbuild-wasm transform(TS→JS string)
              ▼            → executor.execute(jsString, fns)  [globalOutbound:null]
           Dynamic Worker (per call) — sees ONLY codemode.servicenow.* (no env/token/fetch)
              ▼ Workers RPC
           ServiceNowRPC → ServiceNow REST (OAuth header host-side)
                           └─ runServerScript → x_mcp executor (role-gated, signed+verified actor, audited, kill-switchable)
```

**Enforced per-call pipeline (the order is a security property, asserted in Phase 4/5):**

```
size check
→ auth-context check (valid MCP token; audience/issuer/scope)
→ effective-mode resolution (§2.0.1: min(requested, scope, tenant, instance))
→ ActorPolicy check (§2.12: instance/table/mode/field/row)
→ scriptedRest path-denylist check (§3.2)
→ budget reserve (§2.5: daily atomic, per-run init)
→ transpile/bundle (§2.2)
→ execute (sandbox; per-call actor signing for mutations/executor)
→ RPC-call budget accounting (per-run)
→ ServiceNow-request budget accounting (per-run)
→ audit / ledger finalize
```

Authorization happens **before** transpile/execute, and budget reserve happens **before** `load()` (so an exhausted or unauthorized caller never creates a billable Worker).

### 3.2 The three tools + scriptedRest path policy

- **`run_code`** — `{ code: string (TS), mode?: "read_only"|"write"|"admin_script", reason?, idempotencyKey? }`. Default `read_only`. The model writes TS against `codemode.servicenow.*`.
- **`describe_table`** — `{ table }`, read-only, user-aware KV cache.
- **`list_tables`** — `{ filter? }`, read-only, paginated.

`scriptedRest` (inside `ServiceNowRPC`) is a generic ServiceNow REST caller and must **not** become a bypass around `runServerScript()`'s mode gate, ledger, actor signing, and executor audit. Its **path policy** rejects absolute URLs, userinfo, and path traversal; permits only `/api/...`; and applies an explicit **denylist** that no generic call may reach:

```
/api/x_mcp/executor/*        # the executor — reachable ONLY via runServerScript()
/api/*/executor/*            # any other executor-shaped resource
/api/now/table/sys_properties    # kill switch / config tampering
/api/now/table/x_mcp_audit_log   # audit tampering
/oauth_*.do                  # token endpoints
/login.do                    # login/UI
```

**Only `runServerScript()` may call the executor endpoint**, and only after the effective-mode gate (§2.0.1), `ActorPolicy` (§2.12), ledger reservation (§7.3), actor signing (§2.0), and budget reserve (§2.5). Generic `scriptedRest` hitting any denylisted path returns typed `path_denied` (B2). Anything beyond `/api/...` stays off unless explicitly enabled per tenant.

### 3.3 The `ServiceNowRPC` binding (the security boundary)

`class ServiceNowRPC extends RpcTarget`, constructed with `(env, ctx, authContext, credentialMode, effectiveMode, actorPolicy, runBudget)`. Public methods are the only ServiceNow capabilities reachable from the sandbox; credentials are injected host-side. **Every method — reads included — first enforces `ActorPolicy` (§2.12) and the effective-mode capability gate (§2.0.1, §3.5), then meters the per-run budget (§2.5)**, then calls ServiceNow. Read methods come first (§Phase 3); mutating methods additionally take an idempotency key and route through the mutation ledger (§7.3). In `integration_user` mode every mutating/executor call attaches the **signed** actor metadata (§2.0), which the executor **verifies**. No token appears in any method signature or return.

### 3.4 "Official SDK vs hand-rolled" (decision)

Use `DynamicWorkerExecutor` + codemode type-gen; own a thin MCP `run_code` wrapper. `createCodeTool` returns an AI-SDK `Tool` for `streamText` (we are an MCP server, so we don't consume it). We do **not** hand-roll `env.LOADER.load()` (discards the executor's dispatch/normalization/log/timeout). The wrapper only: transforms TS→JS string (§2.2), calls `executor.execute(jsString, fns)`, serializes for MCP. **Phase 0.8 proves the exact `execute()` contract and the TS pipeline before this is built.** ADR-0001 records: the exact user-authored code shape; the exact wrapper generated around user code; the exact string passed to `execute()`; the exact `fns` shape; how imports are allowed/blocked; whether `export default` is accepted or rejected. **Every sample in the plan then conforms to that one shape.**

### 3.5 Capability/mode layer — enforced from day one

Advisory enforcement is a false sense of safety, so the mode is **enforced**:

```ts
export const DEFAULT_MODE = "read_only"; // Decision 1 (§0.9); flip for private demos
export const MODE_CAPABILITIES = {
  read_only:   ["readTables", "attachmentsRead"],
  write:       ["readTables", "writeTables", "importSets", "attachmentsRead", "attachmentsWrite"],
  admin_script:["readTables", "writeTables", "deleteRecords", "importSets",
                "attachmentsRead", "attachmentsWrite", "runServerScript"],
} as const;
```

For a given `run_code` invocation the **effective** mode (§2.0.1: `min(requested, OAuth-scope, tenant, instance)`) constrains which `ServiceNowRPC` methods the sandbox may call; out-of-mode calls throw a typed `capability_denied` recorded in the audit/ledger. The requested `mode` can only narrow — it never grants — so the read-only default cannot be bypassed by asking for `admin_script`. (Permissive override: set `DEFAULT_MODE` and widen `read_only`'s capabilities; document as a private-deployment posture. The override changes the *floor*, not the scope/tenant/instance *ceiling*.)

**Human approval for destructive operations.** A declared `mode:"admin_script"` is **not** the same as approval. `deleteRecords`, `runServerScript`, broad `importSet`s, and attachment writes additionally require one of: MCP **elicitation/confirmation** (stateful variant only, §10.1), Cloudflare **Access-group** membership, a tenant-configured **approval token**, or **dry-run → explicit approve → execute**. Because the stateless `createMcpHandler` shape cannot elicit, stateless deployments use the Access-group/approval-token/dry-run paths; elicitation is available only in the stateful variant. The current design is safe enough for a trusted autonomous engineering agent; a broad user population should require approval here. (Tracked in Phase 7; `reason` is mandatory for `admin_script`.)

---

## 4. Repository layout

```
servicenow-codemode-mcp/
├─ package.json / package-lock.json / tsconfig.base.json / .gitignore / .dev.vars.example
├─ alchemy.run.ts / vitest.config.ts / README.md
├─ packages/
│  ├─ mcp-server/
│  │  ├─ src/
│  │  │  ├─ index.ts                       # OAuthProvider wiring, routing, Origin validation, /health
│  │  │  ├─ server.ts                      # createServer(): 3 tools, per-request
│  │  │  ├─ auth/
│  │  │  │  ├─ mcp-oauth.ts                # OAuthProvider config; client-token issue/validate; storage binding
│  │  │  │  ├─ servicenow-auth-handler.ts  # consent (CSRF) + upstream ServiceNow PKCE
│  │  │  │  ├─ pkce.ts                     # verifier/state/nonce → AuthCorrelationDO
│  │  │  │  ├─ oauth.ts                    # ServiceNow exchange/refresh/revoke
│  │  │  │  ├─ actor.ts                    # canonicalize + HMAC-sign actor metadata (§2.0); executor verifies
│  │  │  │  ├─ token-store.ts              # TokenStoreDO adapter, versioned envelope
│  │  │  │  └─ crypto.ts                   # AES-GCM envelope, KEK versioning
│  │  │  ├─ authz/
│  │  │  │  ├─ effective-mode.ts           # min(requested, scope, tenant, instance) (§2.0.1)
│  │  │  │  ├─ actor-policy.ts             # per-actor instance/table/field/row/mode policy (§2.12)
│  │  │  │  └─ approval.ts                 # admin_script allowlist + approval gate (§3.5)
│  │  │  ├─ tools/ run_code.ts · describe_table.ts · list_tables.ts
│  │  │  ├─ sandbox/
│  │  │  │  ├─ transpile.ts                # esbuild-wasm transform (TS→JS string)  [primary]
│  │  │  │  ├─ bundler-fallback.ts         # worker-bundler module map  [only if 0.8 forces load()]
│  │  │  │  ├─ executor.ts                 # DynamicWorkerExecutor factory + serialize()
│  │  │  │  └─ types.ts                    # codemode type-gen for the ServiceNow surface
│  │  │  ├─ sn/ rpc.ts · client.ts · table.ts · aggregate.ts · attachment.ts · import-set.ts
│  │  │  │     · cmdb.ts · knowledge.ts · catalog.ts · scripted-rest.ts · executor-client.ts · errors.ts
│  │  │  ├─ cache/ schema.ts
│  │  │  ├─ do/ auth-correlation.ts · token-store.ts · budget.ts · mutation-ledger.ts
│  │  │  ├─ recovery/ snapshots.ts         # before/after snapshots for configured tables (§7.7)
│  │  │  ├─ observability/ audit.ts · mutations.ts · budget.ts · redact.ts · origin.ts
│  │  │  └─ config.ts                      # limits + DEFAULT_MODE + MODE_CAPABILITIES + OAuth scopes
│  │  │                                    #   + ActorPolicy defaults + multi-dim budgets + compat date
│  │  ├─ wrangler.jsonc / worker-configuration.d.ts   # incl. OAUTH_KV binding
│  └─ shared/src/types.ts
├─ sn-executor-app/                         # scoped app x_mcp (update-set source)
│  ├─ README.md / update-set/x_mcp.xml
│  ├─ tables/x_mcp_audit_log.xml            # records snow user + mcp actor + actor_verified
│  ├─ tables/x_mcp_nonce.xml                # actor-replay nonce store (TTL-pruned) (§2.0, §10)
│  ├─ roles/x_mcp.executor.xml · roles/x_mcp.admin.xml
│  ├─ acl/x_mcp_executor_endpoint.xml       # REST_Endpoint ACL → x_mcp.executor
│  ├─ acl/x_mcp_audit_log_*.xml             # read/write → x_mcp.admin only (executor cannot read/alter)
│  ├─ script-include/x_mcp_verify.js        # HMAC verify (current+prev key) + nonce replay (§2.0)
│  ├─ scripted-rest/x_mcp.executor.run.js   # synchronous; audit-first; verify signed actor; byte cap; SAFE serialize
│  └─ properties/ enabled · max_bytes · max_output_bytes · timeout_ms
│                · run_server_script_enabled · hmac_secret · hmac_secret_prev
├─ tests/ unit/ · integration/ · bypass/      # B1–B9 (§6 Phase 9)
└─ docs/ ADR/0001-codemode-integration.md · THREAT_MODEL.md · ROLE_MATRIX.md · RECOVERY.md
         · SNOW_EGRESS.md · RETENTION.md · RUNBOOKS.md · DELTAS.md · OPEN_QUESTIONS.md
```

---

## 5. Dependency manifest

Pin **EXACT** for every runtime-critical package; carets only for pure dev tooling, lockfile committed. Re-confirm "tested" against npm in Phase 0; prefer the newest matching the documented API and record changes in `DELTAS.md`.

| Dependency | Pin | Tested (2026-05-30) | Why |
|---|---|---|---|
| `@cloudflare/codemode` | EXACT | `0.3.8` | executor + type-gen |
| `esbuild-wasm` | EXACT | (latest, confirm) | **primary** TS→JS transform inside workerd |
| `@cloudflare/worker-bundler` | EXACT | `0.1.3` (closed beta) | **fallback** module-map bundling (only if 0.8 forces `load()`) |
| `agents` | EXACT | `0.13.3` | `createMcpHandler`, `getMcpAuthContext`, `WorkerTransport`, `Agent` |
| `@modelcontextprotocol/sdk` | EXACT | `1.29.0` (min 1.26.0) | `McpServer`, transports, schemas |
| `@cloudflare/workers-oauth-provider` | EXACT | (confirm) | MCP-client OAuth 2.1 provider |
| `wrangler` | EXACT | `4.95.0` | dev runtime + `wrangler types` |
| `alchemy` | EXACT | `0.87.0` | IaC; WorkerLoader binding (min 0.71.0) |
| `hono` | EXACT | `4.12.23` | routing |
| `zod` | EXACT | `4.4.3` | tool input schemas |
| `ai` | EXACT | (match codemode peer) | peer of `@cloudflare/codemode/ai` type-gen |
| `@cloudflare/vitest-pool-workers` | EXACT | (match wrangler) | **required** to test transpile + loader inside workerd |
| `vitest` / `@modelcontextprotocol/inspector` / `typescript` | caret (dev) | 3.x / `0.21.2` / 5.x | runner / E2E client / language |

Note: depending on Phase 0.8, `@cloudflare/worker-bundler` may be **unused**; keep it only if the fallback path is taken.

---

## 6. Phased build

### Phase 0 — Bootstrap, verification, contract proofs (≈2 days)

**Goal:** a workspace that builds and deploys a trivial Worker, every version/API confirmed, and the high-risk contracts proven.

- **0.1 Version/API reconciliation** → `docs/DELTAS.md`.
- **0.2–0.7** workspace, deps, Alchemy skeleton (four DOs + LOADER + KV + secrets, unified compat date), hello MCP server (per-request), Vitest workers pool, `/health`.
- **0.8a Code Mode execution-contract + no-import transform proof (REQUIRED before Phase 4).** Take a **no-import** TS snippet calling `codemode.servicenow.tableQuery(...)` against a **mock** RPC. Transform TS→JS with **esbuild-wasm** (`transform`, not bundle); call `DynamicWorkerExecutor.execute(jsString, fns)`. Assert: (a) the snippet can call `codemode.*`; (b) global `fetch` unavailable under `globalOutbound:null`; (c) `console.log/warn/error` captured; (d) thrown TS/runtime errors map to a typed MCP error; (e) timeout observable; (f) **`execute()` accepts the transformed string** (if not, switch to the worker-bundler+`load()` fallback and document why).
- **0.8b Allowed-import proof.** `esbuild-wasm transform` only strips types — it does **not** bundle imports. Prove how an allowed import (e.g. `zod`) reaches the sandbox: either **bundle to one JS string** (esbuild stdin→stdout bundling) or **inject the module** via the executor's `modules` option. Record which, and the allow/deny policy for imports. **Also decide broken-type handling and make it actionable:** `transform` catches **syntax** errors only, not type errors; choose (i) accept runtime-only typing, (ii) run `tsc --noEmit` on the snippet for real type-checking (cost/latency tradeoff), or (iii) a lint subset. **Write ADR-0001** with the exact code shape, wrapper, `execute()` string, `fns` shape, import strategy, type-check decision, and `export default` accept/reject. **Then conform every sample in the plan to that shape.**
- **0.9 Pricing/cost-shape proof** (§2.5) → runbook note; stub the **multi-dimensional** `BudgetDO` interface (atomic reserve for workers + RPC + SN-requests + rows/bytes; per-run counters).
- **0.10 OAuthProvider storage/config proof.** Confirm `@cloudflare/workers-oauth-provider` persists clients/grants/tokens in the **`OAUTH_KV`** binding (declare it now); prove a minimal authorize→token→/mcp round-trip with a mock upstream; confirm scopes (`servicenow:read|write|admin_script`) land in `auth.props`.
- **0.11 Streamable HTTP Origin-validation proof.** Confirm how to read/validate `Origin`; prove invalid Origin → 403, local binds to localhost.
- **0.12 Durable Object partition proof.** Prove token, budget (incl. global), idempotency, and PKCE ownership are correctly partitioned and that the **global** budget counter coordinates through a single object.
- **0.13 Authorization & attribution hard-stop proofs (REQUIRED before Phase 1/4/5).** These prove the properties the plan *claims*:
  - **0.13a Actor-signature proof.** Worker canonicalizes `{ actor, script_hash, timestamp, nonce, request_id, instance }` and signs (HMAC); the `x_mcp` resource **verifies** in-scope and **rejects** forged/missing/stale/replayed signatures. Establish the in-scope verification mechanism (Script Include / `GlideCertificateEncryption.generateMac` / `com.glide.tokenbased_auth` HMAC). → S8/S13/B1.
  - **0.13b Effective-mode proof.** `requestedMode` is capped by OAuth scope ∩ tenant ∩ instance; asking for `admin_script` without scope is denied. → B3/B4.
  - **0.13c Integration-user read-policy proof.** An actor cannot read a table/field outside `ActorPolicy` even though `integration_user` can. → B5.
  - **0.13d OAuth storage proof.** `OAUTH_KV` exists and provider data is isolated from `TokenStoreDO`; missing `OAUTH_KV` fails. → B8.
  - **0.13e ServiceNow OAuth refresh proof.** The chosen (confidential) app type returns / rotates / revokes refresh tokens as assumed, incl. MFA/timeout behavior. → B9.

**DoD:** trivial Worker deploys/runs; Inspector lists `hello`; **0.8a/0.8b pass and ADR-0001 is written**; 0.10–0.13 pass (the 0.13 hard-stops gate Phase 1/4/5); `DELTAS.md` populated; one compat date used everywhere; `OAUTH_KV` + `X_MCP_EXECUTOR_HMAC_KEY` declared.

### Phase 1 — Auth (both layers), credential mode, client, discovery, scoped-app spike (≈5–6 days; may split)

**Runbook** (`docs/RUNBOOKS.md`): obtain a PDI (hibernates ~6h idle / ~30 min if woken without login; reclaimed after 10 days of Developer-Portal inactivity — record-creation does not reset it); register the ServiceNow OAuth endpoint (PKCE, KB1645540); create `mcp_integration_user`; MFA applies to U2M PKCE, not ROPC.

- **1.1 MCP-client OAuth layer** (`OAuthProvider` bound to **`OAUTH_KV`**, consent dialog with CSRF protection before forwarding upstream — prevents the confused-deputy problem; the Worker issues its own token bound to `{userId, instanceHost, snowCredentialId, scopes}` where scopes are `servicenow:read|write|admin_script`, §2.0.1).
- **1.2 Credential mode** (§2.0). Implement `integration_user` with `actor.ts` **canonicalizing + HMAC-signing** the actor payload (the executor verifies it in Phase 5), and `per_user_oauth` (per-user PKCE tokens). Register the ServiceNow OAuth app as a **confidential client** (Auth Code + PKCE + client secret) where refresh tokens are required, and complete the **refresh-token proof** (B9, §2.8). `servicenow-auth-handler.ts` + `pkce.ts` (→ `AuthCorrelationDO`). ROPC behind `SNOW_DEV_ROPC=1` for dev/CI.
- **1.3 Token store + crypto + TokenStoreDO** (§2.7); multi-user/instance from the start; **separate from `OAUTH_KV`**.
- **1.4 Auth-context plumbing.** Tools call `getMcpAuthContext()` → derive the token-store key from `auth.props`. Add S2-auth tests now.
- **1.4a Authorization layer (gated by Phase 0.13b/0.13c).** `authz/effective-mode.ts` (cap requested mode by scope ∩ tenant ∩ instance, §2.0.1) and `authz/actor-policy.ts` (per-actor instance/table/field/row/mode, §2.12), both enforced inside `ServiceNowRPC` before every call. **For multi-user, default to `per_user_oauth` unless `ActorPolicy` is implemented and enforced.** Add B3/B4/B5 stubs.
- **1.5 ServiceNow client** with base-URL **allowlist** (parse with `URL`; require https; reject userinfo/path/query/fragment; normalize host; per-tenant allowlist; `*.service-now.com` for PDI/dev only — documented narrowing). Centralized fetch: bearer injection, `requestId`, timeout, 429/5xx retry+jitter.
- **1.6 Error mapping** → typed codes (incl. `instance_hibernating`, `reauth_required`, `capability_denied`, `budget_exceeded`).
- **1.7 Table reads + discovery** (keyset on `sys_id`; **`sys_id` always included internally** even if the user didn't request it, because the cursor needs it); user-aware schema cache.
- **1.8 Minimal `x_mcp` scoped-app spike (make-or-break) — corrected acceptance.** Create scoped app `x_mcp`, role `x_mcp.executor`, one Scripted REST endpoint, a REST_Endpoint ACL requiring the role, the audit table, the kill-switch property. Prove:
  - a user **without** the role gets 403 — **observed via ServiceNow platform security/access logs or the outer Cloudflare gateway log, NOT necessarily `x_mcp_audit_log`** (the resource script does not run on ACL denial; do **not** weaken the ACL to capture custom denied-audit rows);
  - a user **with** the role gets 200 and an `x_mcp_audit_log` row;
  - the **kill switch** returns a controlled 503 **and writes an audit row** (the switch is checked inside the resource, after ACL passes — audit-first);
  - **cross-scope reach (per P8):** read the global `incident` table; update a safe global **test** record; read `sys_dictionary`/`sys_db_object`; use `GlideAggregate`; call the intended APIs from scoped script; observe any cross-scope prompts/failures; **export/import the app into a clean instance and re-test**.

**DoD:** client OAuth handshake (with `OAUTH_KV`) + ServiceNow PKCE both complete; refresh-token behavior proven (B9) and tokens isolated from `OAUTH_KV`; discovery works with user-aware caching; **effective-mode and `ActorPolicy` are enforced in `ServiceNowRPC` (B3/B4/B5 stubs green)**; tokens at rest are the versioned envelope; S2-auth passes; the `x_mcp` spike proves 403(via platform/gateway log)/200/503(with audit)/cross-scope reach including clean-instance re-test.

### Phase 2 — Token/cache/pagination/URL hardening (≈2 days)

- **2.1 KEK rotation** (current+previous KEK; rotation runbook).
- **2.2 Schema cache** finalized (user-aware key, `schema_invalidate` admin route, `schemaVersion` bump, `degraded:true` fallback).
- **2.3 Pagination guards** implementing the **§2.13 strategy** (host cap 1000 over the SN default 10000; `sysparm_limit` applies **before** ACL evaluation). User query + host `ORDERBYsys_id` compose safely; `sys_id>{last}` encoded; reject injected `ORDERBY`/`javascript:`/encoded-query fragments; mid-pagination insert/delete must not duplicate/skip seen `sys_id`s; **an empty page after ACL filtering must advance, not stall** (integration_user: filter via ActorPolicy above the cursor; per_user_oauth: bounded-offset fallback or scoped `GlideRecordSecure` helper; else `partial:true`). `(sys_updated_on, sys_id)` noted for sync (Phase 10.5). → S5/B7.
- **2.4 URL canonicalization** (uppercase/lowercase host normalization; trailing dot; punycode/IDNA; userinfo rejection; path/query/fragment rejection for base URL; custom-domain allowlist; private-IP/localhost rejection if custom host resolution is ever allowed) → S15.

**DoD:** rotation, invalidation, negative cache (S6), pagination (S5), and URL/SSRF (S15) tests satisfiable.

### Phase 3 — `ServiceNowRPC` + read-only surface first (≈3 days)

- **3.1** `ServiceNowRPC` with `fns()` + `typeDescriptors()`; **read methods first**; no token in any signature/return. **Every method enforces `ActorPolicy` (§2.12) + effective-mode (§2.0.1) and meters the per-run budget (§2.5) before calling ServiceNow** — reads included, since in `integration_user` mode ServiceNow ACLs do not bound the MCP user.
- **3.2 Aggregate** (counts without paging rows).
- **3.3 Attachment reads** — `attachmentList` (metadata); `attachmentGet` with a **concrete memory cap and response shape** (stream; return base64 only under cap, else a reference + `truncated` — base64 in MCP balloons fast).
- **3.4 CMDB/Knowledge/Catalog reads.**
- **3.5 Type surface** → `generateTypes` (snapshot test).
- **3.6 Mutating methods (defined, gated, attributed).** `tableCreate/Update/Delete`, `importSet`, attachment writes, catalog add/submit, `runServerScript` — each takes an idempotency key, routes through the **enforced** effective-mode gate (§2.0.1/§3.5) and the mutation ledger (§7.3), and (integration mode) attaches the **signed** actor metadata that the executor **verifies** (§2.0). Destructive ops (`tableDelete`, `runServerScript`, broad `importSet`, attachment writes) additionally require the approval gate (§3.5) and a mandatory `reason`.

**DoD:** read methods unit-tested vs PDI (happy + ≥1 typed error), **with `ActorPolicy` and per-run budget enforced on reads**; type-surface snapshot stable; mutating methods present and gated (exercised in 4/5).

### Phase 4 — `run_code` with the (corrected) TS pipeline + atomic budgets (≈3 days)

- **4.1 `config.ts`** limits + `DEFAULT_MODE`/`MODE_CAPABILITIES` + OAuth-scope→mode map + `ActorPolicy` defaults + **multi-dimensional budgets** (per-run + daily, §2.5) + the single compat date.
- **4.2 `sandbox/transpile.ts`** — **esbuild-wasm `transform`** (TS→JS string) per ADR-0001; structured bundler/type errors (file+line), never raw into the host. (`bundler-fallback.ts` only if 0.8 took the fallback.)
- **4.3 `sandbox/types.ts`** — inject the `declare const codemode: { servicenow: {…} }` surface into the tool description.
- **4.4 `sandbox/executor.ts`** — `DynamicWorkerExecutor({ loader, globalOutbound:null, timeout })`; `serialize(result, cap)` (truncate to `{truncated:true,total:N,sample}`; capture logs; map thrown errors).
- **4.5 `observability/budget.ts` + `BudgetDO`** — **multi-dimensional atomic reserve-before-load** (§2.5). The full enforced order (§3.1) is: **size → auth-context → effective-mode (§2.0.1) → ActorPolicy (§2.12) → scriptedRest denylist (§3.2) → budget reserve → transpile/bundle → execute → RPC-call accounting → SN-request accounting → audit/ledger finalize.** Authorization precedes transpile; reserve precedes `load()` (an unauthorized or exhausted caller never creates a billable Worker). Per-run counters trip mid-snippet; daily hard breaker → typed `budget_exceeded`; emit each dimension as a logged metric.
- **4.6 `tools/run_code.ts`** — `{ code, mode?, reason?, idempotencyKey? }`; default `read_only`; `reason` mandatory for `admin_script`; pipeline per the §3.1 order → `{ content:[{type:"text",text}], isError, mutations? }`. Reject oversize code pre-transpile; reject `mode_not_permitted` pre-transpile.
- **4.7 Wire into `server.ts`.** Introduce a **minimal redactor now** (logs may appear in dev) and expand in Phase 7.

**DoD:** safe example runs E2E; invalid TS → typed error (file/line), host up; infinite loop killed at timeout; 5 MB return truncated; `console.*` captured; **daily + per-run budget breakers trip and every dimension's metric is logged** (acceptance gate); **default mode is `read_only`; a write without `mode` and an `admin_script` request without the scope are both denied** (`capability_denied`/`mode_not_permitted`, B3/B4); the enforced pipeline order (§3.1) is asserted; S1–S4, S11, S14 satisfiable.

### Phase 5 — Full hardened scoped-app executor (≈2.5 days)

Promote the Phase 1.8 spike to the full executor. **Build in the PDI, export as an update set into `sn-executor-app/`.**

- **5.1 Scoped app + roles** `x_mcp`; `x_mcp.executor`; `x_mcp.admin` (separation of duty). **Harden the audit table ACLs (§12):** `x_mcp.executor` may **create** an audit row (the resource inserts/updates only the row it created) but **cannot read or alter** other rows, change properties, or grant roles; `x_mcp.admin` holds read/manage and is **not** the integration user. If same-scope in-script writes require it, perform audit writes through a scoped helper that touches only the current request's row — prove this here.
- **5.2 Audit table** `x_mcp_audit_log` recording **the ServiceNow effective user, the MCP actor, and `actor_verified`** (§2.0), plus `request_id`, `code_hash`, `code_size`, `started_at`, `duration`, `status` (`running|ok|error|truncated|killed|rejected`), `output_size`, `error_class`. **No script body, no raw output.** Add **`x_mcp_nonce`** (value + created; TTL-pruned by a scheduled job) for actor replay defense.
- **5.3 Properties** `enabled` (kill switch), `max_bytes` (**UTF-8 bytes**, §10), `max_output_bytes`, `timeout_ms`, **`run_server_script_enabled`** (tenant egress toggle, §11), `hmac_secret` + `hmac_secret_prev` (actor-signature keys, rotation). **No `allow_unsafe` in v1** — shipping a knob that may not actually prevent global `GlideRecord` access is worse than not having it; reintroduce only if Phase 1.8 proved on the target family that it genuinely constrains the environment.
- **5.4 Executor resource `x_mcp/executor/run` (POST) — see §10 for the full corrected script.** Order: **audit-insert (fail closed if it fails) → verify signed actor (§2.0; reject forged/missing/stale/replayed → 401 `actor_signature_invalid`, `status="rejected"`) → kill switch (`killed`/503) → tenant egress toggle → UTF-8 byte size check → synchronous execute → SAFE serialize → close audit.**
  - **Synchronous:** `new Function('gs','GlideRecord','GlideRecordSecure','GlideAggregate','"use strict";\n'+code)`. No `async`/`await` (scoped apps default ES2021).
  - **SAFE serialize (§10):** wrap `JSON.stringify` in try/catch (circular / GlideRecord-like / too deep → `status="error"`); on over-cap output **never `JSON.parse` a truncated string** — return `{ result:null, result_sample, truncated:true }`.
  - **`timeout_ms` is a client-visible budget, not a hard timeout; the kill switch does not abort a running script; long execution is additionally bounded by ServiceNow transaction limits.** Do not claim interruption.
- **5.4a Signed-actor verification (P5-A, gated by Phase 0.13a).** Implement `script-include/x_mcp_verify.js`: recompute `script_sha256`, rebuild the canonical payload, HMAC-verify against `hmac_secret` then `hmac_secret_prev`, enforce the freshness window, and reject replayed nonces (insert into `x_mcp_nonce`). Negative tests: forged `mcp_actor_email`, missing sig, stale timestamp, replayed nonce — all rejected (B1, S8/S13).
- **5.5 REST_Endpoint ACL** requiring `x_mcp.executor`, **replacing** the default `Scripted REST External Default` (broad `snc_internal`).
- **5.6 `sn/executor-client.ts`** — `runServerScript(script, opts)` builds the canonical payload `{actor, script_sha256, issued_at, nonce, request_id, instance}`, **HMAC-signs** it (`X_MCP_EXECUTOR_HMAC_KEY`), posts via `scriptedRest` (executor path is reachable **only** here, §3.2), returns `{ ok, result, result_sample?, truncated, error, audit_id }`; surfaces 503 as `executor_disabled` and 401 as `actor_signature_invalid`; routes through the `runServerScript` capability, the approval gate (§3.5), and the **leveled** ledger (§7.3).
- **5.7 ServiceNow-side egress controls (§11).** `run_server_script_enabled` is a tenant kill switch for the executor specifically; document the residual egress risk (a server-side script may call ServiceNow outbound APIs / email / events — `globalOutbound:null` does **not** constrain this) in `docs/SNOW_EGRESS.md`; optional best-effort static denylist scan of obvious outbound APIs (documented as *not* a sandbox); mandatory `reason` + approval for `admin_script`; a **separate executor budget** dimension.
- **5.8 Export update set**; install runbook (import → commit → assign `x_mcp.executor`; set `hmac_secret`). **No `sys_trigger` fallback** (unsupported/experimental).

**DoD:** `runServerScript("return gs.getUserName();")` with a **valid signature** returns a **value**; a **forged/missing/stale/replayed** actor is rejected 401 with `status="rejected"` (B1); a non-`x_mcp.executor` identity gets 403 (platform/gateway log); allowed calls write audit rows with **both** users + `actor_verified=true` + hash and no body/output; `x_mcp.executor` **cannot** read other audit rows or flip properties; a call while `enabled=false` records `status="killed"`/503 and an audit-insert failure **fails closed**; truncated output returns a **valid** `result_sample` envelope (B6); cross-scope reach holds on a clean instance; S8, S9, S16 pass.

### Phase 6 — Role matrix & posture (≈0.5 day; depends on Decision 2)

Write `docs/ROLE_MATRIX.md`. **If `integration_user`:** the broad role set applies to `mcp_integration_user` and **host-side actor attribution is mandatory** (§2.0). **If `per_user_oauth`:** the matrix applies to human users/groups and ACLs bound access naturally. Document the reversible elevation path to global-scope writes. Frame least-privilege-per-capability as what makes high aggregate access safe.

**DoD:** the chosen mode's access path verified; `ROLE_MATRIX.md` matches the applied config and names the credential mode.

### Phase 7 — Production hardening (≈3 days)

- **7.1 `observability/redact.ts`** (expand the Phase 4 minimal redactor): denylist fields + token patterns; never log script body or full RPC responses.
- **7.2 `observability/audit.ts`** host-side audit for writes/deletes/`runServerScript`: `(mcp_actor, snow_effective_user, instance, table, sys_id, op, before-hash, after-hash, requestId)`.
- **7.3 `observability/mutations.ts` + `MutationLedgerDO` — leveled idempotency.**
  - **Level 1 — host-mediated RPC mutations** (`tableCreate/Update/Delete`, `importSet`, attachment writes): **fully ledgered**; replays return the original result where safe; ledger entry `(operation, table, sys_id, request-hash, result)`.
  - **Level 2 — `runServerScript` invocation:** dedupe by **script-hash + idempotency key before execution only**; ledger state `started|completed|failed|indeterminate`; **a retry after `indeterminate` must not silently re-execute.**
  - **Level 3 — internal ServiceNow mutations inside arbitrary script:** **not individually idempotent** unless the script implements its own keys. Documented as a limitation, not a guarantee.
- **7.4 Origin validation** (`observability/origin.ts`): remote rejects invalid `Origin` (403); local binds to localhost (documented dev exception). → S12.
- **7.5 Token lifecycle** refresh-rotation (audited), revoke on logout (`oauth_revoke_token.do` + delete row + invalidate the MCP-client session mapping), corrupt/AAD-mismatch → `reauth_required`.
- **7.6 `/health`** → `{ instance: "online"|"hibernating", ok }`.
- **7.7 Recovery model (`recovery/snapshots.ts`, `docs/RECOVERY.md`).** "Recoverable" needs more than hashes:
  - **`tableUpdate`:** store encrypted before/after field snapshots for **configured** tables, or rely on `sys_audit` where sufficient.
  - **`tableDelete`:** **disallow by default** (admin_script only), soft-delete where possible, or store an encrypted preimage with a retention window.
  - **`runServerScript`:** **no general rollback guarantee** — labeled high-risk `admin_script`.
  - **`importSet`/catalog:** idempotency plus created-record references for cleanup.
  - If raw snapshots are too sensitive for a tenant, **say so and narrow the recovery claim** for that tenant rather than implying full reversibility.
  - **Snapshot store policy (`docs/RETENTION.md`) — a snapshot store is itself sensitive data.** Specify: **retention period** (default e.g. 30 days, then purge), **encryption key + version** (dedicated `SNAPSHOT_KEK`, rotated), **who can decrypt** (admin role + key holder), a **deletion workflow** (scheduled purge), **PII classification** (snapshots may contain PII), and **tenant opt-out** (recovery claim narrowed when off). "Recoverable" must not silently become "we built a second sensitive database."
- **7.8 Deploy-path protection** Cloudflare Access / IP allow-list on `/admin/*`; production `/mcp` requires a valid MCP-client token (enforced by the provider) **with audience/issuer/scope checked before tool invocation** (→ O8).
- **7.9 Destructive-op approval (§3.5).** Implement `authz/approval.ts`: `admin_script` requires a tenant allowlist + a second approval (Access-group / approval-token / dry-run→approve→execute; elicitation only in the stateful variant §10.1). `deleteRecords` is `admin_script`-only and soft-delete-preferred; `runServerScript`/broad `importSet`/attachment writes require `reason` + approval. → B3/B4.

**DoD:** redaction tested; writes/deletes/script audited with both identities; **Level-1 replay returns the original result; Level-2 `indeterminate` retry does not re-execute**; Origin validation (S12) passes; refresh/revoke/corruption per spec; `/health` reports hibernation; recovery evidence exists (S18).

### Phase 8 — Local stdio shim (optional, ≈0.5 day)

`bin/stdio.ts` shares `createServer()` and connects `StdioServerTransport`. `run_code` proxies to a local **`wrangler dev --port 8787`** (Worker Loader needs workerd) or returns a clear "use the HTTP endpoint" message. Document the choice in `DELTAS.md`.

### Phase 9 — Full test plan (≈3 days; written alongside earlier phases)

Vitest + `@cloudflare/vitest-pool-workers`. **CI matrix:**

- **Always blocking:** unit; schema-cache (fixtures); S1, S2, **S2-auth**, S11, **S12, S13, S14, S15**; executor serialization; capability/policy; **the bypass group B1–B6, B8**.
- **Blocking before GA:** integration suite against a **sub-production ServiceNow instance** (incl. **S16, S17, S18**, and **B7, B9**).
- **Non-blocking:** PDI smoke (skip-with-warning on hibernation; never silently pass).

Named tests (specs as docstrings):

- **S1** network isolation; **S2** credential non-leakage; **S2-auth** MCP-auth user/instance isolation; **S3** TS transpile (valid/zod-import/broken→file+line); **S4** run_code guardrails (oversize/timeout/truncation/thrown/console); **S5** Table API resilience + pagination edge cases (compose/encode/inject-reject/insert/delete/ACL-hidden/ACL-empty-page-advance per §2.13 → B7); **S6** user-aware schema cache + negative case (B with same role but failing a field/scripted ACL must not get A's field); **S7** token lifecycle (refresh/revoke/corrupt/AAD/KEK-window/per-instance/clock-skew); **S8** executor governance (**ACL-denied observed via platform/gateway log, not app audit**; **forged/missing/stale/replayed actor rejected → B1**; allowed writes both-user audit row with `actor_verified`; `audit_id` returned); **S9** kill switch (503 + `status="killed"`, audit-first; resumes without redeploy); **S10** E2E via Inspector at `http://localhost:8787/mcp` then remote with MCP-client OAuth; **S11** budget breaker (distinct snippets trip the daily counter before `load()`; metric logged).
- **S12 — Origin validation / DNS rebinding.** Invalid Origin → 403 remote; local binds localhost; valid clients work.
- **S13 — OAuth negative.** O1 redirect_uri exact (not prefix) match; O2 missing/invalid state; O3 stale/replayed state; O4 wrong PKCE verifier; O5 unknown client_id; O6 registration metadata sanitized; O7 consent cannot be skipped via cached upstream auth; O8 MCP token audience/issuer/scope checked before tool invocation; O9 instanceHost cannot be swapped during callback; O10 logout/revoke invalidates **both** the MCP-client session and the ServiceNow credential mapping.
- **S14 — Budget concurrency.** Parallel distinct snippets cannot exceed the **global** cap (atomic reserve across the single global-keyed object).
- **S15 — URL allowlist canonicalization / SSRF.** Per Phase 2.4.
- **S16 — ServiceNow scoped-app cross-scope reach.** Per Phase 1.8/5, on a clean instance.
- **S17 — `runServerScript` indeterminate retry.** A timed-out/indeterminate script is not silently re-executed on retry with the same key.
- **S18 — Destructive-operation recovery evidence.** A configured `tableUpdate` is reversible from its snapshot; `tableDelete` is disallowed/soft/preimaged per policy; `runServerScript` is labeled non-recoverable.

**Bypass group (B1–B9) — the v4 "is the claim actually true?" tests.** Each targets a property the plan asserts:

- **B1 — Forged actor metadata rejected.** A request with a tampered `mcp_actor_email`/`mcp_actor_user_id`, a missing signature, a stale `issued_at`, or a replayed `nonce` is rejected by the executor (401, `status="rejected"`); only a valid signature yields `actor_verified=true` (§2.0, §10).
- **B2 — Generic `scriptedRest` cannot reach the executor.** `scriptedRest("/api/x_mcp/executor/run", ...)` (and the other denylisted paths) returns `path_denied`; the executor is reachable only via `runServerScript()` (§3.2).
- **B3 — `admin_script` denied without the OAuth scope.** A client without `servicenow:admin_script` requesting `mode:"admin_script"` is denied `mode_not_permitted`, even with a tenant allowlist (§2.0.1).
- **B4 — Read-only cannot self-escalate.** A `read_only`-scoped client cannot reach `write`/`admin_script` by passing `mode` in the tool input alone (§2.0.1/§3.5).
- **B5 — `integration_user` honors `ActorPolicy` on reads.** An actor cannot read a table/field outside its `ActorPolicy` even though `mcp_integration_user` can; returns `actor_policy_denied` (§2.12).
- **B6 — Truncated executor output is a valid envelope.** A large/over-cap or non-serializable result returns `{ result:null, result_sample, truncated:true }` (or a typed serialize error) — never a thrown `JSON.parse` after the audit row was written (§10).
- **B7 — Empty page after ACL filtering does not stall.** Per the §2.13 strategy, a keyset page blanked by ACL filtering still advances (or returns `partial:true`); no infinite loop, no skipped visible rows (extends S5).
- **B8 — Missing `OAUTH_KV` fails.** Deploy/tests fail closed when the `OAUTH_KV` binding is absent (§2.4/§2.11).
- **B9 — ServiceNow refresh-token behavior proven.** The confidential-client PKCE flow returns, rotates, and revokes refresh tokens as assumed (§2.8); distinct from S7.

**DoD:** always-blocking green; S1, S2, S2-auth, S8, S9, S11, S12, S13, S14, S15 **and B1–B6, B8** are non-negotiable gates; the sub-production suite (incl. S16–S18, B7, B9) green before GA.

### Phase 10 — Stretch / post-MVP

- **10.1 Stateful variant** (`Agent` + `WorkerTransport` + `getAgentByName`).
- **10.2 Warm-isolate cost optimization** (`get(id, cb)` keyed by `(sessionId, codeHash)`) — cost-gated; isolation regression must still pass (S1/S2 for warmed isolates).
- **10.3 `openApiMcpServer` alternative** (host-side `request` keeps tokens out of the sandbox).
- **10.4 Build-time type codegen** for hot tables.
- **10.5 Incremental-sync cursor** `(sys_updated_on, sys_id)`.

---

## 7. Definition of "production ready" (GA gate)

1. **Phases 0–9 complete**; always-blocking suite green; **sub-production integration suite** green (PDI smoke is not the GA evidence base).
2. **Security invariants proven:** sandbox isolation (S1), credential non-leakage (S2), MCP-auth isolation (S2-auth), executor governance (S8) and kill switch (S9), Origin validation (S12), OAuth-negative (S13), budget concurrency (S14), SSRF resistance (S15), **signed-actor verification (B1), executor-bypass denylist (B2), mode-escalation prevention (B3/B4), `ActorPolicy` reads (B5), safe serialization (B6), ACL-pagination (B7), `OAUTH_KV` required (B8)**.
3. **Cost bounded:** **multi-dimensional** atomic budget breaker — unique Workers + RPC + SN requests + rows/bytes, per-run + daily (S11/S14); every dimension's metric logged; runbook cost note.
4. **Identity model decided and recorded** (§2.0); in integration mode, actor attribution is **signed and verified** in every mutating/executor audit row (`actor_verified=true`), and **`ActorPolicy` is enforced before every RPC in any multi-user deployment** (or `per_user_oauth` is used).
5. **Recoverability is honest** (S18): the recovery model is implemented for configured operations and the claim is narrowed where snapshots are not stored.
6. **`run_code` default is `read_only`** (or an explicit, documented override is recorded per §0.9 Decision 1).
7. **No secrets in repo/logs;** versioned token envelope; refresh/revoke/rotation correct (S7).
8. **Exact pins for all runtime-critical packages;** lockfile; `npm ci` reproducible.
9. **Pre-1.0 exit:** `@cloudflare/codemode` ≥ 1.0 and `@cloudflare/worker-bundler` out of closed beta (if used), or a signed exemption in `DELTAS.md`.
10. **Tested against a non-PDI instance.**
11. **ServiceNow OAuth proven** (B9): confidential client returns/rotates/revokes refresh tokens as assumed; `OAUTH_KV` isolated from `TokenStoreDO` (B8).
12. **Authorization is real, not nominal:** `effectiveMode = min(requested, scope, tenant, instance)`; `admin_script` gated by allowlist + approval; the requested `mode` can never grant (B3/B4).
13. **ServiceNow-side egress acknowledged and controlled** (`SNOW_EGRESS.md`; `run_server_script_enabled`; approval), and **recovery snapshots have a retention/encryption/PII/opt-out policy** (`RETENTION.md`, S18) — "recoverable" is not a second unmanaged sensitive store.

---

## 8. Risk register (build-time)

| Risk | Likelihood | Mitigation |
|---|---|---|
| `execute()` contract / TS-pipeline differs from assumption | High | **Phase 0.8 proves it (esbuild-wasm transform → string); ADR-0001 records the shape; worker-bundler fallback documented** |
| Dynamic Workers cost is live; runaway unique-Worker creation | High | **Atomic reserve-before-load in `BudgetDO`** (S11/S14); logged metric; `get(id)` lever (10.2) |
| Identity model ambiguity → wrong audit/authorization | High (addressed) | **Explicit credential mode (§2.0); signed actor attribution in integration mode** |
| Global budget unenforceable in a session DO | High (addressed) | **Split DOs; global counter in a single date-keyed object (§2.10)**; S14 |
| Executor denied-attempt audit impossible | Medium (addressed) | **ACL-denied observed via platform/gateway log, not app audit; ACL not weakened** |
| Scoped-app cross-scope limits block "maximum reach" | Medium | **Phase 1.8/5 cross-scope tests on a clean instance (S16)** |
| `runServerScript` partial-failure duplication | Medium | **Leveled idempotency; `indeterminate` retry blocked (S17)** |
| "Recoverable" over-claimed | Medium (addressed) | **Recovery model + narrowed claim where snapshots absent (S18)** |
| codemode/worker-bundler/oauth-provider breaking changes | High (pre-1.0/beta) | Exact pins; `DELTAS.md`; Phase 0; confine to `sandbox/*` and `auth/*` |
| Missing Origin validation → DNS rebinding | Medium (addressed) | **S12; Phase 7.4** |
| OAuth flaws (redirect/state/PKCE/consent) | Medium (addressed) | **S13 (O1–O10)** |
| `worker-bundler`/`esbuild-wasm` workerd-only | High if missed | Mandate `@cloudflare/vitest-pool-workers` |
| ServiceNow MFA blocks CI OAuth | Medium | CI uses ROPC/client-credentials (MFA-exempt) |
| Scoped-app install rejected by a customer | Low (PDI)/Medium (prod) | Phase 1.8 validates acceptance early; REST-only mode works without the executor |
| PDI hibernation/reclamation interrupts CI | Medium | `/health` gate; PDI non-blocking; GA on sub-prod |
| **Forged actor metadata** (claimed `body.actor`) defeats attribution | High (addressed) | **Host HMAC-signs; executor verifies (freshness + nonce, fail-closed); B1; Phase 0.13a** |
| **Requested `mode` escalates** without authorization | High (addressed) | **`effectiveMode = min(requested, scope, tenant, instance)`; `admin_script` allowlist + approval; B3/B4** |
| **`integration_user` over-reads** in multi-user (audit ≠ access) | High (addressed) | **`ActorPolicy` before every RPC, or `per_user_oauth` default; B5; §2.12** |
| `scriptedRest` bypasses `runServerScript()` gates | Medium (addressed) | **Explicit path denylist; executor reachable only via `runServerScript()`; B2** |
| Executor crash on truncated / non-serializable output | Medium (addressed) | **Safe serialize: never `JSON.parse` truncated; `stringify` try/catch; `result_sample`; B6** |
| **ServiceNow-side egress** via `runServerScript` (`globalOutbound` doesn't cover it) | Medium | **Tenant toggle + approval + denylist scan + non-recoverable labeling (`SNOW_EGRESS.md`)** |
| Cost beyond unique Workers (requests/CPU); one cheap Worker, many calls | High (addressed) | **Multi-dimensional per-run + daily budgets (S11/S14)** |
| `OAUTH_KV` missing or conflated with ServiceNow tokens | Medium (addressed) | **`OAUTH_KV` first-class + isolated from `TokenStoreDO`; fail closed if absent (B8)** |
| ServiceNow refresh-token behavior differs from assumption | Medium | **Confidential client; refresh proof gate B9 (§2.8)** |
| Recovery snapshots become a second sensitive store | Medium (addressed) | **Retention + encryption + PII class + opt-out (`RETENTION.md`, S18)** |
| esbuild `transform` ≠ bundle (imports); type errors uncaught | Medium | **Phase 0.8a/0.8b split (bundle-or-`modules`); type-check decision in ADR-0001** |

---

## 9. Quick-start command sequence

```bash
npm init -y                                    # → workspaces
npm i -E @cloudflare/codemode@<v> esbuild-wasm@<v> agents@<v> alchemy@<v> \
        @modelcontextprotocol/sdk@<v> @cloudflare/workers-oauth-provider@<v> hono@<v> zod@<v> ai@<v>
# add @cloudflare/worker-bundler@<v> ONLY if Phase 0.8 takes the fallback path
npm i -D wrangler@<v> vitest @cloudflare/vitest-pool-workers@<match-wrangler> \
        @modelcontextprotocol/inspector typescript
cp .dev.vars.example .dev.vars                 # SNOW_*, OAUTH_PROVIDER_SECRET, TOKEN_KEK,
                                               #   X_MCP_EXECUTOR_HMAC_KEY, SNAPSHOT_KEK
# bindings (alchemy.run.ts / wrangler.jsonc): LOADER, SCHEMA_KV, OAUTH_KV (required), 4 DOs
npx wrangler types
npx wrangler dev --port 8787                   # /mcp via Miniflare (incl. LOADER) — 8787 everywhere
npx @modelcontextprotocol/inspector            # connect to http://localhost:8787/mcp
npx alchemy deploy
```

Generate `TOKEN_KEK`, `OAUTH_PROVIDER_SECRET`, `X_MCP_EXECUTOR_HMAC_KEY` (actor signing, §2.0), and `SNAPSHOT_KEK` (recovery snapshots, §7.7) as 256-bit base64 (`openssl rand -base64 32`); store as secrets, never in the repo. The `OAUTH_KV` namespace must exist or deploy/tests fail (B8); mirror `X_MCP_EXECUTOR_HMAC_KEY` to the `x_mcp.executor.hmac_secret` property on the instance.

---

## 10. ServiceNow executor reference implementation (corrected)

This is the build reference for the `x_mcp` scoped-app executor — spiked in Phase 1.8, hardened in Phase 5. Build it in a PDI and export it as an update set into `sn-executor-app/`. The arbitrary-server-side-script capability is preserved as a first-class tool, but it lives in a **scoped application** with its own custom role and a REST_Endpoint ACL. The boundary is the **role + REST_Endpoint ACL + audit log + kill switch**, not a lowered capability ceiling.

**Scoped app `x_mcp` ships:**

| Artifact | Purpose |
|---|---|
| Role `x_mcp.executor` | The only role allowed to hit the executor endpoint. **May create (and close) its own audit row; cannot read/alter other rows, change properties, or grant roles.** |
| Scripted REST resource `x_mcp/executor/run` (POST) | The sole entrypoint for arbitrary scripts; reachable **only** via `runServerScript()` (§3.2). |
| ACL of type `REST_Endpoint` on that resource | Replaces `Scripted REST External Default`; requires `x_mcp.executor`. |
| Table ACLs on `x_mcp_audit_log` | read/write → `x_mcp.admin` only; the executor user cannot read or alter rows via Table API. |
| Script Include `x_mcp_verify` | HMAC-verifies the signed actor (current + previous key) + freshness + nonce (§2.0). |
| Audit table `x_mcp_audit_log` | Per request: **MCP actor + ServiceNow effective user + `actor_verified` + `request_id`**, code SHA-256, byte length, `started_at`, duration, status, output size, error class. **No script body, no raw output.** |
| Table `x_mcp_nonce` | Actor-replay defense: seen nonces within the freshness window; TTL-pruned by a scheduled job. |
| Role `x_mcp.admin` | Manages `x_mcp_audit_log`, the kill switch, role assignments (separation of duty). **Not the integration user.** |
| Property `x_mcp.executor.enabled` (bool) | Kill switch. 503 when false. |
| Property `x_mcp.executor.run_server_script_enabled` (bool) | Tenant **egress** toggle for the executor specifically (§11). |
| Property `x_mcp.executor.max_bytes` (int) | **UTF-8 byte** cap on the script, enforced before evaluation. |
| Property `x_mcp.executor.max_output_bytes` (int) | Output cap; over-cap returns a `result_sample`, never a parsed truncation. |
| Property `x_mcp.executor.timeout_ms` (int) | A client-visible budget, **not** a hard abort. |
| Properties `x_mcp.executor.hmac_secret` / `…_prev` | Actor-signature keys (current + previous, for rotation). |

There is deliberately **no `allow_unsafe` property** in v1 (§Phase 5.3): a knob that may not actually prevent global `GlideRecord` access is worse than no knob. Reintroduce only if Phase 1.8 proves on the target family that it genuinely constrains the environment.

**The corrected resource script** — synchronous; audit-first **and fail-closed**; **verifies** the signed actor; UTF-8 byte cap; **safe** serialization:

```javascript
// x_mcp/executor/run  (Scripted REST resource, scoped app x_mcp, role-gated by REST_Endpoint ACL)
// v4: SYNCHRONOUS; audit-FIRST + fail-closed; VERIFIES the signed actor; UTF-8 byte cap; SAFE serialize.

// Correct UTF-8 byte length (incl. surrogate pairs) — 'max_bytes' must mean bytes, not code units.
function utf8Len(s){ var n=0; for (var i=0;i<s.length;i++){ var c=s.charCodeAt(i);
  if (c<0x80) n+=1; else if (c<0x800) n+=2;
  else if (c>=0xD800 && c<=0xDBFF){ n+=4; i++; } else n+=3; } return n; }

(function process(req, res) {
  var body  = req.body.data || {};
  var code  = String(body.script || '');
  var actor = body.actor || {};          // CLAIMED until verified: {mcp_actor_user_id,mcp_actor_email,instance,request_id,issued_at,nonce}
  var sig   = String(body.actor_sig || '');

  // 1) AUDIT-FIRST + FAIL-CLOSED. Record server-known facts and the *claimed* actor as unverified.
  //    (Audit writes touch only THIS request's row; the executor role cannot read/alter other rows.)
  var start = new GlideDateTime();
  var audit = new GlideRecord('x_mcp_audit_log');
  audit.initialize();
  audit.snow_user = gs.getUserID();
  audit.snow_user_name = gs.getUserName();
  audit.mcp_actor_user_id = String(actor.mcp_actor_user_id || '');
  audit.mcp_actor_email   = String(actor.mcp_actor_email || '');
  audit.request_id        = String(actor.request_id || '');
  audit.actor_verified = false;
  audit.code_hash = new GlideDigest().getSHA256Base64(code);
  audit.code_size = utf8Len(code);
  audit.started_at = start;
  audit.status = 'running';
  var auditId = audit.insert();
  if (!auditId) { res.setStatus(500); res.setBody({ error: 'audit_unavailable' }); return; } // fail closed

  // 2) VERIFY the signed actor BEFORE trusting any actor field (§2.0). Fail closed.
  //    x_mcp_verify (proven in Phase 0.13a): recompute script_sha256, rebuild the canonical payload,
  //    HMAC against hmac_secret then hmac_secret_prev, enforce the freshness window, reject replayed nonce.
  if (!new x_mcp.x_mcp_verify().verify(code, actor, sig)) {
    audit.status = 'rejected'; audit.error_class = 'actor_signature_invalid'; audit.update();
    res.setStatus(401); res.setBody({ error: 'actor_signature_invalid', audit_id: auditId + '' }); return;
  }
  audit.actor_verified = true; audit.update();

  // 3) Kill switch, then tenant EGRESS toggle (runServerScript can reach ServiceNow outbound; §11).
  if (gs.getProperty('x_mcp.executor.enabled', 'true') !== 'true') {
    audit.status = 'killed'; audit.update();
    res.setStatus(503); res.setBody({ error: 'executor_disabled', audit_id: auditId + '' }); return;
  }
  if (gs.getProperty('x_mcp.executor.run_server_script_enabled', 'true') !== 'true') {
    audit.status = 'killed'; audit.error_class = 'egress_disabled'; audit.update();
    res.setStatus(503); res.setBody({ error: 'run_server_script_disabled', audit_id: auditId + '' }); return;
  }

  // 4) UTF-8 BYTE size guard (the host enforces this too; defense in depth).
  var maxB = parseInt(gs.getProperty('x_mcp.executor.max_bytes', '32768'), 10);
  var bytes = utf8Len(code);
  if (bytes === 0 || bytes > maxB) {
    audit.status = 'error'; audit.error_class = 'code_size'; audit.update();
    res.setStatus(413); res.setBody({ error: 'code_size', audit_id: auditId + '' }); return;
  }

  // 5) SYNCHRONOUS execution. No async/await (scoped apps default ES2021). Plain GlideRecord
  //    bypasses ACLs server-side (the 'maximum reach'); role + ACL + audit + kill switch +
  //    verified actor are the boundary.
  var result, err = null, status = 'ok';
  try {
    var fn = new Function('gs','GlideRecord','GlideRecordSecure','GlideAggregate','"use strict";\n' + code);
    result = fn(gs, GlideRecord, GlideRecordSecure, GlideAggregate);
  } catch (e) { err = String(e); status = 'error'; }

  // 6) SAFE serialize — catch JSON.stringify failures (circular / GlideRecord-like / too deep).
  var serialized = null;
  try { serialized = JSON.stringify(result === undefined ? null : result); }
  catch (se) { err = err || ('unserializable: ' + String(se)); status = 'error'; serialized = null; }

  var maxOut = parseInt(gs.getProperty('x_mcp.executor.max_output_bytes', '65536'), 10);
  function closeAudit(st, outBytes){ audit.status = st;
    audit.duration = (new GlideDateTime()).getNumericValue() - start.getNumericValue();
    audit.output_size = outBytes; audit.error_class = err ? err.split(':')[0] : ''; audit.update(); }

  // 6a) Over-cap: return a SAMPLE STRING. NEVER JSON.parse a truncated string (it can throw post-audit).
  if (serialized && utf8Len(serialized) > maxOut) {
    if (status === 'ok') status = 'truncated';
    closeAudit(status, utf8Len(serialized));
    res.setStatus(200);
    res.setBody({ ok: !err, result: null, result_sample: serialized.slice(0, maxOut),
                  truncated: true, error: err, audit_id: auditId + '' });
    return;
  }

  // 6b) Under cap: 'serialized' is a COMPLETE JSON string we just produced — safe to parse back.
  closeAudit(status, serialized ? utf8Len(serialized) : 0);
  res.setStatus(err ? 500 : 200);
  res.setBody({ ok: !err, result: (err || serialized == null) ? null : JSON.parse(serialized),
                truncated: false, error: err, audit_id: auditId + '' });
})(request, response);
```

**Notes and limits.**

- **Actor verification is the integrity root and is fail-closed.** `x_mcp_verify` must reject forged, missing, stale, or replayed signatures; the in-scope HMAC mechanism (Script Include / `GlideCertificateEncryption.generateMac` / `com.glide.tokenbased_auth`) is **proven in Phase 0.13a** before this ships. Without it, `body.actor` is attacker-controlled and integration-mode attribution is fiction (B1).
- **Audit-table ACL hardening.** The resource writes only the row it created; `x_mcp.executor` **cannot** read or alter other audit rows, flip properties, or grant roles — those require `x_mcp.admin` (which is not the integration user). The exact same-scope create/close-own-row ACL is proven in Phase 5.1.
- **`runServerScript` is a ServiceNow-side egress channel.** `globalOutbound: null` sandboxes only the Cloudflare Worker; a server-side script can still call ServiceNow outbound APIs, send email/events, or exfiltrate via records. Hence the `run_server_script_enabled` tenant toggle, the mandatory `reason` + approval for `admin_script`, and `docs/SNOW_EGRESS.md` (§11). It is labeled **non-recoverable** (§7.7).
- **`timeout_ms` is a client-visible budget, not a hard timeout.** The kill switch does not abort an already-running script; long-running execution is additionally bounded by ServiceNow transaction limits. Do not claim interruption.
- The **`x_mcp_nonce`** store is pruned by a scheduled job (entries older than the freshness window); size it for peak request volume.
- Scoped apps cannot create global-scope ACLs, but a **REST_Endpoint ACL on a scoped Scripted REST resource lives in the scoped app** and ships in the update set.
- `GlideRecord` inside a scoped-app eval **bypasses ACLs server-side** — documented, intentional, and the basis for "maximum reach."
- **Denied-attempt audit caveat (S8):** an ACL-denied call never runs this script, so it **cannot** write `x_mcp_audit_log`. Observe denials via ServiceNow platform/security/access logs or the outer Cloudflare gateway log. **Do not weaken the ACL** to capture denied rows.
- The **`sys_trigger` row-creation fallback is unsupported/experimental — do not ship it** (Phase 5.8). Point customers at this scoped-app executor and the role matrix (§12).

---

## 11. Threat model

Security threats and their mitigations (distinct from the build-time risk register in §8). The **Test** column names the gate that proves the mitigation (§6 Phase 9).

| # | Threat | Impact | Mitigation | Test |
|---|---|---|---|---|
| T1 | Stolen Cloudflare account / API token | Read encrypted DO storage; redeploy the Worker | Tokens AES-GCM encrypted, versioned AAD-bound envelope, KEK in a Cloudflare secret; Cloudflare Access + IP allow-list on `/admin/*` and the deploy path; rotate keys | S7; Phase 7.8 |
| T2 | Stolen ServiceNow refresh token | Reach the user's surface in ServiceNow | Partition tokens per `(user, instance)` in `TokenStoreDO`; short access-token lifetimes; rotate refresh on every refresh; revoke on logout; fail closed on AAD mismatch | S7 |
| T3 | Prompt-injection makes sandboxed code call `fetch("evil")` | Data exfiltration | `globalOutbound: null` makes `fetch()`/`connect()` throw; no creds in the sandbox `env`, only the typed RPC binding | S1, S2 |
| T4 | LLM-written code mutates records | Unintended writes | Capability is intentional; mitigation is **attributive + recoverable**: every mutating RPC records `(mcp_actor, snow_effective_user, table, sys_id, op, before/after-hash, requestId)` under a **verified** actor; effective-mode gate (§2.0.1) + `ActorPolicy` (§2.12); recovery model (§7.7) | S8, S18 |
| T5 | Sensitive output bleeds into Cloudflare logs / Tail | PII in the observability stream | Redactor denylist fields + token patterns; never log script body or full RPC response; audit stores hashes only | Phase 7.1 |
| T6 | Over-broad role on the integration user | Defeats the role matrix | Role matrix (§12); never reuse a human admin; one-click rotate-executor-role runbook; `x_mcp.executor` decoupled from Table reach | §12 |
| T7 | Schema cache leaks fields across users | Cross-role metadata disclosure | **User-aware** cache key (`userSysId` + `roleHash`, §2.6); short TTL; explicit invalidation; negative test | S6 |
| T8 | Replay of an MCP request or executor call | Duplicated side effects; forged-actor reuse | **Leveled** idempotency in `MutationLedgerDO` (Level-1 replays return the original; Level-2 `indeterminate` retry blocked); executor **nonce** replay rejected | S17, B1; Phase 7.3 |
| T9 | PDI hibernation / reclamation mid-flight | Hangs, half-applied changes | PDIs dev/demo only; `/health` probe; typed `instance_hibernating` instead of hanging | Phase 7.6 |
| T10 | Dynamic Worker pricing (now live) — workers **and** requests **and** CPU | Cost explosion from runaway workers, or one cheap Worker making many RPC/SN calls | **Multi-dimensional atomic reserve-before-load** in `BudgetDO` (workers + RPC + SN requests + rows/bytes); **per-run** caps; daily hard breaker; logged metrics; `get(id)` warm lever (10.2) | S11, S14 |
| T11 | MCP SDK cross-client response leak (CVE) | One client sees another's responses | Construct `McpServer`/transport **per request** (SDK ≥ 1.26.0 guard) | §2.3 |
| T12 | MCP Inspector / endpoint exposed publicly | Anyone invokes `run_code` | Inspector is dev-only; production `/mcp` requires a valid MCP-client token with audience/issuer/scope checked **before** tool invocation | S13 (O8); Phase 7.8 |
| T13 | DNS rebinding via missing Origin validation | Cross-origin invocation | Remote rejects invalid `Origin` (403); local binds to localhost | S12 |
| T14 | OAuth flow abuse (redirect / state / PKCE / consent) | Confused-deputy, token theft | Exact `redirect_uri` match, state/nonce, PKCE `S256`, consent cannot be skipped via cached upstream auth; full negative suite | S13 (O1–O10) |
| T15 | **Forged actor metadata** (a caller fabricates `body.actor`) | False attribution; accountability bypass | Host **HMAC-signs**; executor **verifies** (freshness + nonce, fail-closed); `actor_verified` audited | B1; S8 |
| T16 | **Mode escalation** via the `mode` tool input | Unauthorized writes / arbitrary script | `effectiveMode = min(requested, scope, tenant, instance)` (requested only narrows); `admin_script` needs allowlist + approval | B3, B4; §2.0.1 |
| T17 | **`integration_user` over-reads** for a given user | Confidential data disclosure (audit ≠ access control) | `ActorPolicy` (instances/tables/fields/rows) enforced before every RPC; or `per_user_oauth` | B5; §2.12 |
| T18 | **`scriptedRest` bypasses `runServerScript()`** | Ungated/unaudited executor reach; config/audit tampering | Explicit path denylist (executor, `sys_properties`, audit log, `oauth_*.do`, `login.do`); executor reachable only via `runServerScript()` | B2; §3.2 |
| T19 | **ServiceNow-side egress** via `runServerScript` | Server-side script calls SN outbound / email / events / records | Tenant `run_server_script_enabled` toggle; `reason` + approval for `admin_script`; best-effort outbound-API denylist scan; separate executor budget; labeled non-recoverable | §5.7; `SNOW_EGRESS.md` |
| T20 | **Recovery snapshot store** becomes a second sensitive DB | New PII exposure / over-retention | Retention window + `SNAPSHOT_KEK` encryption + access control + scheduled purge + PII classification + tenant opt-out | S18; `RETENTION.md` |

**ServiceNow-side egress (T19) deserves its own emphasis.** `globalOutbound: null` is a *Cloudflare-side* control; it says nothing about what a server-side script does **inside** ServiceNow. Treat `runServerScript` as an egress-capable primitive: it can reach `RESTMessageV2`/outbound integrations, fire events, send email, or move data between records. The controls are organizational and tenant-scoped (toggle, approval, denylist scan, budget, non-recoverable labeling), documented in `docs/SNOW_EGRESS.md` — not a sandbox.

---

## 12. Role matrix — maximum access via explicit, attributable roles

The goal is **maximum reach with attribution**, not least-privilege-at-all-costs. Reach stays high; what changes is that it travels via a **named identity with an inspectable role footprint**, not a shared `admin` login. This is the starting matrix Phase 6 writes into `docs/ROLE_MATRIX.md`; which column applies depends on the credential mode (Decision 2, §2.0).

| Identity / Role | Where | What it grants | Why |
|---|---|---|---|
| `mcp_integration_user` (integration_user mode) | ServiceNow `sys_user` | Roles: `rest_api_explorer`, `itil`, `sn_customerservice_agent`, `import_transformer`, `snc_platform_rest_api_access`, plus read ACLs on `sys_db_object` / `sys_dictionary` / `sys_glide_object` | Primary integration identity. High aggregate access via well-known roles, not literal admin. Revocable. |
| `x_mcp.executor` (custom role, scoped app) | ServiceNow scoped app | Required by the executor REST_Endpoint ACL. **Can invoke the endpoint and create/close its own audit row; cannot read or alter other audit rows, change properties, or grant roles.** | Decouples "can run arbitrary script" from "can hit Table API." Revoke this one role to kill executor reach without touching other capabilities. |
| `x_mcp.admin` (custom role, scoped app) | ServiceNow scoped app | Manages `x_mcp_audit_log` (read/write), the kill-switch and egress properties, role assignments. **Should not be the integration user.** | Separation of duty: the executor identity cannot read the audit trail, turn it off, or flip the kill switch. |
| Cloudflare deploy identity | Cloudflare account | wrangler / Alchemy IaC permissions | Per-engineer scoped tokens; rotate. |
| MCP-client OAuth identity (per end user) | Cloudflare (OAuthProvider storage) | Maps the end user → signed actor metadata (§2.0); in `per_user_oauth` mode, → that user's ServiceNow tokens | Per-user attribution propagates into `x_mcp_audit_log`. |

**Credential-mode branch (Decision 2, §2.0).**

- **`integration_user` (single-operator default):** the broad role set above applies to `mcp_integration_user`. **Host-side actor attribution is mandatory and signed-and-verified** (§2.0) — ServiceNow-side audit shows the service identity, so the MCP actor must be recorded (and verified) alongside it. **In multi-user deployments this mode additionally requires the `ActorPolicy` layer (§2.12) enforced before every RPC**, because the broad identity otherwise lets any MCP user read anything; attribution alone does not bound access.
- **`per_user_oauth` (multi-user default):** the matrix applies to the human users/groups; ACLs bound access naturally and attribution is native (ServiceNow sees the real user). "Maximum access" then depends on each human's roles.
- **Reversible elevation:** if a tenant wants even higher reach (e.g., write system tables in global scope), grant `admin` to `mcp_integration_user` **explicitly and document it** — the matrix makes the elevation visible and reversible rather than implicit.

---

## 13. Per-API prerequisites & PDI notes

**Per-API prerequisites** (the roles/plugins and gotchas each `ServiceNowRPC` method depends on; build Phase 3 against this):

| API | Path | Roles / plugins | Gotchas |
|---|---|---|---|
| Table API | `/api/now/table/{table}` | Read/write ACLs on the table; `snc_platform_rest_api_access` if strict REST security is on | `sysparm_limit` default is **10000** (we impose a **host-side cap of 1000**); the limit applies **before ACL evaluation** → pages can be empty after filtering (cursor strategy in §2.13); `display_value` triples response size; set `sysparm_exclude_reference_link=true` |
| Aggregate API | `/api/now/stats/{table}` | Read access | Server-side `sysparm_count` / `sysparm_group_by` / `sysparm_avg_fields`; cheaper than client-side counting |
| Attachment API | `/api/now/attachment` | Read ACL on the parent record; 1024 MB default upload cap | Stream; never buffer base64 in Worker memory (Phase 3.3) |
| Import Set API | `/api/now/import/{staging}` (and `/insertMultiple`) | `import_transformer` (or explicit write ACL); `snc_platform_rest_api_access` | Staging extends `sys_import_set_row`; user fields are `u_*` unless scoped |
| CMDB Instance API | `/api/now/cmdb/instance/{class}/{sys_id}` | `itil` typical; **one record per call** | Class hierarchy under `cmdb_ci`; relationships are separate calls |
| Knowledge Mgmt API | `/api/sn_km_api/knowledge/articles` | KB user-criteria + read ACL on `kb_knowledge`; some content needs `itil` | Honors KB ACLs strictly; counts differ between admin and integration user |
| Service Catalog API | `/api/sn_sc/servicecatalog/*` | Catalog roles for variables | Three calls (`add_to_cart` → `checkout` → `submit_order`), or `order_now` in one; references need `sys_id` |
| Scripted REST | `/api/{scope}/{api}/{resource}` | Whatever the resource's REST_Endpoint ACL requires; for `x_mcp.executor.run` → `x_mcp.executor` | Default ACL is `snc_internal` — override it; `GlideRecord` bypasses ACLs server-side; generic `scriptedRest` is **denylisted** from the executor + `sys_properties` + audit-log + `oauth_*.do` + `login.do` (§3.2) |

**PDI notes (dev/demo only).** Personal Developer Instances hibernate after ~6h of inactivity (~30 min if woken without logging in) and are **reclaimed after 10 days of Developer-Portal inactivity — creating records or changing data does NOT reset the 10-day timer** (it tracks portal activity like config/update-set changes). Therefore: never point staging or any pre-prod at a PDI; ship **no** cron-style keepalive (against Developer Program policy) — a `/health` tool returning `{ instance: "hibernating" | "online" }` is the supported pattern; and the **GA evidence base must be a sub-production instance, not a PDI** (§7).

---

## 14. Changelog (v2 → v3)

These are the design corrections that produced the current ("execution-safe") revision; the `P#` codes are referenced from the phases and the risk register.

| P# | Review blocker | Disposition |
|---|---|---|
| P0 | ServiceNow identity model ambiguous | **Accepted.** §2.0 credential mode (`integration_user` default + signed actor attribution; `per_user_oauth` supported); Phase 1.2; Phase 6 branches; audit records both identities. |
| P1 | Permissive run_code default too risky | **Accepted (reverses v2).** Default `read_only`; **enforced** mode→capability map (§3.5); one-line override documented; **confirm or override** (§0.9 Decision 1). |
| P2 | Executor denied-attempt audit impossible | **Accepted.** ACL-denied observed via platform/gateway log, not `x_mcp_audit_log`; ACL not weakened; only allowed + kill-switch-blocked write app audit rows (Phase 1.8, 5.4, S8). |
| P3 | Budget/token storage in a vague session DO | **Accepted.** Split into `AuthCorrelationDO`/`TokenStoreDO`/`BudgetDO`/`MutationLedgerDO` (§2.10); Phase 0.12 partition proof. |
| P4 | Non-atomic global budget | **Accepted.** Atomic reserve-before-load; global counter in a single date-keyed object (§2.5, Phase 4.5, S14). |
| P5 | Missing MCP Origin validation | **Accepted.** §Decision/§3.1; Phase 7.4; S12. |
| P6 | Under-specified OAuth security tests | **Accepted.** S13 (O1–O10). |
| P7 | Compat date + run_code shape inconsistent | **Accepted.** Single compat date everywhere (§2.9); **TS pipeline corrected to esbuild-wasm transform→string with the executor** (§2.2, §3.4); ADR-0001 fixes one shape; worker-bundler demoted to fallback. |
| P8 | Scoped-app cross-scope unproven | **Accepted.** Phase 1.8/5 cross-scope tests incl. clean-instance re-test; S16. |
| P9 | `runServerScript` idempotency overstated | **Accepted.** Leveled idempotency (L1/L2/L3); `indeterminate` retry blocked (§7.3, S17). |
| P10 | "Recoverable" lacks rollback design | **Accepted.** Recovery model (§7.7, `docs/RECOVERY.md`); claim narrowed where snapshots absent; S18. |
| — | `allow_unsafe` not enforceable | **Accepted.** Removed from v1 unless proven on the target family (Phase 5.3). |
| — | Origin/redaction/port/estimates | **Accepted.** Minimal redactor moved to Phase 4; port unified to 8787 (`--port 8787`); Phase 1 re-estimated (5–6 days, may split). |

---

## 15. Changelog (v3 → v4, "authorization-hardened")

The fourth review approved Phase 0 but blocked Phase 1/4/5 because several properties were *claimed* but not yet *made true*. Dispositions (B# = bypass-test gates, §9):

| # | Review blocker | Disposition |
|---|---|---|
| 1 | Actor metadata claimed "signed" but the executor never verified it | **Accepted.** Host HMAC-signs a canonical `{actor, script_sha256, issued_at, nonce, …}`; the executor **verifies** (current+prev key, freshness, nonce replay), fail-closed; `actor_verified` audited (§2.0, §10, Phase 0.13a/5.4a; **B1**). |
| 2 | `mode` not an authorization boundary (client could request `admin_script`) | **Accepted.** `effectiveMode = min(requested, OAuth-scope, tenant, instance)`; scopes `servicenow:read|write|admin_script`; `admin_script` needs allowlist + approval; requested mode only narrows (§2.0.1, §3.5; **B3/B4**). |
| 3 | `integration_user` read-confidentiality (audit ≠ access control) | **Accepted.** `ActorPolicy` (instances/tables/fields/rows/bytes/mode) enforced before every RPC; `per_user_oauth` is the multi-user default unless ActorPolicy is implemented (§2.12, §0.9 Decision 2; **B5**). |
| 4 | Executor serialization can crash after the audit update | **Accepted.** Never `JSON.parse` a truncated string — return `result_sample`; wrap `JSON.stringify` in try/catch (circular/GlideRecord-like/deep) (§10; **B6**). |
| 5 | Table API pagination conflicts with documented behavior | **Accepted.** Default is **10000** (host cap 1000); `sysparm_limit` applies **before** ACL → empty pages; explicit per-mode cursor strategy chosen now, not in Phase 3 (§2.13; **B7**). |
| 6 | Raw `scriptedRest` could bypass `runServerScript()` | **Accepted.** Explicit denylist (executor paths, `sys_properties`, audit log, `oauth_*.do`, `login.do`); executor reachable only via `runServerScript()` (§3.2; **B2**). |
| 7 | Budget covered unique Workers but not requests/CPU/scarce resources | **Accepted.** Multi-dimensional budgets (unique Workers + RPC + SN requests + rows/bytes), per-run + daily (§2.5; S11/S14). |
| 8 | ServiceNow refresh-token assumptions unproven | **Accepted.** Confidential client (Auth Code + PKCE + secret); refresh return/rotate/revoke proof gate (§2.8; **B9**). |
| 9 | `OAUTH_KV` missing from infrastructure | **Accepted.** First-class binding in Alchemy/wrangler/.dev.vars; isolated from `TokenStoreDO`; missing → fail (§2.4, §2.11; **B8**). |
| 10 | esbuild "transform + zod import" internally inconsistent | **Accepted.** Phase 0.8 split into 0.8a (no-import transform) / 0.8b (bundle-or-`modules`); type-check consequence made actionable in ADR-0001 (§Phase 0.8). |
| + | Human approval for destructive ops | **Accepted.** `admin_script`/delete/broad-import/attachment-write require allowlist + approval (Access-group / token / dry-run; elicitation in stateful variant) (§3.5, Phase 7.9). |
| + | `runServerScript` is a ServiceNow-side egress channel | **Accepted.** Tenant toggle, approval, best-effort denylist scan, separate budget, non-recoverable labeling (§11 T19, §5.7, `SNOW_EGRESS.md`). |
| + | Audit/snapshot retention unspecified | **Accepted.** `RETENTION.md`: retention, `SNAPSHOT_KEK` encryption, decrypt access, purge, PII class, tenant opt-out (§7.7). |
| + | Audit table not hardened | **Accepted.** `x_mcp.executor` creates/closes only its own row; `x_mcp.admin` (not the integration user) reads/manages; audit-insert fail-closed (§10, §12, Phase 5.1). |
| + | Nits | **Accepted.** `max_bytes` now means **UTF-8 bytes** (`utf8Len`); Table API limit corrected to 10000/host-cap-1000; MCP Server Console comparison kept as a living `DELTAS.md` note; pre-1.0 SDK exit retained in the GA gate. |
