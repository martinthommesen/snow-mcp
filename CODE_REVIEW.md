# Code Review — ServiceNow Code Mode MCP Server

**Date:** 2026-05-31
**Reviewer:** Claude (full-codebase security review)
**Commit:** none — reviewed the working tree (no remote/commits exist yet)

## What this is

A stateless Cloudflare Worker exposing three MCP tools (`run_code`, `describe_table`,
`list_tables`). The thesis is *"maximum access, achieved safely"*: the model authors
TypeScript, which is transpiled (esbuild-wasm) and run in a per-call Worker Loader sandbox
with **no network, no credentials** (`globalOutbound: null`); the credential is injected
host-side and the sandbox sees only a typed `servicenow.*` RPC surface. Safety rests on
layered host-side controls (effective-mode cap, ActorPolicy, capability gate, per-run
budget, HMAC-signed actor verified by a ServiceNow scoped-app executor) plus a documented
threat model (T1–T20, B1–B9).

## Scope & verification

- **Deep-read:** all of `src/` (auth, authz, sandbox, sn, do, observability, recovery,
  cache, tools, config, server, index), the ServiceNow executor app (`sn-executor-app/`),
  `alchemy.run.ts`, `wrangler.jsonc`, the stdio shim, and `test/run-code-pipeline.test.ts`.
- **Characterized but not line-read:** the other 17 test files and 7 dev scripts (scanned
  for secret-logging — clean; dev harnesses log only presence booleans / HMAC outputs, not
  keys).
- **Tests run:** `npm test` → **105 passed, 18 files, exit 0** (`@cloudflare/vitest-pool-workers`,
  ~27s). README says 99; the suite has grown. `tsc -b` was not separately run.

> **Framing:** the threat model's "✅" means *module implemented + unit-tested* — which is
> **true**. The core finding here is narrower: several of these modules **are never invoked
> by the request path**, so the deployed Worker does not actually enforce them.

## What's strong

- **Crypto is correct** (`packages/mcp-server/src/auth/crypto.ts`): AES-256-GCM, fresh
  12-byte CSPRNG IV per seal, AAD double-bound (pre-check + GCM `additionalData`),
  fail-closed on mismatch, 32-byte KEK enforcement, current+previous rotation window.
- **Sandbox isolation holds** (`sandbox/executor.ts`): only provider fns cross into the
  sandbox — never `env`, a token, or a Fetcher. The HMAC key is correctly base64-**decoded**
  to raw bytes (`tools/handlers.ts:40`) to match `GlideCertificateEncryption`.
- **Enforcement order is real and tested** in the wired read/write path (`sn/rpc.ts:56`):
  ActorPolicy → capability → budget, with field-masking on read responses.
- **Honest docs.** `OPEN_QUESTIONS.md` / `DELTAS.md` are unusually disciplined about
  verified-local vs blocked-external.

---

## Findings

### 🔴 High (active) — the `admin_script`/mutation path is missing its own safety layers

On the live, OAuth-gated path, an `admin_script` `run_code` → `servicenow.runServerScript(...)`
is gated only by **OAuth scope + a non-empty `reason` + HMAC signing** (`tools/run_code.ts:62`).
Three controls the design treats as part of the safety thesis are implemented, unit-tested,
and **wired to nothing**:

- **§7.9 second-approval gate** — `assertAdminScriptApproved` (`authz/approval.ts:30`) has
  **no caller**. The interactive dry-run→approve flow genuinely can't run statelessly (the
  docstring says so) — but the same function's **non-interactive token / access-group check
  can be wired statelessly, and isn't**. Net: a client holding `servicenow:admin_script`
  scope gets unlimited admin_script for the session with no per-call gate.
- **Host-side audit (§7.2)** — `emitAudit` / `buildAuditRecord` (`observability/audit.ts:75`)
  is never called; only its *type* is imported (by `recovery/policy.ts`). The deployed
  Worker keeps **no host-side audit trail** of reads, writes, or denials.
- **Idempotency (T8/S17)** — `idempotencyKey` threads through the schema and RPC args but
  `run_code` never forwards it and `MutationLedgerDO` is never consulted (`sn/rpc.ts:115`,
  `sn/rpc.ts:128`); `LEDGER_DO` is exported but never instantiated. A retried mutation is
  **not** deduplicated.

Also unwired (same pattern, lower stakes): the **B2 `scriptedRest` denylist**
(`sn/scripted-rest-denylist.ts:41` — no caller; no `scriptedRest` method exists yet, so
nothing to bypass *today*), **B7 keyset `paginate`** (`sn/pagination.ts:32`), and **§7.7
snapshot capture** (`recovery/snapshots.ts:33`).

**Recommendation:** wire the token/access-group branch of `assertAdminScriptApproved`,
`emitAudit`, and the ledger into `run_code` / `ServiceNowRPC` for the mutating + executor
methods. Plumb the `ApprovalContext` (allowlist, valid tokens, required group) from the
auth props.

### 🔴 High (latent) — unencoded `table`/`sys_id` defeats ActorPolicy table-scoping

`sn/http.ts:56` checks `path.startsWith("/api/")` on the **raw** string, then builds
`new URL(...)`, which normalizes dot-segments. `table`/`sys_id` are interpolated into the
path **unencoded** (`sn/rpc.ts:78`, `sn/rpc.ts:93`, `sn/rpc.ts:120`) — there is **no
`encodeURIComponent` anywhere in `sn/`**. Verified empirically:

```
tableGet({ table:"incident", sys_id:"../sys_user/<id>" })  →  GET /api/now/table/sys_user/<id>
%2e%2e-encoded traversal also passes the startsWith("/api/") guard.
```

`sys_id` is **never policy-checked**, so this bypasses the ActorPolicy table allowlist — the
exact B5/T17 control the docs mandate for multi-user `integration_user` mode.

**Latent, not exploitable today:** the wired policy is `permissivePolicy` (no table
restriction), so there is nothing to bypass yet — but it activates the moment a restrictive
policy ships.

**Fix:** `encodeURIComponent` the path segments (encoding `/`→`%2F`, which the URL parser
does *not* renormalize as a separator — unlike `%2e`), and validate `sys_id` as 32-hex.

### 🟠 Medium

- **Writes aren't field-masked** (latent) — `gateRead` calls `assertRequestedFieldsAllowed`,
  but `tableUpdate` (`sn/rpc.ts:115`) never checks `args.fields` against `fieldMasks`,
  despite the policy doc claiming masks apply to "request AND response." A masked field can
  be written.
- **Per-run row/byte budgets are observability-only** — `RunBudget.countRows` accumulates
  but never enforces a cap, and `bytesReturned` is never incremented (`sn/run-budget.ts:44`).
  `ActorPolicy.maxRowsPerRun` / `maxBytesPerRun` are **dead fields** (set, never read). The
  daily reserve only sends `{uniqueWorkers:1}` (`tools/handlers.ts:74`), so daily
  row/request/byte caps aren't enforced either.
- **Only `scopeMaxMode` is a live ceiling** — `tenantMaxMode` / `instanceMaxMode` are
  hardcoded to `admin_script` (`tools/handlers.ts:98`), so the OAuth scope is the sole cap.
  Reasonable for single-operator, but two of three documented ceilings are no-ops.
- **OAuth consent re-parses request params from a client-controlled hidden field** on POST
  (`JSON.parse(form.get("oauth"))`, `auth/servicenow-auth-handler.ts:94`) rather than
  server-side state — granted scope can differ from what was displayed/validated at GET.
  Bounded by the single-operator secret model; prefer binding to signed state.
- **`allowLocalhost: true` is hardcoded in production** (`index.ts:38`) — any
  `http://localhost` Origin passes. Should be env-gated to dev only.
- **Raw ServiceNow error messages flow to the client** unredacted (`sn/errors.ts:62`);
  `redactValue` is wired **only** into the (unwired) audit sink, so redaction protects
  nothing on the live response/log path.

### 🟡 Low

- **`MutationLedgerDO.begin`** does `get`→`put` across an await **without** the promise-chain
  mutex that `BudgetDO` uses for the identical read-check-write pattern (`do/budget.ts:44`
  vs `do/mutation-ledger.ts:35`). DO input-gate semantics make this nuanced and it's unwired
  — a **consistency** gap, not a confirmed race.
- **`roleHash` is hardcoded `"default"`** in the cache wiring (`tools/handlers.ts:115`); the
  `roleHash()` helper (`cache/schema.ts:59`) is unused, so the role-change cache-bust the S6
  doc promises isn't active. (Cross-*user* leakage is still prevented via `userId`.)
- **BudgetDO is keyed by date only** (`idFromName(utcDateKey())`) → the daily cap is global
  across all users; in multi-user mode one client can exhaust the day's worker budget for
  everyone. Intentional as a *global* cap, but shared-fate.
- **`alchemy.run.ts:33`** falls back to `"dev-state-password-change-me"` for Alchemy state
  encryption when `OAUTH_PROVIDER_SECRET` is unset, while the Worker secrets below correctly
  fail closed via `reqEnv`. Make the state password fail closed too.
- **`wrangler.jsonc:20`** commits KV namespace IDs — not secrets, and documented as
  placeholders, but worth a note if any are real prod IDs.

### ServiceNow-side executor (source-only, unverified — `sn-executor-app/`)

Real code issues on the admittedly-unverified executor:

- **Nonce replay is check-then-insert** (`script-include/x_mcp_verify.js:97`) — safe only if
  `x_mcp_nonce.value` has a **unique DB index** (not defined in this source); otherwise
  concurrent identical requests race. T8 was verified *sequentially*. No purge job for the
  nonce table either.
- **Size guard runs after nonce consumption** (`scripted-rest/x_mcp.executor.run.js:45` vs
  `:64`) — an oversized but validly-signed call burns its nonce before the 413.
- **`result_sample` slices by code units against a byte cap**
  (`scripted-rest/x_mcp.executor.run.js:94`) — minor; the careful `utf8Len` is used
  everywhere else.
- The **`GlideDigest.getSHA256Base64` UTF-8 input encoding** for `script_sha256` remains the
  documented **0.13a** open seam — the host uses `TextEncoder` (UTF-8); if SN hashes
  UTF-16/Latin-1, non-ASCII scripts break signatures. (The canonical-payload HMAC is
  engine-safe by the ASCII-only encoder — that part is sound.)

---

## Bottom line

Genuinely well-engineered and honestly documented, with correct crypto and real isolation.
The gap between **"module implemented + tested"** and **"invoked by the deployed request
path"** is the theme: the safety thesis leans on second-approval, audit, and idempotency
that the live `admin_script` path doesn't currently call, and the ActorPolicy table-scoping
is bypassable via unencoded `sys_id` the moment a restrictive policy is configured. None of
this is exploitable in the *current* single-operator / permissive-policy deployment, but all
of it must close before the multi-user `integration_user` mode the docs describe.

### Suggested order of fixes

1. `encodeURIComponent` + 32-hex `sys_id` validation in `sn/rpc.ts` (smallest, closes the
   latent ActorPolicy bypass). Write a failing traversal test first.
2. Wire `emitAudit` into the mutating/executor path (no audit trail today).
3. Wire the token/access-group branch of `assertAdminScriptApproved` into `run_code`.
4. Wire the idempotency ledger; mask write fields in `tableUpdate`.
5. Enforce (don't just count) per-run row/byte budgets; env-gate `allowLocalhost`.

---

## Codex addendum — 2026-05-31

**Reviewer:** Codex, full-repository security/code review pass.
**Method:** Source review of the Worker, MCP tool wiring, ServiceNow executor sources, Fluent package,
tests, scripts, and docs; then local verification. This addendum validates the prior review rather
than replacing it.

### Updated findings

#### 🔴 High — multi-user ServiceNow OAuth is not actually wired end-to-end

The Cloudflare MCP-client OAuth layer can identify an MCP user, but the ServiceNow token path is
still shared-credential/bootstrap-only. `buildHandlers` constructs `TokenStore` per
`userId|instanceHost`, but `getServiceNowBearer()` can only reuse an already-populated token or mint
one with the configured ROPC username/password (`packages/mcp-server/src/tools/handlers.ts:73`,
`packages/mcp-server/src/auth/servicenow-oauth.ts:55`, `packages/mcp-server/src/auth/servicenow-oauth.ts:71`).
There is no ServiceNow authorization-code callback that populates `TokenStoreDO` with each human's
own token, and `docs/OPEN_QUESTIONS.md:65` still records this as remaining work.

Impact: a multi-user deployment must still be treated as `integration_user`/shared-credential mode.
ServiceNow native ACLs do not bound individual MCP users, and the current `permissivePolicy` wiring
(`packages/mcp-server/src/tools/handlers.ts:66`) leaves host-side table scoping effectively open.

#### 🔴 High — the prior `admin_script` safety-layer finding still stands

Rechecked call sites: `assertAdminScriptApproved`, `emitAudit`, `MutationLedgerDO`, and recovery
snapshots are implemented/tested modules, but they are not invoked by the live `run_code` path.
`runCode()` enforces only effective mode and non-empty `reason` for `admin_script`
(`packages/mcp-server/src/tools/run_code.ts:50`, `packages/mcp-server/src/tools/run_code.ts:61`),
and `ServiceNowRPC.runServerScript()` signs and posts the actor without consulting the approval gate,
host audit, idempotency ledger, or snapshot/recovery policy
(`packages/mcp-server/src/sn/rpc.ts:128`, `packages/mcp-server/src/sn/rpc.ts:143`).

This remains the central gap between the design's safety thesis and the deployed request path.

#### 🔴 High (latent) — unencoded table/sys_id path traversal still stands

The previous path-segment finding is still valid. `table`, `sys_id`, and stats table names are
interpolated directly into ServiceNow REST paths (`packages/mcp-server/src/sn/rpc.ts:78`,
`packages/mcp-server/src/sn/rpc.ts:93`, `packages/mcp-server/src/sn/rpc.ts:108`,
`packages/mcp-server/src/sn/rpc.ts:120`), while `SnFetchClient` checks the raw path and then lets
`new URL()` normalize it (`packages/mcp-server/src/sn/http.ts:56`,
`packages/mcp-server/src/sn/http.ts:59`). This can defeat future restrictive
ActorPolicy table scoping if `sys_id` contains dot-segment traversal. Fix path encoding and validate
`sys_id` as a 32-hex identifier before adding multi-user ActorPolicy allowlists.

#### 🟠 Medium — the default test command is now red

`npm test` currently fails even though the underlying tests pass with a larger timeout:

- `npm test` -> **failed**: 104 passed, 4 timed out after 5000 ms.
- `npx vitest run --testTimeout=20000` -> **passed**: 108 passed, 19 files.

The failing default tests are Durable Object/token-store timeout cases in
`packages/mcp-server/test/do-partition.test.ts` and `packages/mcp-server/test/token-store.test.ts`.
Until `package.json` or Vitest config carries a realistic timeout, the advertised verification path
is not reproducible.

#### 🟠 Medium — Fluent scoped-app source does not yet enforce all role/audit claims

The Fluent app creates `x_mcp.executor`, `x_mcp.admin`, the audit/nonce tables, and a REST endpoint
ACL (`sn-executor-app/fluent/src/fluent/x_mcp.now.ts:15`,
`sn-executor-app/fluent/src/fluent/x_mcp.now.ts:27`,
`sn-executor-app/fluent/src/fluent/x_mcp.now.ts:48`,
`sn-executor-app/fluent/src/fluent/x_mcp.now.ts:69`,
`sn-executor-app/fluent/src/fluent/x_mcp.now.ts:80`), but I did
not find Fluent ACLs that restrict `x_mcp_audit_log`/properties to `x_mcp.admin`, nor a unique index
or purge job for `x_mcp_nonce`. The hand-authored update-set scaffold describes those controls
(`sn-executor-app/update-set/x_mcp.xml:22`, `sn-executor-app/update-set/x_mcp.xml:53`), but the buildable Fluent source does not yet
materialize them.

`npm run build` in `sn-executor-app/fluent` also warns that all executor property names should begin
with the generated app prefix `x_1793136_mcp.` (`sn-executor-app/fluent/src/fluent/x_mcp.now.ts:101`).
The executor scripts currently read `x_mcp.executor.*`, so packaging should settle this naming
contract before relying on the kill switch and byte caps.

#### 🟠 Medium — Fluent toolchain has audit findings

Root package audit is clean, but the Fluent package is not:

- `npm audit --audit-level=moderate` in `sn-executor-app/fluent` -> **15 vulnerabilities**
  (3 low, 11 moderate, 1 high).
- Notable chains: `tmp <=0.2.5` via `@inquirer/prompts`, `@fastify/static` path traversal via
  `@servicenow/sdk`, and `js-yaml <3.14.2` via `xmlbuilder2`.

These appear to be dev/build-tooling risk rather than deployed Worker runtime risk, but this repo
uses the Fluent SDK to generate ServiceNow metadata, so it still belongs in the release checklist.

#### 🟡 Low — documentation status drift can mislead security decisions

Several docs now disagree with each other and with source. Examples: `docs/OPEN_QUESTIONS.md` says
host audit, B7 pagination, and executor proof are done, while the live Worker path still does not
call host audit/pagination and `docs/SNOW_EGRESS.md` still describes the executor as source-only.
Treat docs as evidence only after checking the call graph.

### Verification run

- `npm run typecheck` -> passed.
- `npm test` -> failed: 104 passed, 4 timed out at the default 5000 ms.
- `npx vitest run packages/mcp-server/test/do-partition.test.ts packages/mcp-server/test/token-store.test.ts --testTimeout=20000` -> passed, 14 tests.
- `npx vitest run --testTimeout=20000` -> passed, 108 tests, 19 files.
- `npm audit --omit=dev --audit-level=moderate` at repo root -> 0 vulnerabilities.
- `npm audit --audit-level=moderate` at repo root -> 0 vulnerabilities.
- `npm run build` in `sn-executor-app/fluent` -> passed with five property-name warnings.
- `npm audit --audit-level=moderate` in `sn-executor-app/fluent` -> failed, 15 vulnerabilities.

### Revised priority order

1. Make the default test command green (`testTimeout` or targeted per-test timeouts) so review
   evidence is reproducible.
2. Encode path segments and validate `sys_id` in `ServiceNowRPC`.
3. Wire `assertAdminScriptApproved`, host `emitAudit`, and `MutationLedgerDO` into mutating and
   executor calls.
4. Decide and implement the credential mode honestly: real per-user ServiceNow OAuth, or explicit
   shared `integration_user` plus restrictive ActorPolicy.
5. Complete Fluent scoped-app hardening: audit/property ACLs, nonce uniqueness/purge, and property
   naming consistency.

---

## Codex addendum — 2026-05-31 full-codebase pass

**Reviewer:** Codex.
**Scope:** source, tests, scripts, ServiceNow executor app, Fluent app metadata, package/config
surfaces, and docs. Generated `dist/`, `node_modules/`, `.alchemy/out`, and real `.dev.vars`
secrets were not reviewed as source of truth.
**Scale reviewed:** 83 source/test/script/app files plus docs, about 15k lines excluding
generated dependency output.

### Current verification

- `npm run typecheck` -> **passed**.
- `npm test` -> **passed**: 108 tests, 19 files. This supersedes the earlier red default-test note.
- `npm audit --audit-level=moderate` at repo root -> **passed**, 0 vulnerabilities.
- `npm audit --audit-level=moderate` in `sn-executor-app/fluent` -> **failed**, 15 vulnerabilities
  (3 low, 11 moderate, 1 high; notably `tmp <=0.2.5`, `@fastify/static`, `js-yaml`).
- `npm run build` in `sn-executor-app/fluent` -> **failed**. `now-sdk build` reports TS307
  unsupported Node global usage at `src/server/x_mcp_executor.js:44:14`, caused by
  `new global.x_mcp_verify()`, plus the existing five property-name warnings for
  `x_mcp.executor.*`.
- Complexity scanner was run over the full repo and then source roots only. Full-repo output was
  dominated by generated `.alchemy/out` findings. Source-root findings were mostly small bounded
  policy/helper loops and one-off verification-script ServiceNow calls; no confirmed product hot
  path needs an algorithmic rewrite before the security/correctness blockers below.

### High findings

1. **The sandbox RPC boundary still trusts TypeScript types that are not enforced at runtime.**
   `transpileTs()` explicitly does not type-check, and `ServiceNowRPC.fns()` casts sandbox-provided
   `unknown` values straight into typed argument objects. That makes `table`, `sys_id`, `limit`,
   `fields`, `idempotencyKey`, and update bodies an unvalidated trust boundary. The previously
   noted unencoded `table`/`sys_id` traversal is one concrete symptom; negative/NaN/string limits
   and malformed field arrays are the same class of bug.

   **Files:** `packages/mcp-server/src/sandbox/transpile.ts:4`,
   `packages/mcp-server/src/sn/rpc.ts:66`, `packages/mcp-server/src/sn/rpc.ts:78`,
   `packages/mcp-server/src/sn/rpc.ts:93`, `packages/mcp-server/src/sn/rpc.ts:120`,
   `packages/mcp-server/src/sn/rpc.ts:167`.

   **Recommendation:** add runtime schemas at the provider boundary before each RPC method runs:
   table name allowlist regex, 32-hex `sys_id`, integer `limit` clamped to `1..TABLE_PAGE_CAP`,
   field-name validation, required idempotency keys for mutations, and byte caps where relevant.
   Then encode path segments with `encodeURIComponent`.

2. **The production Fluent scoped-app build is currently red.**
   The role-gated scoped executor cannot be packaged from `sn-executor-app/fluent` today because
   `now-sdk build` rejects `global.x_mcp_verify()` as unsupported Node global API usage. This blocks
   the production S8 role-ACL path even though the global REST installer/proof may still work.

   **Files:** `sn-executor-app/fluent/src/server/x_mcp_executor.js:44`,
   `sn-executor-app/fluent/src/fluent/x_mcp.now.ts:94`.

   **Recommendation:** make the Fluent package self-contained and buildable: define/import the
   verifier through a supported ServiceNow SDK construct, or use the correct ServiceNow global-scope
   reference pattern accepted by now-sdk. Align executor property names with the generated app scope
   or document and suppress the warning with a deliberate SDK-supported pattern.

3. **The live `admin_script` path still bypasses implemented safety layers.**
   Rechecked this pass: `assertAdminScriptApproved`, host-side `emitAudit`, `MutationLedgerDO`, and
   recovery snapshots remain implemented/tested but unwired from `run_code`/`ServiceNowRPC`. A scoped
   OAuth grant for `servicenow:admin_script` plus a non-empty reason is enough to reach
   `runServerScript`.

   **Files:** `packages/mcp-server/src/tools/run_code.ts:61`,
   `packages/mcp-server/src/sn/rpc.ts:128`, `packages/mcp-server/src/authz/approval.ts:30`,
   `packages/mcp-server/src/observability/audit.ts:75`,
   `packages/mcp-server/src/do/mutation-ledger.ts:35`.

   **Recommendation:** wire second approval, host audit, idempotency, and snapshot/recoverability
   classification into mutating/executor calls before treating `admin_script` as production safe for
   more than a single trusted operator.

### Medium findings

4. **ServiceNow OAuth token requests bypass the instance-host allowlist.**
   Table/API traffic goes through `SnFetchClient`, which canonicalizes and allowlists the instance
   host before attaching credentials. The OAuth token grant path directly posts to
   `https://${cfg.instanceHost}/oauth_token.do` with the client secret and optional ROPC credentials.
   A bad production binding can therefore send secrets to an off-allowlist host before the SSRF guard
   participates.

   **Files:** `packages/mcp-server/src/auth/servicenow-oauth.ts:26`,
   `packages/mcp-server/src/auth/servicenow-oauth.ts:31`,
   `packages/mcp-server/src/tools/handlers.ts:81`,
   `packages/mcp-server/src/sn/url-allowlist.ts:61`.

   **Recommendation:** canonicalize `SNOW_INSTANCE_HOST` once in `buildHandlers` and pass only that
   canonical value to both `SnFetchClient` and ServiceNow OAuth, or have `tokenRequest()` perform the
   same allowlist check before sending secrets.

5. **Output and budget byte caps are not fully byte-enforced.**
   Host serialization checks UTF-8 byte length, but truncates with `json.slice(0, maxBytes)`, which
   slices UTF-16 code units and can exceed the intended byte cap for non-ASCII output. Separately,
   `RunBudget.bytesReturned` is never incremented, and `ActorPolicy.maxRowsPerRun` /
   `maxBytesPerRun` are still dead policy fields.

   **Files:** `packages/mcp-server/src/sandbox/serialize.ts:25`,
   `packages/mcp-server/src/sn/run-budget.ts:17`,
   `packages/mcp-server/src/authz/actor-policy.ts:18`,
   `packages/mcp-server/src/sn/rpc.ts:84`.

   **Recommendation:** add byte-aware truncation, count serialized response bytes, enforce per-actor
   row/byte ceilings, and add tests with multi-byte output.

6. **Per-user ServiceNow OAuth remains a design claim, not an end-to-end implementation.**
   `TokenStore` encryption is solid and tested, but there is still no ServiceNow authorization-code
   callback that stores each human user's ServiceNow tokens. `getServiceNowBearer()` reuses stored
   tokens only if they already exist, otherwise it mints via ROPC when configured.

   **Files:** `packages/mcp-server/src/tools/handlers.ts:73`,
   `packages/mcp-server/src/auth/servicenow-oauth.ts:55`,
   `packages/mcp-server/src/auth/servicenow-oauth.ts:71`.

   **Recommendation:** either finish per-user ServiceNow OAuth wiring, or label the current runtime
   as shared integration-user mode and require restrictive ActorPolicy for multi-user use.

### Low / hygiene findings

7. **Docs and status files disagree with each other and with current verification.**
   Examples: `README.md` still says 99 local tests while the suite is now 108; `docs/THREAT_MODEL.md`
   says OAuth and endpoint protection are not wired; `docs/SNOW_EGRESS.md` says the executor is
   source-only/unverified; `docs/OPEN_QUESTIONS.md` contains both "done" and historical "still
   blocked" sections for the same capabilities. This is now a release-risk issue because the docs are
   used as security evidence.

8. **Several implemented helpers remain unwired or stale.**
   `requireOAuthKv()` is tested but not called by runtime code, `roleHash()` is tested but schema
   cache wiring hardcodes `"default"`, `checkScriptedRestPath()` has no caller because there is no
   generic `scriptedRest` method, and `TokenStoreDO` comments still say it must not be used for real
   tokens even though the adapter encrypts before storage.

### Simplification and performance notes

- The core Worker modules are generally small and readable; the complexity worth reducing is not
  algorithmic so much as boundary sprawl. A small set of shared RPC input schemas would simplify
  security review and remove several bespoke casts.
- The three executor variants are drifting: hand-authored reference app, Fluent app, and global
  installer script. Pick one canonical executor source and generate/copy the others from it, or make
  the differences explicit in `DELTAS.md`.
- One-off scripts intentionally perform sequential ServiceNow setup/verification calls. That is
  acceptable for operator tooling; do not optimize them before the product safety path is closed.

### Updated priority order

1. Add runtime validation and path encoding at the sandbox RPC boundary.
2. Make `sn-executor-app/fluent` build green, then rerun Fluent audit/build.
3. Wire `admin_script` approval, host audit, idempotency, and recovery classification into the live
   mutating/executor path.
4. Canonicalize/allowlist the ServiceNow OAuth token endpoint before sending credentials.
5. Enforce real byte/row budgets and byte-safe truncation.
6. Reconcile docs so status claims match source and verification.

---

## Claude addendum — 2026-05-31 (max-effort pass: defects not yet listed)

**Reviewer:** Claude (Opus). Line-by-line read of all of `src/`, the ServiceNow executor sources,
and four parallel gap-finders, plus targeted empirical checks.
**Posture:** I corroborate the consensus findings above — `admin_script` safety layers unwired,
the unencoded-identifier RPC boundary, per-user ServiceNow OAuth not end-to-end (ROPC fallback),
dead byte/row budgets, docs drift, unwired helpers — and do **not** restate them. Below are **only
defects none of the three prior passes listed**, ranked. Convention: *active* = reachable on the
current deployment; *latent* = needs a config/mode the docs describe but that isn't set today.

### 🟠 Medium — NEW

1. **A sandbox snippet can forge the typed error `code` (active).** `parseSandboxError`
   (`sn/errors.ts:46`) lifts a `[[code]]` prefix straight out of the snippet-controlled
   `err.message` into `structuredContent.code` (`tools/run_code.ts:99`), and `m[1] as ErrorCode`
   accepts any `[a-z_]+` with **no membership check**. A `run_code` snippet that does
   `throw new Error("[[reauth_required]] re-authenticate at https://evil/login")` thus sets the
   host-attested error code the design treats as auditable end-to-end (§3.5). Verified against the
   codemode contract: `test/sandbox-contract.test.ts:72` proves a snippet's *raw* thrown message is
   returned verbatim in `.error`. Impact: any consumer that branches on `code` — a re-auth prompt,
   audit classification, downstream automation — is driven by model / prompt-injection-controlled
   output, and bogus non-union codes (`[[not_a_code]]`) pass through silently.
   **Fix:** validate the parsed code against the `ErrorCode` union; only honor `[[…]]` codes the
   host itself produced (tag host-origin via the `McpToolError` path, not free text).

2. **Rotating `TOKEN_KEK` bricks every stored token — the "current+previous rotation window"
   credited in *What's strong* above is dead by construction.** The only production `KekRing` is
   `{ current: { version: "current", keyBytes }, /* no previous */ }` (`tools/handlers.ts:90`).
   Because the version label is the constant string `"current"`, an old envelope's `kekVersion`
   always equals `ring.current.version`, so `open()` (`auth/crypto.ts:80`) only ever tries the *new*
   key and the previous-key fallback can never engage. The first KEK rotation makes every sealed
   token fail GCM verification. It compounds with `auth/token-store.ts:44`: the initial
   `store.get("servicenow")` in `getServiceNowBearer` (`auth/servicenow-oauth.ts:56`) sits *outside*
   the refresh try/catch, so the throw propagates past the re-mint fallback → hard outage, no
   self-heal, until every user re-authenticates.
   **Fix:** thread a real `{version, keyBytes}` from versioned secrets (`TOKEN_KEK_CURRENT` +
   optional `TOKEN_KEK_PREV`); wrap the initial `get` to fail-closed-then-re-mint.

3. **Cross-instance replay: the signed `instance` claim is never enforced** (latent; source-only,
   needs a PDI). `instance` is part of the HMAC-signed canonical payload (`x_mcp_verify.js:45`, host
   `auth/actor.ts:28`), but **no code in the verifier or the resource script compares `actor.instance`
   to the receiving instance**. A body signed for instance A is cryptographically valid on instance B
   whenever B shares `x_mcp.executor.hmac_secret` (a common dev/test/prod key-reuse), within the 120 s
   freshness window (B keeps its own `x_mcp_nonce` table, so the nonce isn't "seen").
   **Fix:** in `verify()`, reject unless `actor.instance` equals this instance's canonical host.

4. **The mandatory `admin_script` `reason` is recorded on no side and is unsigned.** `run_code`
   forces a non-empty `reason` (`tools/run_code.ts:62`) and ships it to the executor
   (`sn/rpc.ts:146`), but (a) it is **outside** the signed actor payload (`auth/actor.ts:28` — freely
   tamperable in transit) and (b) the authoritative `x_mcp_audit_log` row has no `reason` column and
   never reads `body.reason` (`x_mcp.executor.run.js:29-41`). With host-side `emitAudit` also unwired
   (consensus finding), the one justification a human is compelled to supply for the highest-risk
   operation is persisted nowhere and authenticated by nothing.
   **Fix:** add `reason` to the signed payload *and* to the audit row.

### 🟡 Low — NEW

5. **The authorization core fails *open* on a non-`Mode` value** (latent / defense-in-depth).
   `MODE_RISK[x]` is `undefined` for any non-Mode string, and every `>`/`<` comparison against
   `undefined` is `false`. So if a non-Mode value reached the resolver, `minByRisk`
   (`authz/effective-mode.ts:20`) would not lower it and the cap check (`:50`) would not deny —
   `resolveEffectiveMode` returns `effective` up to `admin_script`. `assertActorPolicy`
   (`authz/actor-policy.ts:59`) has the identical shape. Not reachable today (the zod `mode` enum +
   `maxModeFromScopes` keep modes valid), but a fail-*open* in the authz core is worth hardening:
   validate `Mode` at the boundary, or treat an unknown mode as maximum risk.

6. **`/authorize` and `/oauth/token` are not Origin-checked.** The DNS-rebinding/Origin guard wraps
   only the `/mcp` apiHandler (`index.ts:46`); the consent POST (carrying `operator_secret` + the
   client-controlled `oauth` field) and the token endpoint are routed by `OAuthProvider` *before* that
   check. CSRF is mitigated by the operator-secret requirement, so low — but the documented S12 Origin
   defense doesn't cover the auth surface. (Complements Codex Medium #4, which flags the *outbound*
   SSRF on the same token endpoint; this is the *inbound* gap.)

7. **Smaller latent/correctness items (none on a hot path today):**
   - `SchemaCache.listTables` keys by `filter ?? "*"`, so a literal `"*"` filter collides with the
     no-filter case and can serve a wrong/truncated list for ~24 h (`cache/schema.ts:45`).
   - `BudgetDO.increment` does `get`→`put` with no mutex, racing `reserveCritical` and losing updates
     (`do/budget.ts:82`); no production caller today.
   - `MutationLedgerDO.complete` ignores `requestHash` and fabricates a record from its
     `?? {…requestHash:""}` default, so a stray `complete()` can stamp a result under the wrong key
     (`do/mutation-ledger.ts:55`); unwired today.
   - The executor never reads its `x_mcp.executor.timeout_ms` property; synchronous `new Function` has
     no watchdog, so a runaway script runs to the platform transaction limit
     (`x_mcp.executor.run.js:73`).
   - The nonce is consumed inside `verify()` *before* the kill-switch/egress toggles
     (`x_mcp.executor.run.js:52`) — same class as the size-guard ordering already noted; a call
     rejected by a toggle still burns its nonce.
   - If `GlideCertificateEncryption.generateMac` returns `null`, `_constantTimeEquals(null, sig)`
     throws out of `verify()` past the clean 401, leaving the audit row stuck at `running`
     (`x_mcp_verify.js:88`).

### How these were verified

- **Path traversal + `describe_table` comma-injection** — empirically: `new URL` normalizes
  `/api/now/table/incident/../sys_user/<id>` → `/api/now/table/sys_user/<id>` (the raw
  `startsWith("/api/")` guard passes first), and `esc("incident,sys_user")` is returned unchanged
  (`esc` strips `^`/`=` but not `,`). Both are concrete instances of the consensus "unvalidated
  identifier boundary" finding; the second — `sn/discovery.ts:74` `nameIN${chain.map(esc)…}` — is a
  query-injection sibling (schema disclosure across the per-table policy check) not separately listed
  above. Reinforces the **altitude** fix already recommended: one strict identifier validator at the
  RPC boundary, not scattered `encodeURIComponent` + "also strip commas".
- **Error-code forgery** — confirmed against the codemode contract (`test/sandbox-contract.test.ts:72`).
- **KEK / `instance` / `reason` / fail-open** — source-confirmed at the cited lines; the `instance`
  and executor items (3, 4, parts of 7) require a live PDI to exercise.

### Highest-leverage additions to the fix list

- Validate the parsed sandbox error `code` against `ErrorCode`; only honor host-emitted `[[…]]` codes.
- Thread a *versioned* KEK with a real `previous`, and make token decrypt fail-closed-then-re-mint, so
  a key rotation is not an outage. (This is the item that turns a praised strength into a real one.)
- Enforce `actor.instance` in the executor verifier; sign **and** audit `reason`.
