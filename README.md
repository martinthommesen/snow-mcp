# ServiceNow Code Mode MCP Server

A stateless Cloudflare Worker (`createMcpHandler`) exposing three MCP tools —
`run_code`, `describe_table`, `list_tables` — where the model authors **TypeScript**
against a typed `servicenow.*` RPC surface that is transpiled (esbuild-wasm) and run in
a per-call Worker Loader sandbox with **no network and no credentials**. The single
source of truth for the design is [`DEVELOPMENT_PLAN.md`](DEVELOPMENT_PLAN.md).

## DEPLOYED to Cloudflare; hardening landed in source (live re-verification gated to P8)

Deployed to Cloudflare via Alchemy IaC (`alchemy.run.ts`):
**`https://servicenow-mcp.lammesen.workers.dev`**

An **earlier** `deploy:e2e` run proved the core Code Mode thesis on real edge + real ServiceNow
(run_code → Worker Loader sandbox → `servicenow.tableQuery` → LIVE ServiceNow → `INC0000060`;
sandbox `fetch` blocked (S1); foreign `Origin` → 403 (S12)), and the `x_mcp` executor was
installed + proven live (full chain through the deployed Worker). **That proof predates the
P0–P7 security-hardening branch** (`harden/code-review-closeout`). P7 made a **breaking,
coordinated change to the signed actor payload** (added a signed `reason` key + enforced the
`actor.instance` claim — see DELTAS), so the host and executor **must be redeployed together**
and the live chain **re-verified in P8** (operator-gated). The host + executor are
**source-complete and locally tested** on this branch; their **live** behavior is
**verified in P8**, not currently.

The core safety thesis — *maximum access, achieved safely* — is demonstrated by the local
test suite + call-graph wiring (below); the on-edge re-proof against the hardened build is the
P8 gate. See `docs/THREAT_MODEL.md` for the per-control wired+tested vs P8-live split and
`docs/GA_CHECKLIST.md` for the explicit P8-LIVE gate list.

## Build status (2026-05-31)

This repo is being implemented **phase by phase** from the plan. The P0–P7 security-hardening
phases are **landed and locally test-gated** on `harden/code-review-closeout`; the live
re-verification + redeploy is **P8 (operator-gated, not yet run)**. A large part of the plan's
Definition-of-Done depends on a live ServiceNow PDI and a Cloudflare Workers Paid account — see
[`docs/OPEN_QUESTIONS.md`](docs/OPEN_QUESTIONS.md) for the exact wired+tested vs
P8-live-verified split. Nothing is claimed **live** unless re-proven against the hardened build
in P8; nothing security-critical is claimed verified-in-source unless a green local test backs
it.

### Verified locally — 286 tests / 27 files, `@cloudflare/vitest-pool-workers`, `tsc -b` clean

The P0–P7 hardening wired the previously-implemented-but-uninvoked safety modules into the live
request path, each with failing-first tests asserting the new secure behavior:

- **P1** strict RPC input-validation boundary (`sn/validate.ts`; path-segment encoding;
  traversal/`%2e`/non-hex-`sys_id` rejection) — `rpc-validation.test.ts`, `url-and-path-guards.test.ts`
- **P2** host-attested error codes (forged `[[code]]` can't taint `structuredContent.code`) +
  byte-safe UTF-8 truncation — `error-and-serialize.test.ts`, `run-code-pipeline.test.ts`
- **P3** versioned-KEK ring (content-addressed labels, rotation round-trip, legacy-envelope
  migration, fail-closed re-mint) — `crypto.test.ts`, `servicenow-oauth.test.ts`
- **P4** idempotency ledger + audit-before-effect + recovery snapshot + approval gate wired on
  every host `tableUpdate`/`runServerScript` (`sn/mutation-guard.ts`) — `mutation-wiring.test.ts`,
  `audit-recovery.test.ts`
- **P5** enforced per-run row/byte caps + daily admission/accrual (`sn/run-budget.ts`,
  `do/budget.ts` mutex) — `run-budget.test.ts`, `actor-and-policy.test.ts`
- **P6a** auth-surface origin guard, env-gated localhost, redacted SN errors, signed consent
  state — `auth-surface.test.ts`
- **P6b** per-user ServiceNow OAuth wired end-to-end **in source** (ticket → authorize → callback
  → token store; SN principal sys_id → signed `snow_effective_user_sys_id` + schema cache key
  with `roleHash`) + restrictive opt-in ActorPolicy — `servicenow-ticket.test.ts`, `servicenow-callback.test.ts`,
  `servicenow-reauth-tools.test.ts`, `schema-cache.test.ts`
- **P7** executor + Fluent hardening — **source-complete; live-verified in P8** (see below)


| Area | Plan ref | Tests |
|---|---|---|
| Per-request server (CVE guard) + `/health` | §2.3, 0.5/0.7 | `health.test.ts` |
| Origin validation (DNS-rebinding) | §3.1, 0.11, **S12** | `health.test.ts` |
| esbuild-wasm TS transform in workerd | §2.2, 0.8 | `transpile.test.ts` |
| **Code Mode execute() contract** | §3.4, **0.8a** | `sandbox-contract.test.ts` |
| Sandbox import mechanism + v1 deny policy | **0.8b** | `import-policy.test.ts` |
| Effective-mode cap (read-only default) | §2.0.1, **0.13b**, **B3/B4** | `effective-mode.test.ts` |
| OAUTH_KV present + isolated | §2.4, **0.13d**, **B8** | `oauth-kv.test.ts` |
| DO partition (token isolation, global budget) | §2.10, **0.12** | `do-partition.test.ts` |
| URL/SSRF allowlist | §2.4, **S15** | `url-and-path-guards.test.ts` |
| AES-GCM token envelope (AAD + KEK rotation) | §2.7 | `crypto.test.ts` |
| Actor signing + ActorPolicy (B5) + capability gate | §2.0/2.12/3.5, **B1-shape/B5** | `actor-and-policy.test.ts` |
| **run_code pipeline** (mode-cap, capability, ActorPolicy, masking, budget, code_size, transpile_error) | §3.1/4.6 | `run-code-pipeline.test.ts` |
| MCP tool surface (3 tools, annotations, schemas) | §3.2 | `server-tools.test.ts` |
| describe_table / list_tables (incl. inherited fields, filter sanitation) | §3.2/2.6 | `discovery.test.ts` |
| **BudgetDO atomic reserve-before-load** (cost gate, S14) | §4.5 | `do-partition.test.ts` |
| **MutationLedgerDO** leveled idempotency (S17) | §7.3 | `do-partition.test.ts` |
| admin_script approval gate (§7.9) + redaction (§7.1) | §7 | `approval-redact.test.ts` |

Plus docs: `ROLE_MATRIX` (Phase 6), `THREAT_MODEL`, `SNOW_EGRESS`, `RECOVERY`, `RETENTION` (Phase 7).
All three tools are implemented; `describe_table`/`list_tables` returned real schema
pre-hardening (`describe_table(incident)` → 92 fields incl. inherited on `dev374488`) and are
re-verified live in P8.

Implemented host-side modules (`src/`): `authz/{effective-mode,actor-policy,approval}` ·
`auth/{crypto,actor,oauth-kv,token-store,servicenow-oauth,servicenow-ticket,servicenow-callback-handler}` ·
`sn/{errors,url-allowlist,http,rpc,run-budget,validate,mutation-guard,discovery}` ·
`observability/{audit,redact,origin}` · `recovery/{snapshots,policy}` · `cache/schema` ·
`sandbox/{transpile,executor,serialize}` · `tools/{run_code,handlers}` · `config` ·
`do/{auth-correlation,token-store,budget,mutation-ledger}`. The DOs carry real logic (P4/P5/P6b):
`MutationLedgerDO` leveled idempotency, `BudgetDO` mutexed global+per-user counters,
`AuthCorrelationDO` atomic single-use OAuth correlation records, `TokenStoreDO` encrypted token
storage. The keystone contract is in [`docs/ADR/0001`](docs/ADR/0001-codemode-integration.md);
deltas in [`docs/DELTAS.md`](docs/DELTAS.md).

### Read surface — earlier live proof (pre-hardening), re-verified in P8

An earlier `npm run live:verify` (the actual `ServiceNowRPC` in Node, Basic-Auth dev path)
passed **7/7 against real `dev374488` data** — real `tableQuery` rows + `sys_id` injection,
real `aggregate` count, ActorPolicy table deny, field masking, capability gate. P1 then
tightened this path (validate-first table/`sys_id`/`limit`/fields/query, encoded path
segments), so the read surface is **wired + locally tested** here and **re-verified live in
P8** (`live:verify`, operator-gated).

> **Why two harnesses:** the vitest pool runs in **workerd**, whose outbound `fetch` is
> blocked in this environment (a proxy it detects but can't use) — so live ServiceNow
> calls run in **Node** (`scripts/live-rpc-verify.mjs`, same compiled modules). The
> *combined* sandbox→host→live path therefore can't be exercised here (the sandbox needs
> workerd; workerd can't reach the network). That seam is the only thing the env blocks —
> not a code issue.
>
> Per-user ServiceNow OAuth (`SERVICENOW_CREDENTIAL_MODE=per_user_oauth`) is now wired
> **end-to-end in source** (ticket → `/servicenow/authorize` → `/servicenow/callback` →
> per-user token store; SN principal resolution → signed `snow_effective_user_sys_id`); the
> default remains the `integration_user` Basic-Auth/ROPC dev path. The live authorize/callback
> dance + SN-principal endpoint shape are **P8-live** gates (`oauth-verify.mjs`).

### Source-complete on this branch; live-verified in P8 (NOT proven against the hardened build)

- **ServiceNow scoped-app executor + global core** (`sn-executor-app/`): hardened in source by
  P7 (instance-claim enforcement, null-safe MAC, signed+audited `reason`, byte-safe sample,
  DB-unique-index nonce race-close, admin ACLs, deprecated global-REST endpoint gated off). P7
  **changed the signed actor payload** (added `reason`; enforced `actor.instance`), so the host
  + executor must be **redeployed together** and the full chain (B1 HMAC match, S8 role-ACL, S9
  kill switch, T8 nonce replay, S16 cross-scope, instance-claim mismatch) **re-proven in P8**.
- **0.13a** in-scope HMAC verify + `GlideDigest` SHA-256 UTF-8 encoding, **0.13c**
  `integration_user` read-policy, **0.13e** OAuth refresh behavior; the ServiceNow client's
  live network behavior; the `deploy:e2e` chain against the hardened build; deployment.

The host-side logic is built behind injectable seams so wiring the live client/auth is
additive, not a rewrite — but no security invariant is *claimed proven live* against the
hardened build until P8 runs against ServiceNow.

## Release notes — operator-facing behavior changes (P0–P7, `harden/code-review-closeout`)

These are **behavior changes an operator must know about** before redeploying the hardened
build. The default posture preserves the single-operator deployment; the new safety layers are
**opt-in** unless noted.

- **Mutations now REQUIRE a tool-level `idempotencyKey` (fail-closed).** The first mutating RPC
  (`tableUpdate`/`runServerScript`) in a `run_code` run with no tool-level `idempotencyKey` is
  denied with `capability_denied` (audited). Snippet calls no longer carry per-call keys. There is
  no host-generated fallback — this is the exactly-once anchor (P4).
- **The second-approval gate is fail-closed for `admin_script`.** Empty
  `ADMIN_SCRIPT_ALLOWLIST`/`_APPROVAL_TOKENS`/`_REQUIRED_GROUP` settings deny
  `admin_script`; operators must explicitly allowlist an actor and configure either an approval
  token or required access group. Recovery snapshots and the restrictive ActorPolicy remain
  opt-in: `SNAPSHOT_ENABLED_TABLES` enables snapshots; any `ACTOR_POLICY_*` var builds a
  restrictive policy (table allowlist + field masks + row filters + per-run ceilings).
- **Raw ServiceNow error messages are now redacted.** `mapServiceNowError` returns a generic
  per-status client message (the typed `code` + structured `detail` survive); the raw SN message
  is logged server-side only (redacted) (P6a, finding 22).
- **The browser consent flow requires the worker origin in `ALLOWED_ORIGINS`** (or
  `ALLOW_LOCALHOST=true` in dev). The top-level origin guard now also covers the auth surface
  (`/authorize`, `/oauth/token`, `/oauth/register`, `/servicenow/*`); a missing/foreign Origin on
  those paths returns 403. The worker's own same-origin consent POST is auto-allowed (P6a).
- **Per-user ServiceNow OAuth is wired (opt-in via `SERVICENOW_CREDENTIAL_MODE=per_user_oauth`).**
  In that mode a missing/expired/undecryptable token raises `reauth_required` (with an
  authorize URL) and **never** falls back to ROPC; `integration_user` (default) keeps ROPC.
- **Versioned KEK ring is a migration, not a rename.** First hardened deploy must set
  `TOKEN_KEK_CURRENT` to today's `TOKEN_KEK` passphrase, or it bricks the tokens it protects —
  see [`docs/RECOVERY.md`](docs/RECOVERY.md).
- **Budget residual (documented limit):** a single run may overshoot the daily rows/bytes cap by
  ≤ one per-run ceiling, and the SN-request budget can over-count by one on a replay/deny
  (safe-direction over-count, never under) (P5).

## Develop

```bash
npm install                 # exact-pinned runtime deps; lockfile committed
npm test                    # vitest inside workerd (REQUIRED — codemode/esbuild-wasm need it)
npm run typecheck           # tsc -b (src)
npm run dev                 # wrangler dev --port 8787  (local /mcp + /health)
npm run cf-types            # regenerate worker-configuration.d.ts after wrangler.jsonc edits
```

Copy `.dev.vars.example` → `.dev.vars` (git-ignored) and fill secrets before any flow
that touches ServiceNow or the OAuth provider.

## Layout (populated incrementally — see plan §4 for the full target tree)

```
packages/
  shared/src/types.ts            # Mode/credential-mode/error-code types
  mcp-server/
    src/
      index.ts                   # entry: /health, Origin-gated /mcp, per-request server
      server.ts                  # createServer(): run_code, describe_table, list_tables
      observability/origin.ts    # Origin validation (S12)
      sandbox/transpile.ts       # esbuild-wasm TS->JS string (ADR-0001)
      sandbox/executor.ts        # DynamicWorkerExecutor factory (globalOutbound:null)
      authz/effective-mode.ts    # min(requested, scope, tenant, instance) (§2.0.1)
      auth/oauth-kv.ts           # OAUTH_KV guard + isolation (B8)
      sn/url-allowlist.ts        # SSRF allowlist (S15)
    wrangler.jsonc               # LOADER + SCHEMA_KV + OAUTH_KV, compat 2026-05-13
docs/ ADR/0001 · DELTAS · OPEN_QUESTIONS
```
