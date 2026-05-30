# ServiceNow Code Mode MCP Server

A stateless Cloudflare Worker (`createMcpHandler`) exposing three MCP tools —
`run_code`, `describe_table`, `list_tables` — where the model authors **TypeScript**
against a typed `servicenow.*` RPC surface that is transpiled (esbuild-wasm) and run in
a per-call Worker Loader sandbox with **no network and no credentials**. The single
source of truth for the design is [`DEVELOPMENT_PLAN.md`](DEVELOPMENT_PLAN.md).

## ✅ DEPLOYED & end-to-end proven (live)

Deployed to Cloudflare via Alchemy IaC (`alchemy.run.ts`):
**`https://servicenow-mcp.lammesen.workers.dev`**

`npm run deploy:e2e` drives the **deployed** Worker with a real MCP client — **5/5 pass**,
including the path local workerd couldn't exercise:

- `/health` ok; foreign `Origin` → 403 (**S12** live)
- `list_tables` / `describe_table` against **live ServiceNow** (inherited fields)
- **`run_code` → Worker Loader sandbox → `servicenow.tableQuery` → LIVE ServiceNow → `INC0000060`**
  (the full Code Mode thesis: LLM TypeScript transpiled, sandboxed with no creds/network,
  reaching real ServiceNow via the typed RPC — credential injected host-side)
- **S1**: sandbox `fetch` blocked on the deployed Worker (network isolation holds)

The core safety thesis — *maximum access, achieved safely* — is now demonstrated on real
Cloudflare edge + real ServiceNow.

**The `x_mcp` executor is installed + proven live** (`npm run` `scripts/executor-install.mjs`,
6/6) and the **full chain** runs through the deployed Worker (`deploy:e2e`, 10/10): an
`admin_script` `run_code` snippet calls `servicenow.runServerScript("return gs.getUserName()")`
→ the host HMAC-signs the actor → the executor on ServiceNow **verifies the signature** (forged
or stale → 401), executes, audits, and returns `"admin"`. Cross-engine HMAC (B1/0.13a), kill
switch (S9), nonce replay (T8), and cross-scope reach (S16) all verified live.

## Build status (2026-05-30)

This repo is being implemented **phase by phase** from the plan. A large part of the
plan's Definition-of-Done depends on a live ServiceNow PDI and a Cloudflare Workers Paid
account, which are **not available in the current build environment** — see
[`docs/OPEN_QUESTIONS.md`](docs/OPEN_QUESTIONS.md) for the exact verified-local vs
blocked-external split. Nothing security-critical is claimed verified unless a green
local test backs it.

### Verified locally — 99 tests, `@cloudflare/vitest-pool-workers`, `tsc -b` clean

Added since first cut: **MCP-client OAuth** (deployed, secured — `/mcp` 401 without token,
DCR+PKCE+consent, scope→maxMode), **user-aware schema cache** (S6), **ACL-safe pagination**
(B7), **host-side audit** (7.2), **encrypted recovery snapshots** (7.7), plus live
**OAuth-negative** checks (S13 subset) in `deploy:e2e` (now 9/9).


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
| URL/SSRF allowlist · scriptedRest denylist | §2.4/3.2, **S15/B2** | `url-and-path-guards.test.ts` |
| AES-GCM token envelope (AAD + KEK rotation) | §2.7 | `crypto.test.ts` |
| Actor signing + ActorPolicy (B5) + capability gate | §2.0/2.12/3.5, **B1-shape/B5** | `actor-and-policy.test.ts` |
| **run_code pipeline** (mode-cap, capability, ActorPolicy, masking, budget, code_size, transpile_error) | §3.1/4.6 | `run-code-pipeline.test.ts` |
| MCP tool surface (3 tools, annotations, schemas) | §3.2 | `server-tools.test.ts` |
| describe_table / list_tables (incl. inherited fields, filter sanitation) | §3.2/2.6 | `discovery.test.ts` |
| **BudgetDO atomic reserve-before-load** (cost gate, S14) | §4.5 | `do-partition.test.ts` |
| **MutationLedgerDO** leveled idempotency (S17) | §7.3 | `do-partition.test.ts` |
| admin_script approval gate (§7.9) + redaction (§7.1) | §7 | `approval-redact.test.ts` |

Plus docs: `ROLE_MATRIX` (Phase 6), `THREAT_MODEL`, `SNOW_EGRESS`, `RECOVERY`, `RETENTION` (Phase 7);
a Node **stdio shim** (`bin/stdio.ts`, Phase 8). All three tools are implemented; `describe_table`/
`list_tables` are **live-verified** against `dev374488` (`describe_table(incident)` → 92 fields incl.
inherited).

Implemented host-side modules (`src/`): `authz/effective-mode` · `authz/actor-policy` ·
`auth/crypto` · `auth/actor` · `auth/oauth-kv` · `sn/errors` · `sn/url-allowlist` ·
`sn/scripted-rest-denylist` · `sn/http` · `sn/rpc` · `sn/run-budget` · `sandbox/{transpile,executor,serialize}` ·
`tools/run_code` · `config` · `do/{auth-correlation,token-store,budget,mutation-ledger}` (skeletons).
The keystone contract is in [`docs/ADR/0001`](docs/ADR/0001-codemode-integration.md); deltas in [`docs/DELTAS.md`](docs/DELTAS.md).

### Live-verified against a real instance (`dev374488.service-now.com`)

`npm run live:smoke` (connectivity) and `npm run live:verify` (the actual `ServiceNowRPC`
in Node, Basic-Auth dev path) pass **7/7 against real ServiceNow data**:

- `tableQuery` returns real `incident` rows with `sys_id` injected (§1.7)
- `aggregate` returns a real count (67 incidents)
- **ActorPolicy denies `sys_user`** before the live call (**B5** — live)
- **field masking** strips a forbidden field from the live response (live)
- **capability gate**: `read_only` cannot `tableUpdate` — no mutation reaches the instance

This moves the read surface, ActorPolicy, masking, and capability gating from
mock-verified to **live-verified**.

> **Why two harnesses:** the vitest pool runs in **workerd**, whose outbound `fetch` is
> blocked in this environment (a proxy it detects but can't use) — so live ServiceNow
> calls run in **Node** (`scripts/live-rpc-verify.mjs`, same compiled modules). The
> *combined* sandbox→host→live path therefore can't be exercised here (the sandbox needs
> workerd; workerd can't reach the network). That seam is the only thing the env blocks —
> not a code issue.
>
> The auth flow uses the **Basic-Auth dev path** (the instance has no OAuth client
> configured); OAuth consent/PKCE/token-store wiring is still pending. `describe_table`/
> `list_tables` return `reauth_required` until the schema cache lands.

### Blocked on external services (NOT verified here)

- **ServiceNow scoped-app executor** (`sn-executor-app/` — source written, incl. the §10
  resource script + matching `x_mcp_verify`): needs a PDI to install/prove (S8/S9/S16, B1, B6).
- **0.13a** in-scope HMAC verify mechanism, **0.13c** `integration_user` read-policy on a
  real instance, **0.13e** OAuth refresh behavior; the ServiceNow client's network behavior;
  the auth flow (OAuthProvider consent/PKCE/token-store integration); deployment.

The host-side logic is built behind injectable seams so wiring the live client/auth is
additive, not a rewrite — but no security invariant is *claimed proven* end-to-end until
it runs against ServiceNow.

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
      server.ts                  # createServer(): tools (hello today; 3 real tools later)
      observability/origin.ts    # Origin validation (S12)
      sandbox/transpile.ts       # esbuild-wasm TS->JS string (ADR-0001)
      sandbox/executor.ts        # DynamicWorkerExecutor factory (globalOutbound:null)
      authz/effective-mode.ts    # min(requested, scope, tenant, instance) (§2.0.1)
      auth/oauth-kv.ts           # OAUTH_KV guard + isolation (B8)
      sn/url-allowlist.ts        # SSRF allowlist (S15)
      sn/scripted-rest-denylist.ts # executor-bypass denylist (B2)
    wrangler.jsonc               # LOADER + SCHEMA_KV + OAUTH_KV, compat 2026-05-13
docs/ ADR/0001 · DELTAS · OPEN_QUESTIONS
```
