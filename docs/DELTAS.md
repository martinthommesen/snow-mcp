# DELTAS — where the installed reality differs from DEVELOPMENT_PLAN.md

Plan rule (§0 rule 2): *"If a documented API here no longer matches the installed package, trust the installed package and official docs, and record the delta here."* Each entry: what the plan said → what is true → action taken.

**Reconciliation date:** 2026-05-30. Runtime: workerd `1.20260526.1`, miniflare `4.20260526.0`, Node `v24.16.0`.

## D1 — Dependency versions (Phase 0.1)

| Package | Plan pin | Installed (EXACT) | Note |
|---|---|---|---|
| `@cloudflare/codemode` | `0.3.8` | `0.3.8` | match |
| `esbuild-wasm` | "(latest, confirm)" | `0.28.0` | confirmed; primary TS transform, works in workerd |
| `@cloudflare/worker-bundler` | `0.1.3` (fallback) | **not installed** | 0.8a passed → fallback not needed (ADR-0001 D1) |
| `agents` | `0.13.3` | `0.13.3` | exports `createMcpHandler`, `getMcpAuthContext` confirmed |
| `@modelcontextprotocol/sdk` | `1.29.0` | `1.29.0` | supports zod `^3.25 || ^4.0` |
| `@cloudflare/workers-oauth-provider` | "(confirm)" | `0.7.0` | pinned |
| `wrangler` | `4.95.0` | `4.95.0` | match |
| `alchemy` | `0.87.0` | `0.87.0` | latest is `0.93.9`; pinned to plan value (IaC only, not on the local-verifiable path) |
| `hono` | `4.12.23` | `4.12.23` | match |
| `zod` | `4.4.3` | `4.4.3` (server pkg) | see D2 |
| `ai` | "match codemode peer" | `^6.0.0` (`6.0.193`) | codemode `0.3.8` peers `ai ^6.0.0` |
| `@cloudflare/vitest-pool-workers` | "match wrangler" | `0.16.10` | bundles `[email protected]` + `miniflare 4.20260526.0` |
| `vitest` | "caret 3.x" | **`^4.1.0`** (`4.1.7`) | **DELTA** — vitest-pool-workers `0.16.10` peers `vitest ^4.1.0`; 3.x is incompatible |
| `typescript` | "caret 5.x" | `^5.7.0` (`5.9.3`) | match |

## D2 — Dual zod versions (build hygiene)

`@cloudflare/[email protected]` depends on `zod ^3.x`, hoisting `[email protected]` to the workspace root, while the server package + codemode peer require `zod 4`. The MCP SDK (hoisted to root) then resolved zod 3 and rejected zod-4 schemas (`ZodOptional<ZodString> is not assignable to AnySchema`).
**Action:** added `zod@4.4.3` to the **root** `dependencies` so zod 4 hoists to root; the test pool keeps its own nested `zod@3`. SDK now resolves zod 4. Typecheck clean.

## D3 — vitest-pool-workers config API changed for vitest 4 (Phase 0.6)

Plan/older docs use `import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config"`. In `0.16.10` the `./config` subpath and `defineWorkersConfig`/`defineWorkersProject` are **gone**.
**Action (`vitest.config.ts`):** use the new `cloudflareTest` **plugin** from `@cloudflare/vitest-pool-workers` + `defineConfig` from `vitest/config`:
```ts
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";
export default defineConfig({ plugins: [cloudflareTest({ wrangler:{configPath}, miniflare:{…} })], test:{…} });
```
(Confirmed via the package's bundled `vitest-v3-to-v4` codemod.)

## D4 — Code Mode sandbox namespace is single-level (Phase 0.8a, ADR-0001 D4)

Plan writes the surface as `codemode.servicenow.*`. Installed `0.3.8` exposes each provider as a **single-level** global: `{ name:"servicenow", fns }` → `servicenow.tableQuery(...)`. No two-level nesting exists.
**Action:** all samples and the generated type surface use `servicenow.*`. Raw-fns form of `execute()` is deprecated → always pass `ResolvedProvider[]`.

## D5 — Transpile output needs a trailing-semicolon strip (Phase 0.8a, ADR-0001 D3)

esbuild emits the arrow as a statement (`async () => {...};`); codemode wraps code as `( <code> )()`, so the trailing `;` causes `SyntaxError: Unexpected token ';'`.
**Action:** `transpileTs()` strips one trailing `;`. Proven by the 0.8a suite.

## D6 — Sandbox compatibility date is fixed by the SDK (Phase 0.8a / §2.9)

Plan §2.9 wants ONE compat date everywhere. codemode `0.3.8` **hardcodes the inner sandbox Worker's `compatibilityDate` to `2025-06-01`**; it is not configurable via `DynamicWorkerExecutorOptions`.
**Action:** host + tests + wrangler use the unified `2026-05-13`; the *sandbox inner Worker* is `2025-06-01` (SDK-fixed). Acceptable — the sandbox only runs transpiled user code against the RPC proxy. Re-open if the SDK exposes the option.

## D7 — esbuild-wasm requires explicit wasm module + `worker:false` in workerd (Phase 0.8)

In workerd there is no implicit wasm fetch / Web Worker.
**Action:** `transpile.ts` does `esbuild.initialize({ wasmModule: <imported esbuild.wasm>, worker:false })`, importing `esbuild-wasm/esbuild.wasm` as a `WebAssembly.Module` (ambient decl in `src/wasm.d.ts`). Works under vitest-pool-workers.

## D8 — `ServiceNowRPC` does not extend `RpcTarget` (§3.3)

Plan §3.3 writes `class ServiceNowRPC extends RpcTarget`. We expose plain methods and
hand `fns()` to codemode, whose `ToolDispatcher` is itself the `RpcTarget` over Workers
RPC (confirmed in the 0.3.8 executor source). Extending `RpcTarget` here is unnecessary
and would couple the class to `cloudflare:workers` for no benefit. Recorded; revisit only
if a direct-RPC path (bypassing codemode) is added.

## D10 — ServiceNow executor install via REST (Phase 5, observed on dev374488) — DEPRECATED

> **DEPRECATED reference (P7).** The canonical executor is the scoped, role-ACL-gated Fluent app
> (**D11** + D12), and `executor-install.mjs` now installs **only the global `x_mcp_verify`
> helper** by default. The un-ACL'd global-REST endpoint below is gated OFF behind
> `X_MCP_INSTALL_GLOBAL_REST=1` and kept only as a non-SDK reference. Findings observed here
> (numeric namespace, no custom tables via Table API, cross-engine HMAC) remain accurate.

- **Global-scope Scripted REST APIs get an auto-generated NUMERIC namespace.** The endpoint
  is `/api/1793136/x_mcp/executor/run`, not `/api/x_mcp/...`. The host executor path is now
  configurable (`SNOW_EXECUTOR_PATH`); the scriptedRest denylist (B2) matches `/executor/` at
  any depth.
- **Custom tables cannot be created via the Table API.** POSTing `sys_db_object` returns 201
  but no physical table forms (`GlideRecord.insert() - invalid table name`). The REST-based
  install therefore uses `syslog` (audit, JSON message) + `sys_user_preference` (nonce). The
  PRODUCTION scoped app ships the dedicated `x_mcp_audit_log` + `x_mcp_nonce` tables, the
  `x_mcp.executor` role, and the REST_Endpoint ACL via a **Studio update set** (plan §10).
- **B1 cross-engine HMAC confirmed:** `GlideCertificateEncryption.generateMac(key,'HmacSHA256',data)`
  with a base64 key matches host WebCrypto `HMAC-SHA256` over the ASCII-only canonical payload.
- **Executor governance flag:** the REST install sets `requires_acl_authorization:false`, so
  the HMAC signature is the execution gate (any authenticated caller without a valid signature
  gets audited + 401). Production adds the role ACL as a second gate.

## D11 — Production executor via ServiceNow SDK + Fluent (replaces the XML update set)

Built the production scoped app `x_1793136_mcp` as a **ServiceNow SDK (now-sdk 4.7.1) Fluent
project** (`sn-executor-app/fluent/`, TypeScript metadata: Table/Role/Acl/RestApi/Property)
and deployed via `now-sdk install` — **no XML update set import**. Proven 4/4 live
**pre-hardening** (`scripts/executor-scoped-verify.mjs`): S8 role-ACL enforced, B1 valid
executes, forged→401, audit-first row written. (P7 later changed the signed payload — added
`reason`, enforced `actor.instance` — so this is **re-verified in P8** after a coordinated
host+executor redeploy; see D12.) Findings:

- **`new Function` (eval) and `GlideCertificateEncryption` are GLOBAL-only** — neither is
  allowed in a scoped application. So the executor's CORE (verify + eval) must live in global
  scope; the scoped app is a **role-gated REST wrapper that DELEGATES** to the global
  `x_mcp_verify.run()` (exactly the plan's §0.13a "global verification Script Include exposed
  to the scope"). This is the correct production architecture — recorded because the plan's
  §10 implies a self-contained scoped executor, which ServiceNow does not permit.
- **Cross-scope call:** `new global.x_mcp_verify()` is required at runtime, but the SDK linter
  flags `global` as a Node.js builtin (`no-unsupported-node-builtins`) — suppress with
  `// eslint-disable-next-line no-unsupported-node-builtins`. `gs.include()` alone does not
  bring the class into scope ("undefined, maybe missing global qualifier").
- **Vendor prefix:** scoped apps must use the instance vendor prefix — scope `x_1793136_mcp`,
  tables `x_1793136_mcp_audit_log`/`_nonce`, role `x_1793136_mcp.executor`. Endpoint:
  `/api/x_1793136_mcp/x_mcp/executor/run`.
- **S8 nuance:** the `admin` user bypasses ACLs regardless of `adminOverrides:false`; a true
  403 needs a non-admin caller. The ACL + role + `enforce_acl` config is verified instead.
- `now-sdk` env-var CI auth: `SN_SDK_AUTH_TYPE`, `SN_SDK_USER`, `SN_SDK_USER_PWD`, etc.

The `update-set/x_mcp.xml` scaffold is superseded by the Fluent project (kept as a reference
for non-SDK environments).

## D12 — Hardening deltas (P0–P7, `harden/code-review-closeout`)

The P0–P7 security-hardening branch landed the following deltas vs the pre-hardening reality.
**Breaking, coordinated:** the signed actor payload changed, so the host + executor must be
**redeployed together** (P8). Live re-verification of every executor-side item is a P8 gate.

- **Signed `reason` (the last canonical key) — host + executor.** `reason` is appended LAST to
  the host `auth/actor.ts` `CANONICAL_KEYS` and to every executor core's `_canonical` (6 keys:
  `email, sys_id, instance, request_id, script_sha256, issued_at, nonce, reason`). `signActor`
  accepts it; `rpc.ts` `runServerScript` signs the **host** tool-level `reason` (validated, not
  the snippet-supplied body) and the unsigned top-level `body.reason` is dropped — so the audited
  justification can't be forged independent of the HMAC. Byte-identical canonical output verified
  across the host signer + all 3 executor cores via a Node harness.
- **Instance claim enforced (executor).** The verifier rejects a payload whose signed
  `actor.instance` does not name this instance (cross-instance replay → clean 401). The host
  already signed `instance`; the executor now compares it.
- **Live nonce store = the DB-unique-indexed SCOPED `x_1793136_mcp_nonce` table, INSERT-as-arbiter
  in the WRAPPER.** (Reconciled 2026-05-31 — supersedes an earlier draft that placed
  `_consumeNonce` in the global core against a global `x_mcp_nonce` table; that never shipped, HEAD
  `8c6e1fd` moved consumption to the scoped wrapper, confirmed live.) The scoped wrapper
  (`x_mcp_executor.js`) delegates HMAC verify + `new Function` eval to the GLOBAL `x_mcp_verify`
  core (global-only primitives, D11) — that core does **verify()/execute()/run() only, no nonce,
  no DB write**. The wrapper itself does a bare INSERT into the **scoped `x_1793136_mcp_nonce`**
  between verify() and execute(); a duplicate (falsy insert OR unique-constraint violation) is a
  replay → 401. Arbiter = the scoped table's **DB unique index** on `value` (✅ live-verified via
  the CONCURRENT one-200/one-401 case). now-sdk 4.7.1 creates the physical index but omits the
  `sys_index` catalog row — index enforces while `sys_index` reads empty; verify functionally.
- **`executor-install.mjs` = global verify()/execute()/run() CORE + properties ONLY (no tables,
  no REST endpoint).** The global-REST endpoint is deprecated (gated behind
  `X_MCP_INSTALL_GLOBAL_REST=1`, default OFF). The canonical surface is the scoped, role-ACL-gated
  Fluent REST at the two-segment path **`/api/x_1793136_mcp/x_mcp/executor/run`**.
  **P8 finding (2026-05-31):** a global numeric endpoint `/api/1793136/x_mcp/executor/run` from an
  *earlier* install had survived and was LIVE — and its verify reject branch was dead code
  (`if (!new x_mcp_verify().verify(...))` is always false because `verify()` returns an object), so
  it executed every request with no signature check and no role ACL. `SNOW_EXECUTOR_PATH` had used
  that numeric form, so the Worker routed through it (the all-green e2e masked it — only the valid
  path is exercised). Fixed: repoint `SNOW_EXECUTOR_PATH` to the scoped two-segment path; delete
  the global op + definition (keep the shared global core); `executor-scoped-verify.mjs` now
  asserts the numeric path is dead (S8b) to lock the regression.
- **now-sdk 4.7.1 `run_period` `'[object Object]'` ScheduledScript serializer bug.** The SDK's
  ScheduledScript serializer emits `'[object Object]'` for a structured `run_period`. This affects
  the scoped `MCP Nonce Purge` job — which is the LIVE purge for the scoped `x_1793136_mcp_nonce`
  table (not "unused"; there is no global purge job — `executor-install.mjs` creates no tables).
  Set its interval once in the UI (System Definition → Scheduled Jobs). Replay protection does not
  depend on the purge — only unbounded table growth does — so this is a hygiene fixup, not a gate.
- **Content-addressed versioned KEK ring (P3).** `buildKekRing(currentSecret, prevSecret?)` with
  version labels `kek-${sha256(keyBytes)[:8]}`, so a same-label rotation can no longer mask the
  previous key. Threaded for both the token ring (`handlers.ts`) and the snapshot ring (P4).
  `TOKEN_KEK`/`SNAPSHOT_KEK` kept as one-release aliases. Migration runbook in RECOVERY.md.
- **Host-attested error codes (P2).** `structuredContent.code` derives only from monotonic host
  signals (`budget_exceeded`/`reauth_required`); a forged `[[code]]` in a sandbox throw collapses
  to `run_error`. `truncateUtf8` replaces the UTF-16 `json.slice` (byte-safe output).
- **Opt-in posture (P4/P5/P6b).** The restrictive ActorPolicy (`ACTOR_POLICY_*`), the
  second-approval gate (`ADMIN_SCRIPT_*`), and recovery snapshots (`SNAPSHOT_ENABLED_TABLES`) are
  ALL **opt-in** — with the relevant vars unset, the single-operator behavior is preserved.
  Mutations, however, now **hard-require** a tool-level `idempotencyKey` (fail-closed, not opt-in).

## D13 — Deferred-but-available (documented, no speculative code)

Per the plan's "Deferred" section — kept as tested helpers, wired only when the trigger exists:

- **B2 `scriptedRest` denylist (`sn/scripted-rest-denylist.ts`).** No generic `scriptedRest`
  RPC method exists today, so wiring the guard would protect nothing. The tested helper is kept
  (`url-and-path-guards.test.ts`); wire it when such a method is added. **Available-but-unwired by
  design** (finding: B2).
- **B7 keyset `paginate` (`sn/pagination.ts`).** `tableQuery` already returns an honest `partial`
  flag, so a stall/skip is visible without keyset pagination. Wire only if live P8 testing under
  the restrictive policy surfaces ACL blank-page stalls; otherwise **available-but-unwired**
  (finding: B7).

## Open / deferred

- `@cloudflare/workers-oauth-provider@0.7.0` storage round-trip (Phase 0.10) — to verify with a mock upstream in Phase 1 wiring.
- ServiceNow-side proofs (0.13a/c/e, §10) — blocked on a live PDI; see `OPEN_QUESTIONS.md`.
