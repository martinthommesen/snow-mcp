# Code Review — Codex Security Findings Remediation

**Date:** 2026-06-01
**Branch:** `main`
**Scope:** Eight Codex security findings raised against historical commits of `snow-mcp`
(`1b65b55`, `077a22f`, `5d8c593`, `27eb7c6`, `ca83b4b`, `8c6e1fd`, `dbd17bb`, `9a02e49`).
**Method:** Each finding was re-verified **against HEAD** (not trusted from its old-commit
description) because the repo has had several remediation passes since. Two findings were already
mitigated at HEAD; one was half-mitigated; the rest were fixed in this pass. Dispositions and
evidence below follow the `docs/CODE_REVIEW_2026-05-31.md` format.

---

## Disposition summary

| Codex finding | Severity | State at HEAD | Disposition |
|---|---|---|---|
| Unencoded sys_id path traversal | Med | already mitigated | verified-mitigated |
| Installer creds → unvalidated host | Med | open | fixed |
| Verifier creds → unvalidated host/path | Med | open | fixed |
| `/authorize` GET churns OAUTH_KV | Med | open | fixed (KV + admission cap) |
| Daily budgets exceeded by accrual | Med | half-mitigated (M-1 done) | fixed (reserve-max + refund) |
| Public `execute()` bypasses HMAC | High | open | fixed (capability handshake) |
| Upgrade ignores old kill-switch namespace | High | open | fixed (fail-closed on either) |
| Restrictive row filters bypassable | High | split | fixed (`tableGet`) + verified (`^OR` guard) |

---

## Findings

#### CDX-1 — Unencoded sys_id allows table path traversal — VERIFIED MITIGATED
- **File:** `packages/mcp-server/src/sn/validate.ts:58-63`, `packages/mcp-server/src/sn/rpc.ts:211,231,259`, `packages/mcp-server/src/sn/http.ts:51-70`
- **Category:** path traversal / SSRF
- **Disposition.** Already mitigated at HEAD. `validateSysId` enforces `/^[0-9a-f]{32}$/` before
  any path interpolation; `table`/`sys_id` are wrapped in `encodeURIComponent`; `SnFetchClient`
  rejects `..`/`%2e`/`@`/`://` and re-checks the post-`new URL()` pathname stays under `/api/`.
- **Evidence / tests.** `rpc-validation.test.ts` asserts a `../sys_user/<id>` sys_id is rejected
  pre-request (test "tableGet rejects a path-traversal sys_id") and a non-hex sys_id is denied;
  `url-and-path-guards.test.ts` covers the transport guard. No code change required.
- **Verdict:** confirmed mitigated.

#### CDX-2 — Installer admin credentials can be sent to an unvalidated host — FIXED
- **File:** `scripts/executor-install.mjs`
- **Category:** SSRF / credential exfiltration
- **Fix.** Canonicalize `SNOW_INSTANCE_HOST` through the existing
  `canonicalizeInstanceHost(host, { allowedHostSuffixes: ["service-now.com"] })`
  (`packages/mcp-server/dist/sn/url-allowlist.js`) before any credentialed fetch — the same guard
  `SnFetchClient`/`live-rpc-verify.mjs` use. Rejects userinfo, private/loopback IPs, and
  off-allowlist domains, so a tampered host cannot exfiltrate the admin Basic credential.
- **Evidence / verify.** `node --check` parses; an inline harness confirms `attacker.example`,
  `dev.service-now.com@attacker.example`, `127.0.0.1`, `evil.com` all throw `UrlNotAllowed`, while
  `dev12345.service-now.com` is accepted — pre-fetch, no live instance needed.
- **Verdict:** fixed.

#### CDX-3 — Verifier endpoint path can exfiltrate ServiceNow credentials — FIXED
- **File:** `scripts/executor-scoped-verify.mjs`
- **Category:** SSRF / credential exfiltration
- **Fix.** (a) Canonicalize the host as in CDX-2. (b) Add `assertApiPath()` mirroring
  `SnFetchClient`: `SNOW_EXECUTOR_PATH` must `startsWith("/api/")` and must not contain `://`,
  `@`, `..`, or `%2e`, validated before `ENDPOINT` is built.
- **Evidence / verify.** Inline harness confirms `.attacker.example/api/...`,
  `@attacker.example/api/...`, `/api/../../x`, `/api/%2e%2e/x`, `https://evil/api/x`, `/notapi/x`
  are all rejected; the default scoped path is accepted.
- **Verdict:** fixed.

#### CDX-4 — Unauthenticated `/authorize` GET can churn OAuth KV writes — FIXED
- **File:** `packages/mcp-server/src/auth/servicenow-auth-handler.ts:108-128`, new
  `packages/mcp-server/src/do/consent-rate.ts`, `packages/mcp-server/src/index.ts`,
  `packages/mcp-server/wrangler.jsonc` (binding `CONSENT_RATE_DO` + migration `v2`),
  `alchemy.run.ts` (the PRODUCTION deploy path — the binding MUST be declared here too, or the
  handler's `if (env.CONSENT_RATE_DO)` guard silently no-ops in prod)
- **Category:** availability / KV-write flood
- **Fix (kept KV, added admission control).** GET `/authorize` now (a) rejects an unknown OAuth
  client with 400 and (b) consults `ConsentRateDO.allow(clientId|ip, now)` BEFORE the
  `OAUTH_KV.put`, returning 429 over a per-(client_id + IP) rolling-window cap (30/60s). The DO
  holds counters **in memory only** (no per-request `ctx.storage` write) so the fix does not
  relocate the flood into DO storage; a DO eviction simply resets the window and re-engages. The
  server-side consent KV state (anti-tampering, commit `27eb7c6`) is preserved.
- **Residual / ops note.** Dynamic client registration (`/oauth/register`) remains enabled; the
  rate cap, not client-registration posture, is the bound. Operators who do not need DCR may
  disable it to remove the register-once-then-flood enabler.
- **Evidence / tests.** `do-partition.test.ts` (real DO via the pool): admits 30/window then
  denies, resets next window, isolates per key. `auth-surface.test.ts`: GET is 429'd with no
  consent page when the limiter denies; passes through when it allows; an unknown client is 400'd
  before the limiter is consulted.
- **Verdict:** fixed.

#### CDX-5 — Daily RPC/request budgets can be exceeded by the accrual path — FIXED
- **File:** `packages/mcp-server/src/do/budget.ts` (new `reconcile`), `packages/mcp-server/src/tools/run_code.ts`, `packages/mcp-server/src/tools/handlers.ts`
- **Category:** cost ceiling / concurrency overshoot
- **State at HEAD.** The M-1 part (dead `sandboxRpcCalls` ceiling) was already fixed —
  `sandboxRpcCalls` is in the admission loop (`budget.ts:101`). The remaining gap was concurrency
  overshoot: the pre-run reserve committed only `serviceNowRequests:1` while a run can spend up to
  200, so concurrent runs could collectively overshoot.
- **Fix (reserve-max + refund).** The pre-run reserve now commits the PER-RUN MAXIMUMS
  (`serviceNowRequests`/`sandboxRpcCalls` = `BUDGETS.perRun.*` = 200) plus `uniqueWorkers:1`, so
  admission checks at the true ceiling and concurrent overshoot is bounded by the cap. A new
  `BudgetDO.reconcile(signedDelta)` folds actuals back post-run — refunding the unused reservation
  (negative delta, clamped `>= 0`) and accruing the unreserved rows/bytes — through the same
  promise-chain mutex as `reserve`/`increment`. `run_code.ts` reconciles on **every** post-reserve
  exit (success, error, AND transpile failure before `RunBudget` exists → full refund), gated on a
  `reserved` flag rather than on `runBudget`. A dropped reconcile leaves the maximums reserved
  (over-counts → denies early → fail-closed).
- **Evidence / tests.** `do-partition.test.ts`: reserve-200-then-reconcile-to-actual refunds the
  difference; over-refund clamps at 0; the (N+1)th concurrent 200-reserve is denied once N×200 >
  cap. `run-code-pipeline.test.ts`: reconcile fires on success and error; fires (snapshot
  undefined) on a transpile failure AFTER reserve; does NOT fire on a pre-reserve early throw.
- **Verdict:** fixed (residual: a single run may still overshoot by ≤ one per-run ceiling — the
  same bounded, deny-next-run posture documented for rows/bytes).

#### CDX-6 — Public global `execute()` bypasses executor HMAC checks — FIXED (live-gate P8)
- **File:** `sn-executor-app/script-include/x_mcp_verify.js` + byte-synced `sn-executor-app/fluent/src/server/x_mcp_verify.js`; `sn-executor-app/fluent/src/server/x_mcp_executor.js`
- **Category:** auth-bypass / arbitrary code execution
- **State.** The split `execute(code)` ran `new Function(...)` with no in-code proof that
  `verify()` + the single-use nonce INSERT had occurred (only a comment). The Script Include is
  `access:"public"` (object-level — a single method cannot be made private) so the scoped wrapper
  can call it cross-scope; any server-side code in another accessible scope could call `execute()`
  directly. Note re-running `verify()` inside `execute()` is **insufficient** — a captured, still-
  fresh signed tuple would replay, because single-use lives only in the wrapper's nonce INSERT.
- **Fix (capability handshake bound to nonce consumption).** `execute(code, nonce, cap)` now
  requires `cap == HMAC(hmac_secret, 'x_mcp_exec_cap|' + nonce + '|' + SHA256(code))` and
  fail-closes (missing secret or any mismatch → `capability_required`, no eval). The SCOPED wrapper
  mints `cap` (it reads its own scoped secret and calls the global `_hmacBase64`, which takes the
  key as an argument so it is not a minting oracle) **only AFTER** the single-use nonce INSERT
  succeeds, then passes `(code, nonce, cap)`. A direct caller in another scope has no secret and
  cannot forge a cap; re-running `verify()` alone does not mint one. (Moving nonce validation into
  the public global method is infeasible — global scope cannot INSERT into the scoped
  `x_1793136_mcp_nonce` table.) Residual: an attacker would need the HMAC secret or a live
  in-process `cap`.
- **Evidence / verify.** Both verifier copies parse; `npm run check:verifier-sync` confirms the
  prototype bodies remain byte-identical. Full HMAC behavior (`GlideCertificateEncryption`/
  `GlideDigest`) is provable only on a PDI — **P8 live gate** (re-install required).
- **Verdict:** fixed (source); live-verify at P8.

#### CDX-7 — Executor upgrade ignores existing kill-switch properties — FIXED (live-gate P8)
- **File:** `sn-executor-app/fluent/src/server/x_mcp_executor.js:66-87`
- **Category:** safe-migration / fail-open
- **Fix (fail-closed on either namespace).** The executor now treats itself as disabled if EITHER
  the live `x_1793136_mcp.executor.{enabled,run_server_script_enabled}` OR the legacy
  `x_mcp.executor.*` property is explicitly `!= 'true'`. `gs.getProperty(name, 'true')` returns the
  default when a name is absent/unreadable, so a fresh scoped install (no legacy property) is
  unaffected and only an explicit legacy `'false'` disables — a strict-safety ADD that is never
  less safe than the prior code. An operator who disabled the executor before upgrading keeps it
  disabled.
- **Evidence / verify.** `node --check` parses. Whether a scoped app can read the legacy GLOBAL
  property cross-scope via `gs.getProperty` is pending **P8 live confirmation**; if blocked, the
  default makes the legacy check a no-op (no regression).
- **Verdict:** fixed (source); cross-scope read behavior verified at P8.

#### CDX-8 — Restrictive ActorPolicy row filters are bypassable — FIXED + VERIFIED
- **File:** `packages/mcp-server/src/sn/rpc.ts:223-251` (`tableGet`); `packages/mcp-server/src/sn/validate.ts:30-41` (`hasStructuralOperator`)
- **Category:** authz / row-filter bypass
- **Fix (tableGet).** `tableGet` previously did a direct `/api/now/table/{table}/{sys_id}` GET that
  never applied the mandatory `rowFilter` (unlike `tableQuery`/`aggregate`). When
  `hasMandatoryFilter(table)`, it now routes the single-record lookup through the filtered list
  endpoint — `sysparm_query = applyRowFilter(policy, table, 'sys_id=' + sysId)`, `limit 1` —
  returning the masked row or `null`. A record outside the filter (or absent) returns `null` with
  no existence leak. The fast direct-GET path is kept when no mandatory filter applies.
- **`^ORderby` escape — VERIFIED MITIGATED.** The structural-operator guard at HEAD is the
  hand-written `hasStructuralOperator` (not the regex in the Codex finding): it uses
  case-sensitive `startsWith("ORDERBY")` then uppercases the 2-char op, so `^ORderby` is denied as
  `^OR`. Covered by `rpc-validation.test.ts` ("still rejects a genuine `^OR` escape … `^ORderby`").
- **Evidence / tests.** New `rpc-validation.test.ts` cases: under a mandatory filter, `tableGet`
  routes through `/api/now/table/{table}` with `sysparm_query=active=true^sys_id=<id>` &
  `sysparm_limit=1`; a sys_id outside the filter resolves to `null`.
- **Verdict:** fixed (`tableGet`) + confirmed mitigated (`^OR` guard).

---

## Verification run

- `npm run typecheck` — clean.
- `npm test` — 30 files, 370 tests pass (incl. all new CDX-4/5/8 cases).
- `npm run check:verifier-sync` — both `x_mcp_verify.js` copies in sync after the CDX-6 change.
- Script SSRF guards (CDX-2/3) confirmed pre-fetch via inline harness (no live instance).
- **Live P8 gate (out of scope here):** CDX-6 and CDX-7 touch the ServiceNow executor `.js` and
  require a PDI re-install to verify HMAC/cap behavior and cross-scope property reads.
