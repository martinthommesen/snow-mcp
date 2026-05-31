# Code Review — ServiceNow MCP Server

**Date:** 2026-05-31
**Branch:** `harden/code-review-closeout`
**Scope:** Full-codebase security + correctness review of the ServiceNow MCP server (Worker host, Durable Objects, sandbox/executor path, OAuth flow, install/deploy scripts, and the scoped Fluent executor app).
**Method:** Multi-lens review with adversarial verification. Every finding below was challenged by 1–3 independent skeptic agents that re-read the cited code; only findings the skeptics upheld are reported. Two additional candidate findings were refuted during verification and dropped. "Confirmed" = majority of skeptics upheld; "uncertain" = split (none in this set).

---

## 1. Executive summary

Overall posture is **solid with one materially important gap**. The architecture is defense-in-depth: layered mode ceilings (scope/tenant/instance/actor-policy), an HMAC-signed + role-ACL-gated scoped executor, single-use nonces, idempotency ledgers, audit-before-effect, redaction, and an SSRF host allowlist. The hardening discipline shows: most issues found are *latent* (dead code, documentation drift, defense-in-depth gaps) rather than live, default-on vulnerabilities, and several previously-incident-shaped surfaces are now correctly default-off with live fail-closed guards.

The notable exception is a **real authorization asymmetry**: the per-actor `maxMode` ceiling is enforced on every read/write path but **not** on the most dangerous capability (`runServerScript` / arbitrary admin script). Two independent review lenses found this same gap, raising confidence. It is rated **high** (not critical) because exploitation requires a specific—but documented and architecturally-intended—operator configuration.

A recurring systemic theme is **fail-open on a degraded or absent control**: budget ceilings that are configured but never enforced, accrual that silently disables a daily ceiling on dependency failure, and guards described in comments as "live" that are in fact dead code. None of these is currently a confidentiality/integrity breach, but together they describe a pattern worth a dedicated hardening pass (see Themes).

### Counts by severity

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High     | 2 (one logical issue, found by two lenses) |
| Medium   | 7 |
| Low      | 5 |
| Info     | 8 |
| **Total kept** | **22 findings (21 distinct issues after merge)** |

The two **High** findings (`actor-authz-1` and `XCUT-auth-bypass-1`) are the **same defect** found independently by two review lenses; they are merged below as a single issue. Counting distinct issues, the review surfaced **21 distinct problems**.

---

## 2. Findings by severity

### HIGH

#### H-1 — `runServerScript` bypasses the actor-policy `maxMode` ceiling (the per-actor cap fails OPEN on the executor path)

- **File:** `packages/mcp-server/src/sn/rpc.ts:377–502` (absence of `assertActorPolicy`); contrast the read path at `rpc.ts:167` (`gateRead`) and the write path at `rpc.ts:260` (`tableUpdate`).
- **Category:** auth-bypass / fail-open
- **Found by:** two independent lenses (`actor-authz-1`, `XCUT-auth-bypass-1`) — **merged**. Independent rediscovery raises confidence that this is real and not an artifact of one reviewer's reading.

**Impact.** In `integration_user` credential mode (the documented default per `handlers.ts:149`), ServiceNow ACLs do not bound the shared integration identity, so `ActorPolicy.maxMode` is the host-side per-actor cap (`actor-policy.ts:1–6`). An operator who sets `ACTOR_POLICY_MAX_MODE=write` intends "this actor may read and write tables but **never** run arbitrary server-side scripts." That intent holds for every table read/write — but **not** for `runServerScript`, which executes arbitrary GlideScript at the executor app's privilege (ACL-bypassing). The least-privileged operations are blocked while the most-privileged one fails open.

**Evidence.**
- `runServerScript` (`rpc.ts:377–502`) authorizes only via `requireCapability(this.deps.effectiveMode, "runServerScript")` at `rpc.ts:386`, plus an *optional* approval preflight (`rpc.ts:463–471`) that exists only when `ADMIN_SCRIPT_*` env is configured (absent by default).
- `policy.maxMode` is enforced in exactly one place — `assertActorPolicy` at `actor-policy.ts:190` (`modeRisk(ctx.mode) > modeRisk(policy.maxMode)`). `runServerScript` never calls it.
- `policy.maxMode` is **not** threaded into `resolveEffectiveMode` (`effective-mode.ts:47–61`), which caps only by `min(scopeMaxMode, tenantMaxMode, instanceMaxMode)`. `handlers.ts:391–398` wires only those three; the policy is passed separately as `actorPolicy` and consulted only inside `assertActorPolicy`.
- Exploit precondition is reachable: `parseMaxMode(undefined)` returns `admin_script` (`handlers.ts:103`), so unset `TENANT_MAX_MODE`/`INSTANCE_MAX_MODE` impose no ceiling; with an OAuth scope granting `servicenow:admin_script`, `effectiveMode = min(admin_script, admin_script, admin_script) = admin_script`, `requireCapability` passes, and with no approval gate configured there is no second check.
- The class-level invariant at `rpc.ts:5` ("Every method — reads included — enforces, IN ORDER: ActorPolicy → effective-mode capability → per-run budget") is violated by the file's own most-dangerous method.
- Test gap: `actor-and-policy.test.ts:106–107` asserts `assertActorPolicy` denies `admin_script` under `maxMode:"write"` **in isolation**, but no test drives the `runServerScript` RPC against a restrictive `policy.maxMode`. This is exactly the "enforcement verified in isolation, not wired at the dangerous call site" incident class.

**Recommended fix.** Do **not** call `assertActorPolicy` here (it requires a `table` arg and would run the table allowlist, meaningless for arbitrary script). Instead add an explicit mode-ceiling re-check at the top of `runServerScript`, before signing/sending:

```ts
if (modeRisk(this.deps.effectiveMode) > modeRisk(this.deps.actorPolicy.maxMode))
  throw new McpToolError("actor_policy_denied", "admin_script exceeds this actor's maxMode.");
```

(import `modeRisk` from `@servicenow-codemode/shared`). Alternatively, thread `policy.maxMode` into `resolveEffectiveMode` as a fourth ceiling so the cap is applied uniformly. Add a unit test: `ACTOR_POLICY_MAX_MODE=write` + `effectiveMode` resolving to `admin_script` must make `runServerScript` throw `actor_policy_denied`, mirroring the existing `tableUpdate`/`tableQuery` denial.

**Mitigations that bound severity (why high, not critical).** Triggering requires *all* of: the executor wired, the OAuth scope legitimately granting `admin_script`, tenant/instance ceilings unset (or `admin_script`), and the approval gate unconfigured (the default). The scope/tenant/instance ceilings are redundant correct controls that *do* cap this path — an operator who sets `TENANT_MAX_MODE=write` is safe. What keeps it high: the documented *per-actor* knob silently fails to apply to the single most dangerous operation, in the exact credential mode where it is supposed to be the bound.

**Verdict:** confirmed (3/3 on `actor-authz-1`; 3/3 on `XCUT-auth-bypass-1`).

---

### MEDIUM

#### M-1 — Daily `sandboxRpcCalls` cap is configured but never enforced (dead ceiling)

- **File:** `packages/mcp-server/src/do/budget.ts:90–95, 139–147`
- **Category:** fail-open
- **Impact.** `BUDGETS.daily.sandboxRpcCalls = 100_000` (`config.ts:69`) can never fire. The only cap comparison is in `reserveCritical`'s requested-dimension loop, which `continue`s on any dimension with `inc <= 0` (`budget.ts:92`). The sole production `reserve()` call passes only `{ uniqueWorkers: 1, serviceNowRequests: 1 }` (`handlers.ts:223`), so `sandboxRpcCalls` never reaches `would > caps[d]`. It is only ever written via `increment`/`incrementCritical`, which never compare to caps. Practical overrun is bounded by the `uniqueWorkers` backstop (1000 workers × per-run `rpcCallLimit` 200 = ~200k/day vs the 100k cap — ~2× over), and widens unbounded if either limit is raised.
- **Evidence.** `budget.ts:91–92` `const inc = req[d] ?? 0; if (inc <= 0) continue;`; `handlers.ts:223` reserve req omits `sandboxRpcCalls`; `incrementCritical` (`budget.ts:139–147`) does `cur + inc` puts with no cap check. Of the five `daily` dimensions, four are enforced (uniqueWorkers + serviceNowRequests via reserve; rowsReturned + bytesReturned via the admission loop); `sandboxRpcCalls` is the only one covered by neither, with no "telemetry only" comment.
- **Recommended fix.** Either (a) gate `sandboxRpcCalls` in `reserveCritical` with a daily admission check analogous to rows/bytes (deny the next run when `current.sandboxRpcCalls >= caps.sandboxRpcCalls`), or (b) remove the dead cap and its comment so it is not mistaken for an enforced ceiling. Add a test asserting a run is denied once `dim:sandboxRpcCalls` is at/over cap.
- **Verdict:** confirmed (1/1).

#### M-2 — Persistent `BUDGET_DO` failure silently disables the daily rows/bytes ceiling (fail-open)

- **File:** `packages/mcp-server/src/tools/run_code.ts:200–212`
- **Category:** fail-open
- **Impact.** The daily rows/bytes ceiling is enforced only by `reserveCritical`'s admission check (`budget.ts:85–87`), which reads `dim:rowsReturned`/`dim:bytesReturned` — counters written only by the post-run accrual path. `run_code.ts` wraps `accrueDailyBudget` in a try/catch that swallows errors to `console.error`. If `BUDGET_DO` is persistently unavailable, accrual never lands, the counters stay at 0, and the admission check never trips — the daily ceiling silently degrades to per-run caps + the `uniqueWorkers` daily backstop. This is the errors→grant-instead-of-deny pattern. (Note: the *pre-run* `reserveDailyBudget` is **not** wrapped, so a fully-down DO fails closed; the fail-open materializes specifically in the partial-failure window where reserve succeeds but accrual fails.)
- **Evidence.** `run_code.ts:200–211` catch swallows after `await deps.accrueDailyBudget(...)`; the in-code comment at `run_code.ts:204–209` self-documents the exact hazard. `budget.ts:85–87` is the sole enforcement point for those dims.
- **Recommended fix.** Treat repeated accrual failures as a hard signal: emit a metric/alert an SRE gate can act on, or fail the *next* reserve closed after a streak of accrual failures. At minimum, keep the `uniqueWorkers` daily cap low enough to bound worst-case cost when rows/bytes enforcement is down.
- **Verdict:** confirmed (1/1).

#### M-3 — Snippet logs bypass the output byte cap (uncapped, unmetered) — response-side DoS

- **File:** `packages/mcp-server/src/tools/run_code.ts:159, 167, 178, 189` (serialize at 181; `SIZE_LIMITS` at `config.ts:54–56`)
- **Category:** reliability / cap-bypass
- **Impact.** The 256KB output cap is enforced only on the snippet's return value (`serializeResult(exec.result, SIZE_LIMITS.maxOutputBytes)` at line 181). `exec.logs` is spliced verbatim into `structuredContent.logs` on all four return paths with no truncation and no byte/count limit. The codemode executor builds `__logs` via `console.log = (...a) => __logs.push(...)` with no cap, and log bytes are never counted by `runBudget.countBytes` (which only meters ServiceNow payloads). A snippet doing `for(;;) console.log("x".repeat(1e6))` returns a trivial result but produces a `logs` field bounded only by sandbox memory (~128MB) and the 30s timeout — orders of magnitude past the documented cap, inflating the tool-result payload and host-side memory. No secret leakage (sandbox holds no secrets); impact is availability/cap-bypass.
- **Evidence.** `run_code.ts:181` caps only the result; `logs: exec.logs ?? []` at 159/167/178/189 with no truncation; codemode `console.log` capture has no length limit; `config.ts` `SIZE_LIMITS` defines only `maxCodeBytes`/`maxOutputBytes`.
- **Recommended fix.** Add `maxLogBytes`/`maxLogEntries` to `SIZE_LIMITS`; truncate `exec.logs` via a shared helper used by all four return paths (set a `logsTruncated` flag). Optionally meter cumulative log bytes against `runBudget`.
- **Verdict:** confirmed (1/1).

#### M-4 — Opt-in global REST endpoint is HMAC-only with no role ACL

- **File:** `scripts/executor-install.mjs:211–226`
- **Category:** missing-authorization
- **Impact.** When `X_MCP_INSTALL_GLOBAL_REST=1`, the installer creates a global Scripted REST op with `requires_acl_authorization:"false"` (line 224) — gated solely by HMAC, the same no-role-ACL shape as the incident endpoint, fronting an arbitrary server-script eval surface. It is **default-OFF** and its reject guard is live (fail-closed), unlike the incident's dead guard. Residual risk: if opted in on production, any authenticated user reaching the endpoint is gated only by the shared HMAC secret, with no executor-role backstop (the scoped wrapper additionally requires the executor role).
- **Evidence.** Line 224 `requires_authentication:"true", requires_acl_authorization:"false"`, `relative_path "/executor/run"`, no role ACL; the embedded script runs `new x_mcp_verify().execute(code)`. Default-off gate at lines 22/215; live `if (!v.verified)` boolean guard at line 175.
- **Recommended fix.** Keep default-OFF as reference only; if it must exist, attach a role ACL mirroring the scoped executor ACL gate.
- **Verdict:** confirmed (1/1). *(See also L-3, which is the same surface from the auth-bypass lens — merged conceptually.)*

#### M-5 — Install self-test can leave the executor kill-switch disabled on mid-test failure

- **File:** `scripts/executor-install.mjs:303–312`
- **Category:** reliability
- **Impact.** The S9 kill-switch self-test sets `x_1793136_mcp.executor.enabled='false'` (line 305), waits, calls, then re-enables to `'true'` (line 308) — with **no try/finally**. If the process is interrupted (SIGINT) or any awaited call throws between 305 and 308 (`fetch` is not `.catch`-guarded; only `r.json()` is), the property is left `'false'` and the **live** executor stays disabled. This is a shared scoped-namespace property the production Fluent wrapper reads (`x_mcp_executor.js:67`), so a leaked `false` silently DoS's the production delegation path (`run_code` admin_script → 503 `executor_disabled`), discovered only when real calls start failing.
- **Evidence.** Lines 305/308 setProperty calls with two awaited timeouts + an awaited `call()` between them, no try/finally; `call()` (251–256) leaves `fetch` un-guarded.
- **Recommended fix.** Guard the toggle with try/finally so `enabled` is restored regardless of outcome, or read+restore the prior value rather than hardcoding `'true'`.
- **Verdict:** confirmed (1/1).

#### M-6 — Field masks not applied to `sysparm_query` predicates — masked values inferable via row-selection / aggregate oracle

- **File:** `packages/mcp-server/src/sn/rpc.ts:178–208, 231–252`; `packages/mcp-server/src/authz/actor-policy.ts:196–230`; `validate.ts:128–135` *(note: actor-policy lives at `src/authz/`, not `src/sn/`)*
- **Category:** injection / confidentiality
- **Impact.** `ActorPolicy.fieldMasks` is documented (§2.12) to strip forbidden fields from request **and** response. It is enforced on the requested `fields` and stripped from returned rows (`maskRow`), but **nothing inspects the caller-supplied `sysparm_query` predicate** for masked-field references. `validateUserQuery` only checks structural operators (and only when a mandatory `rowFilter` is present); `applyRowFilter` only AND-composes. So a snippet can filter *on* a masked column without requesting it: `tableQuery({table:'sys_user', query:'salary>500000', fields:['name']})` returns exactly the rows whose masked salary exceeds the threshold (binary-search reconstructs the value); `aggregate({table, query:'ssn=...', groupBy:['dept']})` is a single-query equality oracle. `aggregate`'s `groupBy`/`countField` *are* mask-checked, but its `query` is not. In `integration_user` mode the mask is the sole field-level confidentiality barrier, and it is bypassed for read selection.
- **Evidence.** `userQuery` passed to ServiceNow verbatim after only structural-op + rowFilter checks; `assertRequestedFieldsAllowed`/`maskRow` operate on `fields` and response rows only; `applyRowFilter` does `userQuery ? \`${mandatory}^${userQuery}\` : mandatory` with no predicate inspection.
- **Recommended fix.** Parse the caller query's field references (token before each operator in each `^`-separated clause, plus `ORDERBY`/`GROUPBY` targets) and reject any matching a `fieldMask` (reuse the dot-aware `isMaskedBy` logic), in `validateUserQuery`/`applyRowFilter`. Apply identically to `tableQuery` and `aggregate`. Fail with `actor_policy_denied`.
- **Verdict:** confirmed (1/1). Deployment-gated (requires a restrictive policy with `fieldMasks` configured) and an inference channel for an already-authenticated sandbox actor, but within that posture the only confidentiality barrier is fully defeated.

#### M-7 — Outbound ServiceNow fetch follows redirects with the Authorization bearer attached, never re-validating the post-redirect host

- **File:** `packages/mcp-server/src/sn/http.ts:65–99`
- **Category:** ssrf
- **Impact.** `SnFetchClient.request` builds the URL against the canonicalized allowlisted host, then calls `fetchImpl(url.toString(), {...})` with **no `redirect` option** — the workerd default is `redirect:'follow'`. The Authorization header (live OAuth bearer / Basic credential) rides along. Cloudflare's runtime forwards `Authorization` across cross-origin redirects (unlike browsers, which strip it). The SSRF allowlist (`canonicalizeInstanceHost`) validates only the **initial** host in the constructor; there is no post-fetch check of `res.url`. A 3xx from the instance (open redirect, compromised/misconfigured endpoint, on-path MITM) transparently steers the credential-bearing request to an arbitrary host — credential exfiltration + off-allowlist egress, defeating the advertised S15 guard.
- **Evidence.** `http.ts:78` `fetchImpl(url.toString(), { ... headers: { authorization, ... }, signal: ac.signal })` — no `redirect:` key; line 88 reads `res.text()` without inspecting `res.url`/`res.redirected`. Constructor SSRF guard runs once (line 47).
- **Recommended fix.** Set `redirect:'manual'` (or `'error'`) and treat any 3xx as a failed request — ServiceNow Table/scripted-REST APIs return data directly with no legitimate cross-host redirect. If redirects must ever be supported, re-run `canonicalizeInstanceHost` on `res.url`'s host before following and strip `Authorization` on host change.
- **Verdict:** confirmed (1/1). Medium (not high): the redirect must originate from the otherwise-trusted allowlisted instance; it is not an unconditional external-attacker primitive. Impact (live credential exfiltration) and the explicit mandate flagging redirect-following keep it above low.

#### M-8 — KEK/secret derived from passphrase via unsalted single-iteration SHA-256 — offline dictionary attack on leaked envelopes

- **File:** `packages/mcp-server/src/auth/crypto.ts:118–121, 151–160`
- **Category:** crypto
- **Impact.** `deriveKeyBytes()` converts a deployment secret to a 32-byte AES-256/HMAC key with a single SHA-256 over the raw string — no salt, no KDF stretching. `buildKekRing()` feeds `TOKEN_KEK_*`/`SNAPSHOT_KEK_*` through it, and `servicenow-ticket.ts` feeds `OAUTH_PROVIDER_SECRET` through it for the reauth-ticket HMAC. The code's own comments invite low-entropy inputs ("Lets a KEK secret be any string"; "any passphrase works as the HMAC key"), and the README documents these as "passphrase" values with no entropy/CSPRNG guidance. Envelopes store cleartext AAD + auth tag, giving an oracle-free correctness check; an attacker with leaked envelopes (DO compromise, KV/backup leak) mounts an offline guessing attack at ~1 SHA-256 + 1 AES-GCM per candidate. No salt → amortizes across deployments, rainbow-table-friendly.
- **Evidence.** `crypto.ts:119` `crypto.subtle.digest("SHA-256", enc.encode(secret))` — single hash, no salt/iteration. The only length check (`importKey`, `crypto.ts:38`) runs on the 32-byte *output*, never constraining input entropy.
- **Recommended fix.** Either (a) require the secret to be a base64/hex-encoded 32-byte random value and reject anything else, or (b) replace bare SHA-256 with a salted KDF (PBKDF2-HMAC-SHA256 with a per-deployment salt + high iterations, or HKDF if input is already high-entropy). At minimum, document and enforce CSPRNG generation (`openssl rand -base64 32`) for `TOKEN_KEK*`/`SNAPSHOT_KEK*`/`OAUTH_PROVIDER_SECRET`.
- **Verdict:** confirmed (1/1). Gated on two preconditions (envelope leak *and* a low-entropy operator-chosen secret); a 32-byte CSPRNG secret makes single-SHA-256 cryptographically fine. The exposure is the accepted-weak-input affordance — a real defense-in-depth weakness, not a live bypass.

---

### LOW

#### L-1 — Scripted-REST denylist is dead code; comments overstate it as a live, wired guard

- **File:** `packages/mcp-server/src/sn/scripted-rest-denylist.ts:1–66`; `http.ts:52–55`; `rpc.ts` (no caller)
- **Category:** fail-open / documentation drift
- **Found by:** two lenses (`sn-rpc-egress-1` at low, `XCUT-egress-injection-3` at info) — **same issue, merged**; reported at the more conservative of the two non-trivial severities.
- **Impact.** `checkScriptedRestPath()`/`DENY_PATTERNS` (blocking `/executor`, `sys_properties`, `x_mcp_audit_log`, `oauth_*.do`, `login.do`) have **zero production callers**; there is no `scriptedRest` method in `ServiceNowRPC.fns()` (only tableQuery/tableGet/aggregate/tableUpdate/runServerScript). Yet `http.ts:52–55` states the denylist "is enforced by the generic `scriptedRest` RPC method (§3.2), NOT here," and the module header frames itself as the live guard. Not exploitable today (no generic-path surface exists), but it is the exact recent-incident class — a guard asserted active in comments but not on any live path. A Phase-5.6 author adding a `scriptedRest` tool could trust the comment and not wire the denylist in.
- **Evidence.** `grep` finds `checkScriptedRestPath` only in its module and tests; `fns()` (`rpc.ts:526–534`) exposes no `scriptedRest`; the `http.ts` comment claims an enforcing method that does not exist.
- **Recommended fix.** Reword the `http.ts`/denylist comments to "defined but not yet wired," or remove the module until the tool exists; add a lint/test guard that any future `scriptedRest` path goes through `checkScriptedRestPath()`.
- **Verdict:** confirmed (1/1 each lens).

#### L-2 — Audit intent→outcome supersede breaks across UTC midnight, orphaning an `intent` row

- **File:** `packages/mcp-server/src/tools/handlers.ts:316–324` (key built at 319)
- **Category:** data-integrity
- **Impact.** The audit design relies on the `intent` row and the later outcome row sharing the same KV key so the outcome supersedes the intent. `auditKey` is built from `utcDateKey()` recomputed fresh on every `put` (handlers.ts:319), and intent/outcome are separate puts around the network effect. A mutation straddling UTC midnight (intent at 23:59:59 day D, outcome at 00:00:01 day D+1) lands the two rows on different keys; the day-D key retains status `intent` permanently (until 30-day TTL), so an auditor sees a perpetually-unresolved intent for a mutation that completed. Audit-integrity only — the ledger (not the audit row) holds exactly-once safety, and the failure direction is "reads unresolved," never "false success."
- **Recommended fix.** Compute `utcDateKey` once per guarded mutation (from `guard.now()` at intent time) and reuse it for the outcome write; or key the audit event solely on `requestId/ordinal` and rely on KV TTL.
- **Verdict:** confirmed (1/1).

#### L-3 — Opt-in deprecated global REST endpoint is HMAC-only (`requires_acl_authorization:false`)

- **File:** `scripts/executor-install.mjs:215–226`
- **Category:** auth-bypass
- **Note:** This is the same surface as **M-4**, from the auth-bypass lens (`install-deploy-scripts-3`). It is recorded here for completeness; treat M-4 as the canonical entry. Re-arming the flag deploys a second, weaker-authorized endpoint alongside the scoped one; if the shared `X_MCP_EXECUTOR_HMAC_KEY` leaks, this endpoint executes arbitrary script with no role check.
- **Recommended fix.** Consider dropping the global-REST install path entirely now that the scoped Fluent wrapper is canonical, or add a loud install-time warning; ensure scoped-verify S8b also asserts the scope-name form `/api/x_mcp/executor/run` is absent, not just the numeric form.
- **Verdict:** confirmed (1/1).

#### L-4 — No runtime assertion couples `AUDIT_KV`/`LEDGER_DO` presence to mutating mode; `HandlerEnv` re-declares `LEDGER_DO` optional

- **File:** `packages/mcp-server/src/tools/handlers.ts:41–49, 304–324, 372–381`
- **Category:** reliability / hygiene
- **Impact.** `guardMutation` treats the idempotency ledger and durable audit sink as optional; both are attached only when their bindings are truthy. If either is absent at runtime, mutations still proceed with replay/dedup silently disabled and/or audit-before-effect never armed. `HandlerEnv.LEDGER_DO` is optional (`handlers.ts:45`) while the worker `Env.LEDGER_DO` is required (`index.ts:27`) — a type divergence. The mandatory `runKey` gate still fires independently, so this never bypasses the idempotencyKey requirement; it only soft-degrades the replay/audit layers under a non-standard config (the committed `wrangler.jsonc` binds both, so a standard deploy is unaffected). Reported as a hygiene gap, not a live fail-open.
- **Recommended fix.** Add a mode-time assertion: when a mutation runs in write/admin_script mode, require `guard.ledger` and `guard.audit` (or assert the bindings at handler-build time for non-read-only deployments) and fail closed otherwise. Align `HandlerEnv.LEDGER_DO` with the required worker `Env`.
- **Verdict:** confirmed (1/1).

#### L-5 — Discovery read paths count rows but not bytes (per-run + daily byte accounting gap)

- **File:** `packages/mcp-server/src/sn/discovery.ts:101, 142`
- **Category:** data-integrity
- **Impact.** `describeTable` (101) and `listTables` (142) call `runBudget.countRows(...)` but never `countBytes()` on the serialized payload, whereas every `rpc.ts` read path counts both (`rpc.ts:206, 227, 250`). The per-run byte ceiling and the daily `dim:bytesReturned` counter both exclude discovery bytes. Bounded by `TABLE_PAGE_CAP=1000` rows/call and rpc/SN per-run call limits, and the payload is low-sensitivity schema metadata — but a snippet can return more bytes than the byte budgets account for by routing reads through discovery.
- **Recommended fix.** After `countRows` in both functions, add `deps.runBudget.countBytes(utf8Len(JSON.stringify(<returned payload>)))` measuring the masked/mapped output, matching the `rpc.ts` pattern.
- **Verdict:** confirmed (1/1).

#### L-6 — Nonce purge run period serializes to a bad string and needs a manual fix

- **File:** `sn-executor-app/fluent/src/fluent/x_mcp.now.ts:110–133`
- **Category:** reliability
- **Impact.** The now-sdk serializer turns the 15-minute execution-interval `Duration` into an invalid `run_period` string (`"[object Object]"`), so the interval must be set by hand after each install (documented in an in-source "P8 MANUAL FIX REQUIRED" comment). If skipped, the purge job does not run and the nonce table grows unbounded. **Fail-safe** for replay (more retained nonces only strengthen the unique-index defense, which is independent of the purge), so this is a storage/operational gap, not a security one.
- **Recommended fix.** Add the `run_period` fixup to the install/verify harness, or assert the interval in the scoped verify script.
- **Verdict:** confirmed (1/1).

---

### INFO

#### I-1 — `redirect_uri` sent to ServiceNow is derived from the attacker-influenceable request Host, not pinned config

- **File:** `packages/mcp-server/src/auth/servicenow-callback-handler.ts:99–101, 135, 165`
- **Category:** open-redirect / hardening
- **Impact.** `/servicenow/authorize` builds `redirect_uri = ${url.origin}/servicenow/callback` (line 135), where `url.origin` reflects the request Host. The origin guard validates only the Origin *header* and explicitly allows requests with no Origin (`origin.ts:49`), so a non-browser request with a spoofed Host can make the worker emit an attacker-chosen `redirect_uri`. **Bounded to near-nil:** the flow is gated by an unforgeable host-HMAC ticket; the token is exchanged/stored server-side under `record.userId` and never sent to the redirect host; the PKCE verifier lives only in the DO; and ServiceNow rejects any unregistered `redirect_uri`. Worst realistic case is a self-inflicted failed flow. The trust-boundary smell (a security-relevant value from the request host, not pinned config) is real; the exploitable risk is informational.
- **Recommended fix.** Derive `redirect_uri` (and the authorize URL in `handlers.ts:168`) from a configured canonical public origin (`WORKER_PUBLIC_ORIGIN`), or validate `url.origin` against an allowlist before use.
- **Verdict:** confirmed (1/1).

#### I-2 — Anti-CSRF nonce stored in the correlation record but never verified at the callback (effectively dead)

- **File:** `packages/mcp-server/src/auth/servicenow-callback-handler.ts:126, 143–188`
- **Category:** correctness / documentation drift
- **Impact.** The ticket nonce is copied into `AuthCorrelationRecord` at `/authorize` (line 126) and documented as an "anti-CSRF nonce … defense in depth," but `handleCallback` never reads `record.nonce` — the field is write-only. The real CSRF/replay protection is the opaque single-use `state` (atomic read-then-delete in the DO), which is sound. Purely documentation drift: a reader may believe a second correlation check exists when it does not.
- **Recommended fix.** Remove the nonce field and correct the comments so the opaque single-use state is documented as the sole CSRF control, or actually bind/verify the nonce if defense-in-depth is wanted.
- **Verdict:** confirmed (1/1).

#### I-3 — `scopeMaxMode` from OAuth props not validated with `isValidMode` (defensive gap, not exploitable)

- **File:** `packages/mcp-server/src/index.ts:95`
- **Category:** fail-open / consistency
- **Impact.** `const scopeMaxMode = (props.maxMode as Mode) ?? "read_only"` uses `??`, which only substitutes null/undefined — a set-but-invalid string would pass through, inconsistent with `parseMaxMode`/`loadActorPolicy`, which coerce invalid values to `read_only`. **Not exploitable:** the sole writer (`maxModeFromScopes`) always returns a valid Mode, props come from the validated grant, and even an invalid value would be displaced by `minByRisk` (`modeRisk` returns `+Infinity` for non-Modes), so it can never raise the ceiling. Flagged only because the mandate targets `||`/`??`-to-permissive defaulting and the hardening pattern is applied everywhere else.
- **Recommended fix.** `const scopeMaxMode = isValidMode(props.maxMode) ? props.maxMode : "read_only";`
- **Verdict:** confirmed (1/1).

#### I-4 — `userId` defaults to `"operator"` in SchemaCache key — safe under the single-operator grant model

- **File:** `packages/mcp-server/src/index.ts:104, 424`
- **Category:** correctness / latent landmine
- **Impact.** `userId = (props.userId as string) ?? "operator"` threads into the SchemaCache identity. The cache exists to prevent ACL-filtered field visibility leaking across users. It cannot collapse two users today: the only OAuth grant site hardcodes `userId:"operator"` in both credential modes; per-user SN identity rides the reauth ticket, not the MCP grant props. The `??` default (and the fact `??` does not catch `""`) is a latent landmine **only** if a future change emits per-user `userId` props.
- **Recommended fix.** No change required now. If per-user MCP grants are introduced, reject empty/missing `userId` at the SchemaCache boundary (treat `""`/undefined as a hard error, not a shared default).
- **Verdict:** confirmed (1/1).

#### I-5 — Top-level / apiHandler catch blocks log `e.message` without redaction

- **File:** `packages/mcp-server/src/index.ts:112, 153`
- **Category:** secret-leakage (server-log hygiene)
- **Impact.** Both catches `console.error(prefix, e instanceof Error ? e.message : String(e))` with no `redactString()` pass, unlike `sn/errors.ts` (which scrubs via `redactString`). These wrap the post-OAuth MCP handler and provider/callback routing. The client-facing response is correctly generic (`{error:'internal_error'}`), so this is server-log hygiene, not a client leak. No concrete secret-bearing message was proven to reach these specific catches (the cited `servicenow_oauth_failed` is built from non-secret OAuth error fields and is caught elsewhere), so reported as info. *(A more direct instance of the same unredacted-log class exists at `servicenow-callback-handler.ts:167`.)*
- **Recommended fix.** Wrap the logged message in `redactString()` at both sites (import from `observability/redact.js`), matching `sn/errors.ts`.
- **Verdict:** confirmed (1/1).

#### I-6 — `rpc.ts` executor path defaults to the global scope-name endpoint when `SNOW_EXECUTOR_PATH` is unset

- **File:** `packages/mcp-server/src/sn/rpc.ts:416`
- **Category:** endpoint-mismatch / fail-closed-by-design gap
- **Impact.** `path: this.deps.executorPath ?? "/api/x_mcp/executor/run"`. In production the default is unreachable — `handlers.ts:276/406` gate `executorReady` on `SNOW_EXECUTOR_PATH` and always pass it non-null, and the signing guard throws when signing is absent. The default `/api/x_mcp/executor/run` is **neither** the production scoped path **nor** the deprecated numeric incident path; it is a malformed/legacy guess that most plausibly 404s, so a future caller hitting it would fail (accidentally fail-closed) rather than route signed traffic to the un-ACL'd surface. The valid hardening point: a security-critical executor path should fail closed by *throwing* on undefined rather than falling back to a hardcoded guess.
- **Recommended fix.** Make `executorPath` required when signing is present (throw if undefined) instead of defaulting.
- **Verdict:** confirmed (1/1). *(One skeptic corrected the original "routes to the weaker surface" framing — the realistic worst case is a 404, hence info.)*

#### I-7 — Deprecated standalone scripted-rest reference still contains the literal incident bug (dead `!object` reject = full signature bypass) if ever installed

- **File:** `sn-executor-app/scripted-rest/x_mcp.executor.run.js:55–58`
- **Category:** fail-open / latent landmine
- **Impact.** This reference executor calls `if (!new x_mcp.x_mcp_verify().verify(code, actor, sig)) { ...401... }`. The unified `verify()` now returns an **object** `{verified:boolean}` (`x_mcp_verify.js:115–145`), and `!{}` is always false — the reject branch is **dead code**, so every request (forged/unsigned/stale/replayed) falls through to `new Function(... code)` at server privilege. The precise twin of the recent incident. Mitigated today purely by process: the file header says "do NOT install this," it is not in the default install path, the opt-in global endpoint uses the correct object-aware check, the production Fluent wrapper does `if (!v.verified)` correctly, and the host-side denylist would block executor-shaped paths. No live impact — but a copy-pasteable full-bypass landmine of exactly the class that caused the incident.
- **Recommended fix.** Delete the deprecated file outright (safest given incident history), or change its guard to `if (!new x_mcp.x_mcp_verify().run(code, actor, sig).verified)`.
- **Verdict:** confirmed (1/1).

#### I-8 — Executor HMAC key encoding contract is unverified (host decodes base64 vs verifier passes string) — Phase 0.13a seam

- **File:** `packages/mcp-server/src/tools/handlers.ts:86–88, 286`
- **Category:** crypto (deployment/functionality risk)
- **Impact.** The host signs with `hmacKey = b64ToBytes(X_MCP_EXECUTOR_HMAC_KEY)` (base64-decodes to raw bytes), while the in-scope verifier calls `GlideCertificateEncryption.generateMac(key, 'HmacSHA256', message)` with `key = gs.getProperty(...hmac_secret)` and a TODO(0.13a) noting the exact key encoding is unconfirmed for the target family. If the two sides disagree on raw-vs-base64, the MACs won't match. **Not a security weakening:** a mismatch, empty key, or null MAC all produce a non-matching signature → `verify` false → 401 (fail CLOSED). It is a deployment risk on a path the code itself flags "UNVERIFIED IN THIS BUILD."
- **Recommended fix.** Before enabling the executor, pin the key-encoding contract in one place and add a deploy-time round-trip check that a host-signed sample verifies in-scope, so a silent all-401 is caught.
- **Verdict:** confirmed (1/1).

---

## 3. Themes — systemic patterns

**T-1: Fail-open on a degraded or absent control.** The most consistent pattern. Distinct instances:
- **Dead ceilings:** the daily `sandboxRpcCalls` cap is configured but never reaches a comparison (M-1); discovery bytes are never metered (L-5). A ceiling that exists in config but not in the enforcement path reads as "protected" while protecting nothing.
- **Dependency-failure degradation:** persistent `BUDGET_DO` accrual failure silently disables the daily rows/bytes ceiling (M-2); absent `AUDIT_KV`/`LEDGER_DO` bindings soft-degrade replay/audit (L-4). The asymmetry in M-2 (pre-run reserve fails *closed*, post-run accrue fails *open*) is the subtle, latent hazard.
- **Guard-described-but-not-wired:** the scripted-REST denylist is dead code while comments assert it is the live guard (L-1). This is the *exact* shape of the recent incident — a guard claimed active in comments/config but absent from the live path.

**Recommendation:** adopt a rule that every configured ceiling has a test proving it can *deny*, and every "enforced by X" comment is backed by a wiring test. M-1, M-2, and L-1 would all have been caught by such tests.

**T-2: Authorization-check coverage gaps at the dangerous call site.** H-1 is the headline: a per-actor cap verified in isolation but not wired into the most dangerous method. M-6 is the same shape at the data layer — masks enforced on `fields`/responses but not on query predicates. Both are "the check exists and works when called; it just isn't called where it matters most." The class-level invariant comment in `rpc.ts:5` actively *misleads* here. **Recommendation:** treat every privileged sink (`runServerScript`, query predicates) as requiring an explicit, tested authorization assertion at the sink, not an inherited one.

**T-3: Crypto and secret-handling rely on operator discipline rather than enforcement.** M-8 (unsalted single-SHA-256 KDF accepting any-string secrets) and I-8 (unverified HMAC key-encoding contract) both fail safe *if* operators supply high-entropy, correctly-encoded secrets — but neither enforces or verifies that. **Recommendation:** validate secret entropy/encoding at startup and add a deploy-time HMAC round-trip check.

**T-4: Latent incident-twins kept as reference.** I-7 (a copy-pasteable full-bypass reference file) and L-3/M-4 (an opt-in no-role-ACL endpoint) are both default-off and process-gated, but both reproduce the incident's exact shape and sit next to live code. **Recommendation:** delete reference copies of known-dangerous patterns rather than commenting "do not install."

**T-5: Egress trust boundaries derived from request-controlled values.** M-7 (redirect-following with bearer attached, no post-redirect host check) and I-1 (`redirect_uri` from request Host) both build security-relevant egress targets from values the caller can influence. **Recommendation:** pin egress targets to config; set `redirect:'manual'`.

---

## 4. Coverage & residual risk

**Reviewed (static, full-codebase, multi-lens + adversarial verification):**
- Worker entrypoint and routing (`index.ts`), OAuth provider + ServiceNow callback flow (`auth/*`, ticket/correlation, PKCE, redirect_uri).
- Mode/authorization stack: scope/tenant/instance ceilings (`effective-mode.ts`), actor policy + field masks + row filters (`authz/actor-policy.ts`), capability gating (`config.ts`), and the RPC enforcement order (`sn/rpc.ts`).
- Sandbox/codemode execution path (`tools/run_code.ts`), output/log capping, RPC byte/row metering.
- Budgets and Durable Objects (`do/budget.ts`, reserve/accrue), idempotency ledger, audit-before-effect (`tools/mutation-guard.ts`, `handlers.ts`).
- ServiceNow egress (`sn/http.ts` SSRF allowlist + redirects, `discovery.ts`, scripted-rest denylist).
- Crypto/secrets (`auth/crypto.ts` KEK ring, envelope AAD, HMAC ticket).
- Install/deploy tooling (`scripts/executor-install.mjs`) and the scoped Fluent executor app (`sn-executor-app/*`, `x_mcp_verify.js`, kill-switch, nonce purge).
- Observability/redaction (`audit.ts`, `origin.ts`, `redact.ts`).

**Residual risk — areas warranting deeper manual / dynamic testing:**

1. **Executor key-encoding live verification (I-8).** The host↔verifier HMAC contract is explicitly unverified for the target ServiceNow family. This needs a live PDI round-trip before the executor goes GA — a static review cannot resolve `GlideCertificateEncryption.generateMac`'s key interpretation.

2. **Redirect behavior of the production runtime (M-7).** Confirm under live workerd that a 3xx from the instance does (or, after the fix, does not) forward `Authorization`. The fix should be validated dynamically, not just by code inspection.

3. **Budget enforcement under partial DO failure (M-2, M-1).** The fail-open windows (accrual succeeds-but-fails, dead `sandboxRpcCalls` cap) are best confirmed with fault-injection / chaos testing against the real `BUDGET_DO`, measuring actual daily overrun versus configured caps.

4. **Field-mask inference channel (M-6).** Warrants a dynamic test harness driving `tableQuery`/`aggregate` with predicates on masked columns against a real instance, to confirm the oracle and then to confirm the predicate-parser fix rejects all masked-field references (including dot-walked and `ORDERBY`/`GROUPBY` forms).

5. **End-to-end OAuth flow with spoofed Host / absent Origin (I-1).** A live test that a non-browser client with a forged Host cannot complete a token-bearing flow would convert the I-1 reasoning from static argument to evidence.

6. **The actor-policy ceiling on the executor path (H-1).** After the fix lands, an integration test must drive the full `run_code` → `runServerScript` dispatch (not just `assertActorPolicy` in isolation) under a restrictive `ACTOR_POLICY_MAX_MODE`. The absence of this test is itself part of the finding.

7. **Install-script interrupt paths (M-5).** The kill-switch leak is timing/interrupt-dependent; a manual SIGINT-during-self-test rehearsal (and the try/finally fix) should be exercised against a non-production instance.

**Not deeply exercised in this review:** runtime performance/DoS limits beyond the byte/log/budget findings; the now-sdk's broader serialization correctness beyond the nonce-purge case (L-6); and third-party dependency supply-chain (`@cloudflare/codemode` was read where it bears on M-3 but not audited wholesale).
