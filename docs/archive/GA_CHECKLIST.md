# GA gate (plan §7) — status

Maps each "production ready" criterion to current evidence. ✅ done · 🟢-P8 source-complete,
live-verified in P8 · 🟡 partial · ⬜ open.

**Branch:** `harden/code-review-closeout` (P0–P7 landed + locally test-gated; P8 live is
operator-gated, not yet run). The earlier on-edge proofs predate P7's **breaking signed-payload
change** (added `reason`; enforced `actor.instance`) — they are re-verified in P8, not inherited.

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | Phases 0–9 complete; always-blocking suite green; sub-prod integration green | 🟡 | **286 local tests / 27 files green** (P0–P7); P8 live + sub-prod not yet (PDI only) |
| 2 | Security invariants proven (S1, S2, S2-auth, S8, S9, S12, S13, S14, S15, B1–B8) | 🟡 | **Host (wired+tested):** S1✅ S12✅ S14✅ S15✅ B2✅ B3/B4✅ B5✅(policy) B7✅ B8✅. **Pre-hardening live, re-verified in P8:** S8 S9 S13 B1 B6. **🟢-P8:** executor verify (instance-claim, nonce unique-index, SHA-256 UTF-8) |
| 3 | Cost bounded: multi-dim atomic budget breaker, metrics logged | ✅ | BudgetDO mutexed reserve-before-load + per-user map; ENFORCED per-run row/byte caps (P5); S14 |
| 4 | Identity model decided; integration mode signed+verified; ActorPolicy enforced | ✅ host / 🟢-P8 live | actor signing incl. signed `reason` (`auth/actor.ts`, tested); ActorPolicy enforced (`actor-policy.ts`, tested); 🟢-P8 the in-scope HMAC verify match (B1) |
| 5 | Recoverability honest (S18) | ✅ | recovery snapshots **wired** to SNAPSHOT_KV (fail-closed before mutate) + recoverability classifier; claim narrowed where unsnapshotted (P4) |
| 6 | run_code default read_only (or documented override) | ✅ | DEFAULT_MODE=read_only; B3/B4 enforced + unknown-mode fail-closed |
| 7 | No secrets in repo/logs; versioned envelope; refresh/rotation/corruption handling (S7) | ✅ | AES-GCM envelope; versioned-KEK ring (P3); token-store rotate; redactor; .dev.vars gitignored |
| 8 | Exact pins; lockfile; `npm ci` reproducible | ✅ | runtime deps EXACT; package-lock committed |
| 9 | Pre-1.0 exit (codemode ≥1.0) or signed exemption | ⬜ | codemode 0.3.8 (pre-1.0) → exemption candidate |
| 10 | Tested against a non-PDI instance | ⬜ | dev374488 is a PDI |
| 11 | ServiceNow OAuth proven (B9); OAUTH_KV isolated from TokenStoreDO (B8) | ✅ host / 🟢-P8 dance | B9 grant/refresh proven live pre-hardening; per-user OAuth wired in source (P6b), tested; B8; 🟢-P8 the live authorize/callback dance |
| 12 | Authorization real: effectiveMode=min(...); admin_script gated | ✅ | effectiveMode min + unknown-mode fail-closed; approval gate defaults to deny (§7.9, P4) |
| 13 | SN-side egress controlled; recovery retention/encryption/table enablement | ✅ host / 🟢-P8 executor | host audit/ledger/snapshot/approval wired on `runServerScript` (P4); snapshot store **built**; 🟢-P8 executor kill-switch/egress live |

## What remains for GA

- ~~S8 role-ACL~~ **DONE in source** — production scoped app `x_1793136_mcp` shipped via the
  ServiceNow SDK + Fluent (`sn-executor-app/fluent/`), with the real
  `x_1793136_mcp_audit_log`/`_nonce` tables, `x_1793136_mcp.executor` role, and the enforced
  REST_Endpoint ACL. (Eval + crypto are global-only, so the scoped wrapper delegates to the
  global core — DELTAS D11.) **Live re-verified in P8** (the earlier 4/4 predates the P7 payload
  change).
- ~~Per-user ServiceNow tokens~~ **WIRED end-to-end in source** (P6b) — ticket → authorize →
  PKCE → callback → per-user `TokenStoreDO`; SN principal → signed `snow_effective_user_sys_id`
  + schema cache key with roleHash. 🟢-P8 the live authorize/callback dance + SN-principal endpoint shape.
- ~~Recovery snapshot store~~ **BUILT + WIRED** — `SNAPSHOT_KV` (30-day KV `expirationTtl`, no
  separate purge job needed — KV auto-expires), sealed under the versioned `SNAPSHOT_KEK` ring,
  fail-closed before mutate (P4; policy in RETENTION.md).
- **Sub-production instance** for the GA evidence base (PDIs are dev/demo only, §13).
- **Pre-1.0 dependency exit** or a signed exemption in DELTAS for `@cloudflare/codemode`.

## P8-LIVE GATE — must be proven on the PDI before GA (cannot run here)

P7's breaking signed-payload change means the host + executor are **redeployed together** and
the full chain is re-proven live. The specific gates:

1. **`instance_name` property shape** — fail-closed: an FQDN or empty value makes
   `_instanceMatches` reject everything (total 401 brick). Confirm the property returns the bare
   subdomain (e.g. `dev374488`) on the PDI.
2. **`GlideDigest` SHA-256 UTF-8 encoding** — confirm `getSHA256Base64` hashes the **UTF-8** bytes
   of the script (the `script_sha256` seam, 0.13a); a UTF-16/Latin-1 hash breaks non-ASCII scripts.
3. **`x_1793136_mcp_nonce` unique-index DB enforcement** — the INSERT-as-arbiter race-close is
   **inert without the DB-enforced unique index**. Confirm a concurrent duplicate `value` INSERT is
   actually REJECTED (not merely that the `sys_index` row exists). ✅ VERIFIED 2026-05-31: the
   scoped-verify CONCURRENT case returns one-200/one-401 across repeated runs (the wrapper has no
   SELECT-before-INSERT, so a 401-loser can only come from a unique-constraint INSERT failure).
   NOTE: now-sdk 4.7.1 creates the physical DDL index but does **not** write the `sys_index`
   catalog row — so the index enforces yet `sys_index` reads empty. Verify enforcement
   functionally (CONCURRENT), never by the catalog row alone.
4. **Coordinated host + executor redeploy** — the signed canonical changed (6 keys incl. `reason`);
   a half-redeploy = total signature mismatch.
5. **`SNOW_EXECUTOR_PATH`** must be the literal two-segment scoped path
   **`/api/x_1793136_mcp/x_mcp/executor/run`** (namespace `x_1793136_mcp` + service `x_mcp`).
   The one-segment form `/api/x_1793136_mcp/executor/run` 404s, and the numeric form
   `/api/1793136/x_mcp/executor/run` was a deprecated **global** endpoint that bypassed signature
   verification — now retired (see "Nonce replay store" below). ✅ VERIFIED 2026-05-31.
6. **Per-user OAuth authorize/callback live dance** (`oauth-verify.mjs`) — authorize → callback →
   token stored/reused/refreshed; `reauth_required` when absent.
7. **KEK rotation drill** — deploy with `TOKEN_KEK_CURRENT`=current passphrase → existing tokens
   still decrypt; simulate rotation (current→prev, new current) → no outage.

## Nonce replay store — live architecture (P7 finding 24; reconciled 2026-05-31)

> Supersedes an earlier draft of this section that placed nonce consumption in the global core
> against a global `x_mcp_nonce` table. That design never shipped: HEAD `8c6e1fd` moved single-use
> consumption into the **scoped wrapper**, and the live instance confirms it. The text below is
> the verified live architecture.

The request path is the **scoped, role-ACL-gated Fluent wrapper** at
`/api/x_1793136_mcp/x_mcp/executor/run` (`sn-executor-app/fluent/src/server/x_mcp_executor.js`).
Its order is: audit → kill → egress → size/413 → **verify → consume-nonce → execute**. HMAC verify
+ `new Function` eval are delegated to the **GLOBAL `x_mcp_verify` core** (those primitives are
global-only, DELTAS D11), but that core does **verify()/execute()/run() ONLY — no nonce, no DB
write**. SINGLE-USE NONCE consumption is owned by the wrapper, which does a bare `INSERT` into the
**scoped `x_1793136_mcp_nonce` table** between verify() and execute() and treats a duplicate
(falsy insert OR thrown unique-constraint violation) as a replay → 401. Consuming AFTER verify
means a forged request never burns a nonce; BEFORE execute means a replay never double-executes.

The **concurrency arbiter is the scoped table's DB UNIQUE INDEX on `value`** (declared in
`x_mcp.now.ts`). ✅ VERIFIED live 2026-05-31 via the scoped-verify CONCURRENT case (one-200/
one-401, repeatable). CAVEAT: now-sdk 4.7.1 creates the **physical** index but does not write the
`sys_index` catalog row — so enforcement is real while `sys_index` reads empty; verify
functionally, not by the catalog row. Bounding the table is the scoped `MCP Nonce Purge`
ScheduledScript (`x_mcp.now.ts`), still subject to the now-sdk 4.7.1 `run_period`
`'[object Object]'` serializer bug → set its interval once in the UI (TTL >> the 120s freshness
window; replay protection works regardless — only purge is deferred until set).

**RETIRED — global shadow endpoint (P8 root cause):** a deprecated GLOBAL numeric REST endpoint
`/api/1793136/x_mcp/executor/run` (no role ACL) had survived an earlier `executor-install` run.
Its verify reject branch was dead code (`if (!new x_mcp_verify().verify(...))` — `verify()` returns
an object, so `!obj` is always false), so it executed **every** request with no signature check.
`SNOW_EXECUTOR_PATH` had used the numeric form, so the Worker routed through it (the all-green e2e
masked this — it only exercises the valid path). Fixed by repointing `SNOW_EXECUTOR_PATH` to the
scoped two-segment path and deleting the global op + definition (the shared global *core* stays).
`scripts/executor-scoped-verify.mjs` now asserts the numeric path is dead (S8b) to lock the regression.

## Fluent toolchain audit residual (P7 — `sn-executor-app/fluent`)

`npm audit` reports **15 vulnerabilities (3 low, 11 moderate, 1 high)** — UNCHANGED after a
non-breaking `npm audit fix` (no `--force`). Every advisory is in the **dev/build toolchain**
of `@servicenow/sdk@4.7.1`, not in any deployed Worker or ServiceNow runtime artifact:

| Chain | Severity | Why it can't be fixed non-breaking |
|---|---|---|
| `tmp <=0.2.5` → `external-editor` → `@inquirer/editor` → `@inquirer/prompts` → `@servicenow/sdk-cli` | high | the CLI pins `@inquirer/prompts <=6.0.1`; bumping needs a new SDK |
| `@fastify/static 8.0.0–9.1.0` → `@servicenow/isomorphic-rollup` → `@servicenow/sdk-api` | moderate | transitively pinned by `@servicenow/sdk@4.7.1` |
| `js-yaml <3.14.2` → `xmlbuilder2` → `@cyclonedx/cyclonedx-library` / `@servicenow/sdk-build-core` | moderate | bundled with the SDK build core |

`npm audit fix --force` would install `@servicenow/sdk@4.6.1` — a **breaking downgrade** that
regresses the Fluent build the executor depends on. Per the P7 plan ("do not break the now-sdk
build chasing upgrades") **no upgrade is applied**. Residual risk is dev-only (the SDK runs at
build/deploy time on a trusted developer machine; none of these packages ship to Cloudflare or
ServiceNow). Re-audit when ServiceNow releases an SDK that bumps these transitive pins; track as
a GA release-checklist item, not a runtime blocker.
