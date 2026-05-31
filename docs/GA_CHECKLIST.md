# GA gate (plan §7) — status

Maps each "production ready" criterion to current evidence. ✅ done · 🟡 partial · ⬜ open.

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | Phases 0–9 complete; always-blocking suite green; sub-prod integration green | 🟡 | 105 local tests + 10 deployed e2e + executor 6/6 green; **sub-prod** not yet (PDI only) |
| 2 | Security invariants proven (S1, S2, S2-auth, S8, S9, S12, S13, S14, S15, B1–B8) | ✅ | S1✅ S2/S2-auth✅ **S8✅** (scoped role-ACL via Fluent) S9✅(live) S12✅ S13✅(subset live) S14✅ S15✅ B1✅(live) B2✅ B3/B4✅(live) B5✅(live) B6✅(live) B7✅ B8✅ |
| 3 | Cost bounded: multi-dim atomic budget breaker, metrics logged | ✅ | BudgetDO reserve-before-load; per-run meter; S14 |
| 4 | Identity model decided; integration mode signed+verified; ActorPolicy enforced | ✅ | actor signing+verify proven live (B1); ActorPolicy live (B5) |
| 5 | Recoverability honest (S18) | ✅ | recovery snapshots + recoverability classifier; claim narrowed where unsnapshotted |
| 6 | run_code default read_only (or documented override) | ✅ | DEFAULT_MODE=read_only; B3/B4 enforced live |
| 7 | No secrets in repo/logs; versioned envelope; refresh/revoke/rotation (S7) | ✅ | AES-GCM envelope; token-store rotate/revoke/KEK; redactor; .dev.vars gitignored |
| 8 | Exact pins; lockfile; `npm ci` reproducible | ✅ | runtime deps EXACT; package-lock committed |
| 9 | Pre-1.0 exit (codemode ≥1.0; worker-bundler GA) or signed exemption | ⬜ | codemode 0.3.8 (pre-1.0); worker-bundler unused → exemption candidate |
| 10 | Tested against a non-PDI instance | ⬜ | dev374488 is a PDI |
| 11 | ServiceNow OAuth proven (B9); OAUTH_KV isolated from TokenStoreDO (B8) | ✅ | B9 live (grant/refresh); B8 |
| 12 | Authorization real: effectiveMode=min(...); admin_script gated | ✅ | live B3/B4; approval gate (§7.9) |
| 13 | SN-side egress controlled; recovery retention/encryption/opt-out | 🟡 | egress toggle + approval live; snapshot store policy doc'd, store not built |

## What remains for GA

- ~~S8 role-ACL~~ **DONE** — production scoped app `x_1793136_mcp` shipped via the ServiceNow
  SDK + Fluent (`sn-executor-app/fluent/`), with the real `x_1793136_mcp_audit_log`/`_nonce`
  tables, `x_1793136_mcp.executor` role, and the enforced REST_Endpoint ACL. Verified 4/4 live.
  (Eval + crypto are global-only, so the scoped wrapper delegates to the global core — DELTAS D11.)
- **Sub-production instance** for the GA evidence base (PDIs are dev/demo only, §13).
- **Pre-1.0 dependency exit** or a signed exemption in DELTAS for `@cloudflare/codemode`.
- **Per-user ServiceNow tokens** wired end-to-end (the TokenStore adapter + crypto are done
  and unit-verified; wiring into the OAuth callback is the remaining integration).
- Recovery **snapshot store + scheduled purge** (policy in RETENTION.md; crypto verified).

## Nonce replay store — live target (P7 finding 24)

The production verifier is the **GLOBAL `x_mcp_verify` core** installed by
`scripts/executor-install.mjs` (`new Function` + `GlideCertificateEncryption` are global-only,
DELTAS D11). Its `_consumeNonce` does a bare `INSERT` into the **GLOBAL `x_mcp_nonce` table** and
treats a duplicate (insert returns falsy OR throws the constraint violation) as a replay. The
**concurrency arbiter is a DB-enforced UNIQUE INDEX on the value column**, installed as a
`sys_index` record (mirroring the now-sdk's own output for the scoped table, where the column
dictionary's `unique` stays false and the index lives in a separate `sys_index`). The installer
also creates a **`sysauto_script` nonce-purge job** (15-min cadence, 1-hour TTL >> the 120s
freshness window); that REST-installed job's `run_period` is a plain string, so it is **not**
affected by the now-sdk 4.7.1 `'[object Object]'` ScheduledScript serializer bug.

The scoped Fluent `x_1793136_mcp_nonce` table + its unique index + its `MCP Nonce Purge`
ScheduledScript (in `x_mcp.now.ts`) are **reserved/unused by the live core** — kept for a
possible future scoped-hosted verifier. The now-sdk 4.7.1 serializer bug (P8 manual `run_period`
fixup) applies only to that scoped, **functionally-unused** ScheduledScript — it is NOT a
functional blocker for the live purge.

**P8-LIVE GATE (cannot run here):** the race-close is correct **only if** the `x_mcp_nonce` value
unique index is DB-enforced. The `_consumeNonce` INSERT-as-arbiter logic is inert without that
constraint, so the live gate is: **confirm a concurrent duplicate `value` INSERT is actually
REJECTED** (not merely that the `sys_index` row exists) on a live PDI. The global nonce-purge
`sysauto_script` is likewise new Table-API DDL to verify live.

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
