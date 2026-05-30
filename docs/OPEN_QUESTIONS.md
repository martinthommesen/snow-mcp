# OPEN QUESTIONS & external-credential wall

This build is being implemented from `DEVELOPMENT_PLAN.md`. A large part of the plan's
Definition-of-Done depends on **live external services that are not available in this
environment**. This file records exactly what is proven locally vs what is blocked, so no
unverified claim is mistaken for a verified one (plan §0 rule 9; §7 GA gate).

## ✅ DEPLOYED — most of the wall is now cleared

With the user's instance + Cloudflare access, the major external items are DONE:
- [x] **Deployed** to Cloudflare via Alchemy (`alchemy.run.ts`) — Worker + Worker Loader +
      KV + 4 sqlite DOs + secrets. URL: `https://servicenow-mcp.lammesen.workers.dev`.
- [x] **Full sandbox→live e2e** on the deployed Worker (`npm run deploy:e2e`, 5/5): run_code
      transpiles + sandboxes LLM TS, calls `servicenow.*` over RPC, reaches LIVE ServiceNow
      (`INC0000060`); fetch blocked in-sandbox (S1); Origin 403 (S12) — all on real edge.
- [x] **OAuth token flow** live-verified (B9).
- [x] ServiceNowRPC reads / ActorPolicy / masking / capability gate live-verified.

## ✅ MCP-client OAuth — DONE + deployed (Phase 1.1, §2.4, §7.8)

The deployed `/mcp` is now **OAuth-gated** (was open). `npm run deploy:e2e` (7/7):
- [x] unauthenticated `/mcp` → **401**; RFC-8414 metadata exposed
- [x] full OAuth dance (DCR + **PKCE S256** + single-operator consent secret) issues a token
- [x] authenticated `run_code` → sandbox → **live ServiceNow** (`INC0000060`)
- [x] **B4 at the wire**: a `read_only`-scoped client requesting `write` → `mode_not_permitted`
- [x] S1 sandbox isolation on the deployed Worker

## Also done since: Phase 2 + Phase 7 host-side

- [x] §2.6 user-aware schema cache (S6) — wired into describe/list
- [x] §2.13 ACL-safe keyset pagination (B7) — no stall, no skip, honest `partial`
- [x] §7.2 host-side audit (hashes + redaction, both identities)
- [x] §7.7 encrypted recovery snapshots (AES-GCM, SNAPSHOT_KEK, AAD fail-closed, retention)
- [x] S13 (subset, LIVE): wrong operator secret → no code; wrong PKCE verifier → rejected

## ✅ `x_mcp` executor — INSTALLED + PROVEN LIVE (Phase 5; user-authorized)

`node scripts/executor-install.mjs` installed the executor and proved **6/6** on the live
instance, and `npm run deploy:e2e` proves the **full chain** through the deployed Worker:
- [x] **B1 / 0.13a**: host WebCrypto signer ≡ ServiceNow `GlideCertificateEncryption` over the
      ASCII-canonical payload — valid sig executes (`gs.getUserName()`→`admin`); **forged email
      → 401**, **bad sig → 401**. Cross-engine HMAC contract holds.
- [x] **S16**: cross-scope reach (GlideAggregate count on global `incident` = 67)
- [x] **T8**: nonce replay rejected (first 200, second 401)
- [x] **S9**: kill switch disabled→503, re-enabled→200 (audit-first)
- [x] **B6**: over-cap output → `{result:null, result_sample, truncated:true}` (live)
- [x] **FULL CHAIN**: deployed `admin_script` run_code → sandbox → `runServerScript` → signed
      actor → executor verify+execute → result. End-to-end on real infra.

## Also done: Phase 1.3 token store + S18

- [x] §2.7/§1.3 `TokenStore` adapter (TokenStoreDO + AES-GCM): encryption-at-rest, rotate,
      revoke, S2-auth AAD isolation, KEK rotation window (`token-store.test.ts`)
- [x] §7.7/S18 recoverability classifier (reversible/soft-delete/non-recoverable) + delete-gating

Deltas (recorded in DELTAS): global-scope Scripted REST APIs get a **numeric namespace**
(`/api/1793136/x_mcp/...`); custom tables can't be created via Table API, so this REST
install uses `syslog` (audit) + `sys_user_preference` (nonce) — the **production scoped app
ships the real `x_mcp_audit_log`/`x_mcp_nonce` tables + role ACL via a Studio update set**.

## Remaining (refinements / GA)

- [ ] Production scoped-app packaging: real tables + `x_mcp.executor` role + REST_Endpoint ACL
      (S8 role-gating) via Studio update set (the REST install proves the mechanism in global scope).
- [ ] Per-user ServiceNow tokens via TokenStoreDO (operator OAuth gates clients; ServiceNow
      credential is the shared Basic-Auth integration identity today).
- [ ] Remaining Phase 9 tests: S2-auth, S7 (full), S18, B6 (live), full S13.
- [ ] GA gate (§7): sub-production instance (not a PDI), pre-1.0 dependency exit.

## The wall (historical) — what needed credentials / accounts

| Capability | Needs | Blocks |
|---|---|---|
| Deploy the Worker | Cloudflare **Workers Paid** account + `wrangler`/Alchemy auth | real `/mcp` deploy; Dynamic Workers pricing checks (§2.5) |
| ServiceNow Table/Aggregate/etc. | a live **PDI** (or sub-prod) + OAuth app | Phases 1.5–1.7, 3, integration suite, GA gate |
| Scoped-app executor (`x_mcp`) | a PDI to build + export the update set | Phase 1.8 spike, Phase 5, S8/S9/S16, B1 |
| Signed-actor verify mechanism | in-scope HMAC on ServiceNow (Script Include / `GlideCertificateEncryption.generateMac` / `com.glide.tokenbased_auth`) | **0.13a**, Phase 5.4a, B1 |
| `integration_user` read-policy | a PDI with seeded tables/ACLs | **0.13c**, B5 (host-side `ActorPolicy` logic *is* locally testable; the ServiceNow side is not) |
| ServiceNow OAuth refresh behavior | confidential client on a real instance | **0.13e** / B9 |

## Locally verifiable (in scope this session) — status

- [x] Workspace, exact-pinned deps, committed lockfile (0.2–0.4)
- [x] Hello MCP server, per-request `createServer` (CVE guard, §2.3) (0.5)
- [x] `@cloudflare/vitest-pool-workers` harness inside workerd (0.6)
- [x] `/health` (0.7)
- [x] **0.8a** Code Mode execute() contract (servicenow.* RPC, fetch blocked, logs, error, timeout)
- [x] **0.8b** import mechanism proven + v1 import policy = disabled
- [x] **0.11** Origin validation (S12 shape): foreign Origin → 403; loopback/no-Origin allowed
- [x] **0.12** Durable Object partition proof — TokenStoreDO isolation per (user,instance) +
      scoped revoke (S7-shape); BudgetDO global counter coordinates through one date-keyed
      object; distinct date keys independent. DO classes are **storage skeletons** (no crypto
      / atomic-reserve yet — those are Phases 1.3/4.5).
- [x] **0.13b** effective-mode capping (B3/B4) — requested mode only narrows
- [x] **0.13d** OAUTH_KV present + fail-closed-if-absent + isolation (B8)
- [x] **S15** URL/SSRF allowlist; **B2** scriptedRest path denylist (standalone host guards)

### Phase 1–5 host-side logic — IMPLEMENTED and unit-verified against MOCKS

These build the host-side logic with tests against an injected mock `SnHttpClient`. The
LOGIC is verified; live ServiceNow behavior and end-to-end integration are NOT.

- [x] §2.7 AES-GCM token envelope — round-trip, AAD-mismatch fail-closed, KEK rotation window
- [x] §2.0 actor canonicalize + HMAC-SHA256 sign (B1-shape host-side; authoritative verify is on SN)
- [x] §2.12 ActorPolicy host enforcement (instance/table/field/row/mode) — **B5** logic
- [x] §3.5 mode→capability gating (capability_denied)
- [x] §3.1/3.3 ServiceNowRPC read surface + mutating gates, enforcement order, against a mock
- [x] §4.6 run_code pipeline end-to-end (mode-cap, capability, ActorPolicy, masking, budget, code_size, transpile_error)
- [x] §4.5 per-run budget meter (daily atomic BudgetDO reserve still TODO — Phase 4.5)
- [x] §3.2 MCP tool surface: run_code/describe_table/list_tables registered with schemas + annotations
- [x] §10 executor reference script + `x_mcp_verify` written as **source** in `sn-executor-app/` (unverified)

### LIVE-verified against `dev374488.service-now.com` (Basic-Auth dev path)

`npm run live:verify` — 7/7 against real ServiceNow:
- [x] ServiceNowRPC `tableQuery` real rows + `sys_id` injection (§1.7)
- [x] `aggregate` real count
- [x] **ActorPolicy denies non-allowlisted table (B5)** — live
- [x] field masking strips forbidden field from live response — live
- [x] capability gate: `read_only` cannot `tableUpdate` (no live mutation)
- [x] cost gate: BudgetDO atomic reserve-before-load + **S14** concurrency (granted == cap)

### Environment limitation (not a code defect)

- workerd outbound `fetch` is **blocked in this sandbox** (a detected-but-unusable proxy);
  Node `fetch` works. So live calls run in Node; the **combined sandbox→host→live** path
  can't be exercised here (sandbox needs workerd; workerd can't reach the network).

### OAuth token flow — LIVE-verified (B9), `npm run` via scripts/oauth-verify.mjs

Registered a test OAuth client (`mcp-codemode-test`) on the instance (user-approved write)
and proved the real flow:
- [x] **ROPC grant → 200**, returns `access_token` AND `refresh_token` (B9: refresh IS returned)
- [x] **Bearer token → Table API** returns a real `incident` row (the OAuth path reaches data)
- [x] **refresh_token grant → 200** issues a new access token
- [x] **B9 finding:** this client type **does NOT rotate** the refresh token on refresh (same
      token reused). Recorded for §2.8 — token-store rotation logic must not *assume* rotation.
- Note: the Table API returns the **encrypted-at-rest** `client_secret`; we set a known
      plaintext secret via PATCH (ServiceNow validates OAuth against the decrypted value).

The `ServiceNowRPC`/`SnFetchClient` auth is scheme-agnostic (`getAuthorization` returns the
full header), so the live-verified RPC path works identically with an OAuth `Bearer` token.

### Still blocked on external services

- [ ] Wire the OAuth provider (consent/PKCE) + TokenStoreDO into the server's request path
      (the token *grant/refresh* against the instance is now proven; the provider plumbing
      and per-user token storage are not yet wired e2e).
- [ ] ServiceNow client retry/429/5xx + hibernation-splash detection (live network behavior)
- [ ] describe_table/list_tables real implementations (need schema cache against the instance)
- [ ] `x_mcp` scoped-app executor install + proof (S8/S9/S16, B1, B6) — needs app install on the PDI
- [ ] Deployment (Cloudflare Workers-Paid account)

## Known gaps & hardening notes (honest caveats)

- **Cost-safety gate — NOW IMPLEMENTED.** BudgetDO does an atomic multi-dimensional
  reserve serialized by an in-instance mutex; `run_code` calls `reserveDailyBudget()`
  BEFORE `createExecutor`/`load()`, so an exhausted caller never creates a billable
  Dynamic Worker. **S14** proves parallel reserves through the single global object can't
  exceed the cap (granted == cap, never over-committed). `buildHandlers` wires it to the
  date-keyed BUDGET_DO. (Per-run meter still bounds one cheap Worker mid-snippet.)
- **B1 cross-engine canonicalization — hardened, host-verified, SN side still unproven.**
  Host signer and `x_mcp_verify.js` now use an identical ASCII-only canonical encoder
  (no `JSON.stringify`), so non-ASCII actor fields can't silently break signatures. The
  host side is unit-tested with Unicode fields; the ServiceNow side remains source-only
  until a PDI run confirms `GlideCertificateEncryption.generateMac` key encoding and that
  `GlideDigest.getSHA256Base64` hashes the **UTF-8** bytes of the script (the `script_sha256`
  digest-input-encoding seam). 0.13a still owes this proof.
- **Typed error code across the sandbox** is now preserved via a `[[code]]` message
  envelope (RPC encodes, run_code decodes into `structuredContent.code`). The host-side
  audit/ledger that records denials (§7.2/7.3) is not yet built.

## Posture decisions still owed by the operator (plan §0.9)

1. **`run_code` default mode** — plan recommends `read_only` (Decision 1). Adopted as the
   default in `config.ts` when written; flip via `DEFAULT_MODE` for private demos.
2. **ServiceNow credential mode** — `integration_user` (single operator) vs `per_user_oauth`
   (multi-user default), or `integration_user` + enforced `ActorPolicy`. Must be chosen per
   deployment before Phase 1 (§0.9 Decision 2). Not decidable without knowing the audience.

## Notes

- A real Cloudflare account *connector* may be reachable in this environment, but **deploying
  to it is an outward-facing action** and has not been done without explicit authorization.
- ServiceNow has no connector available here, so that side is blocked regardless.
