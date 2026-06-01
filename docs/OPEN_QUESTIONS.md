# OPEN QUESTIONS & external-credential wall

This build is being implemented from `DEVELOPMENT_PLAN.md`. A large part of the plan's
Definition-of-Done depends on **live external services that are not available in this
environment**. This file records exactly what is proven locally vs what is blocked, so no
unverified claim is mistaken for a verified one (plan §0 rule 9; §7 GA gate).

## Status note (P0–P7 hardening branch) — what "done" means here

This file predates the `harden/code-review-closeout` branch (P0–P7). Two things changed how to
read it:

1. **The earlier live proofs predate the hardening.** P7 made a **breaking, coordinated change
   to the signed actor payload** (added a signed `reason` key + enforced the `actor.instance`
   claim). So the on-edge `deploy:e2e` chain and the live executor proofs below were verified
   against the **pre-hardening** build and the **old** canonical — they are **re-verified in P8**
   (operator-gated, not yet run), not currently valid for this branch. They are relabelled
   **"proven live pre-hardening; re-verified in P8"** below.
2. **Credential mode is decided (posture, below):** `per_user_oauth` is now wired end-to-end **in
   source** (P6b) and `integration_user` remains the **default**; the restrictive ActorPolicy is
   **opt-in**.

## ✅ DEPLOYED to Cloudflare; ☐ P8 re-verification pending

With the user's instance + Cloudflare access, the major external items are DEPLOYED, but the
hardened build's live behavior is a P8 gate:
- [x] **Deployed** to Cloudflare via Alchemy (`alchemy.run.ts`) — Worker + Worker Loader +
      KV (4 namespaces) + 4 sqlite DOs + secrets. URL: `https://servicenow-mcp.lammesen.workers.dev`.
- [~] **Full sandbox→live e2e** (`deploy:e2e`) — proven live **pre-hardening** (5/5: run_code →
      sandbox → `servicenow.*` RPC → LIVE ServiceNow `INC0000060`; S1 fetch-blocked; S12 Origin
      403). **Re-verified in P8** against the hardened build (forged-error stripped, byte-cap
      truncation, restrictive-policy denial, idempotent-retry dedup, audit emitted, reauth flow).
- [x] **OAuth token flow** (ROPC grant/refresh) live-verified pre-hardening (B9).
- [~] ServiceNowRPC reads / ActorPolicy / masking / capability gate — proven live pre-hardening;
      P1 then tightened the read path (validate-first), so re-verified in P8 (`live:verify`).

## MCP-client OAuth — gating WIRED + tested; live deploy:e2e re-verified in P8

The deployed `/mcp` is **OAuth-gated** (was open). The gating + dance are **wired and locally
tested**; the on-edge `deploy:e2e (7/7)` run below proved them **pre-hardening** and is re-run
in P8 against the hardened build:
- [x] unauthenticated `/mcp` → **401** — wired (`index.ts` `OAuthProvider apiRoute:/mcp`) +
      tested (`health.test.ts` asserts the 401); RFC-8414 metadata exposed
- [x] full OAuth dance (DCR + **PKCE S256** + single-operator consent secret) — signed/single-use
      consent tested (`auth-surface.test.ts`)
- [~] authenticated `run_code` → sandbox → **live ServiceNow** (`INC0000060`) — proven live
      pre-hardening; re-verified in P8
- [x] **B4 at the wire**: a `read_only`-scoped client requesting `write` → `mode_not_permitted`
      — wired + tested (`effective-mode.test.ts`); live wire re-verified in P8
- [~] S1 sandbox isolation on the deployed Worker — proven live pre-hardening; re-verified in P8

## Also done since: Phase 2 + Phase 7 host-side (wired + locally tested)

- [x] §2.6 user-aware schema cache (S6) — wired into describe/list; ServiceNow sys_id +
      content-addressed roleHash cache key (P6b-2), `"*"`-collision fixed (`schema-cache.test.ts`)
- [x] §2.13 ACL-safe pagination posture (B7) — `tableQuery` returns an honest `partial` flag;
      add keyset pagination with its production caller if live ACL testing proves it is needed.
- [x] §7.2 host-side audit — **wired** on every mutation (`sn/mutation-guard.ts` → AUDIT_KV,
      audit-before-effect, fail-closed; `mutation-wiring.test.ts`)
- [x] §7.7 encrypted recovery snapshots — **wired** before reversible mutates (SNAPSHOT_KV,
      versioned SNAPSHOT_KEK, fail-closed; `audit-recovery.test.ts`)
- [~] S13 (subset): wrong operator secret → no code; wrong PKCE verifier → rejected — proven live
      pre-hardening; re-verified in P8

## `x_mcp` executor — proven live PRE-HARDENING; HARDENED IN SOURCE (P7); ☐ re-verified in P8

`node scripts/executor-install.mjs` installed the executor and proved **6/6** live, and an
earlier `deploy:e2e` proved the **full chain** — **all against the PRE-HARDENING build/canonical**.
P7 then changed the signed payload (added `reason`; enforced `actor.instance`), so these are
re-run in P8 after a coordinated host+executor redeploy (the old proofs do NOT cover the hardened
build):
- [~] **B1 / 0.13a**: host WebCrypto signer ≡ ServiceNow `GlideCertificateEncryption` over the
      ASCII-canonical payload (now **6-key incl. signed `reason`**). Byte-identical canonical
      confirmed across host + all 3 executor cores via a Node harness; the **live** HMAC match +
      `GlideDigest` SHA-256 UTF-8 encoding are P8 gates.
- [x] **S16** cross-scope reach · **T8** nonce replay (DB-unique-index INSERT-as-arbiter on the
      SCOPED `x_1793136_mcp_nonce`) · **S9** kill switch (audit-first) · **B6** over-cap output —
      ✅ verified live 2026-05-31 (CONCURRENT one-200/one-401 proves the race-close arbiter).
- [x] **NEW P8 cases:** instance-claim mismatch → 401; signed+audited `reason`; null-MAC → clean
      401; size/kill before nonce-consume — ✅ all green in `executor-scoped-verify.mjs` (13/13).
- [x] **FULL CHAIN** proven 2026-05-31 (`deploy:e2e` 13/13 + `executor-scoped-verify.mjs` 13/13)
      against the scoped two-segment endpoint **`/api/x_1793136_mcp/x_mcp/executor/run`**.

## Also done: Phase 1.3 token store + S18

- [x] §2.7/§1.3 `TokenStore` adapter (TokenStoreDO + AES-GCM): encryption-at-rest, rotate,
      S2-auth AAD isolation, KEK rotation window (`token-store.test.ts`)
- [x] §7.7/S18 recoverability classifier (reversible/soft-delete/non-recoverable) + delete-gating

Deltas (recorded in DELTAS): global-scope Scripted REST APIs get a **numeric namespace**
(`/api/1793136/x_mcp/...`); custom tables can't be created via Table API, so that deprecated REST
install used `syslog` (audit) + a global nonce store. **That global numeric endpoint is RETIRED
(P8, 2026-05-31)** — it bypassed verification (dead reject branch) and had no role ACL. The
**production surface is the scoped Fluent app** at `/api/x_1793136_mcp/x_mcp/executor/run`, which
ships the real `x_1793136_mcp_audit_log` / `x_1793136_mcp_nonce` tables + role ACL.

## Remaining (refinements / GA)

- [x] Production scoped-app packaging: real tables + `x_1793136_mcp.executor` role + REST_Endpoint
      ACL via the **Fluent SDK project** (P7 / DELTAS D11), superseding the XML update set + the
      global-REST install (both now DEPRECATED references). ☐ live re-verified in P8.
- [x] **Per-user ServiceNow tokens — wired end-to-end IN SOURCE** (P6b, commits `b2dc973`/`9a02e49`):
      `SERVICENOW_CREDENTIAL_MODE=per_user_oauth` drives ticket → `/servicenow/authorize` → PKCE
      S256 → `/servicenow/callback` → per-user token in `TokenStoreDO`; SN principal resolves the
      sys_id → signed `snow_effective_user_sys_id` + schema cache key with roleHash. ☐ live
      authorize/callback dance + SN-principal endpoint shape re-verified in P8.
- [ ] GA gate (§7): sub-production instance (not a PDI), pre-1.0 dependency exit.

### Open-pending-live (P8 gates) — VERIFIED LIVE 2026-05-31 on dev374488

- [x] Coordinated host+executor redeploy (the P7 breaking payload change): `deploy:e2e` 13/13,
      `executor-scoped-verify.mjs` 13/13 (forged/empty/null/garbage/instance/tamper → 401, valid →
      200, CONCURRENT one-200/one-401). KEK rotation drill + `oauth-verify.mjs` still pending.
- [x] `GlideDigest` SHA-256 UTF-8 (0.13a) + `instance_name` shape: implicitly confirmed — a genuine
      signed request validates end-to-end (valid → 200), which requires correct hash + instance
      match + freshness + canonical (incl. the `reason` last-key). `x_1793136_mcp_nonce`
      unique-constraint enforcement confirmed functionally (CONCURRENT); see GA_CHECKLIST note on
      the now-sdk 4.7.1 `sys_index`-catalog gap (physical index enforces; catalog row absent).
- [x] `SNOW_EXECUTOR_PATH` points at the scoped endpoint — the literal two-segment path
      **`/api/x_1793136_mcp/x_mcp/executor/run`**. (P8 root cause: it had used the numeric global
      form `/api/1793136/x_mcp/executor/run`, a deprecated endpoint that bypassed verify — now
      retired; see GA_CHECKLIST "Nonce replay store" / DELTAS.)

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
      per-user/per-instance isolation (S7-shape); BudgetDO global counter coordinates through one date-keyed
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

### Read surface — proven live PRE-HARDENING (`dev374488`, Basic-Auth); re-verified in P8

An earlier `npm run live:verify` passed 7/7 against real ServiceNow. P1 then tightened the read
path (validate-first table/`sys_id`/`limit`/fields, encoded path segments), so these are wired +
locally tested here and re-verified live in P8:
- [~] ServiceNowRPC `tableQuery` real rows + `sys_id` injection (§1.7)
- [~] `aggregate` real count
- [~] **ActorPolicy denies non-allowlisted table (B5)** — re-verified live in P8
- [~] field masking strips forbidden field from live response — re-verified live in P8
- [~] capability gate: `read_only` cannot `tableUpdate` (no live mutation)
- [~] cost gate: BudgetDO atomic reserve-before-load + **S14** concurrency (granted == cap)

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

### Still blocked on external services (P8 live gates)

- [x] OAuth provider (consent/PKCE) + per-user TokenStoreDO wired into the request path **in
      source** (P6a signed consent; P6b per-user authorize/callback) — ☐ the live authorize/callback
      dance is a P8 gate.
- [ ] ServiceNow client retry/429/5xx + hibernation-splash detection (live network behavior)
- [ ] `x_mcp` scoped-app executor re-install + proof against the **hardened** build (the breaking
      payload change requires a coordinated redeploy) — needs the PDI (P8)
- [ ] KEK rotation drill: deploy with `TOKEN_KEK_CURRENT`=current passphrase → existing tokens
      still decrypt; simulate rotation → no outage (P8)

## Known gaps & hardening notes (honest caveats)

- **Cost-safety gate — NOW IMPLEMENTED.** BudgetDO does an atomic multi-dimensional
  reserve serialized by an in-instance mutex; `run_code` calls `reserveDailyBudget()`
  BEFORE `createExecutor`/`load()`, so an exhausted caller never creates a billable
  Dynamic Worker. **S14** proves parallel reserves through the single global object can't
  exceed the cap (granted == cap, never over-committed). `buildHandlers` wires it to the
  date-keyed BUDGET_DO. (Per-run meter still bounds one cheap Worker mid-snippet.)
- **B1 cross-engine canonicalization — hardened, host-verified, SN side P8-live.**
  Host signer and the executor `_canonical` now use an identical ASCII-only canonical encoder
  (no `JSON.stringify`) over a **6-key payload incl. the signed `reason`** (P7), so non-ASCII
  actor fields can't silently break signatures and the audited justification can't be forged
  independent of the HMAC. Byte-identical canonical output is confirmed across the host + all 3
  executor cores via a Node harness; the ServiceNow side is **source-complete; live-verified in
  P8** — a PDI run confirms `GlideCertificateEncryption.generateMac` key encoding and that
  `GlideDigest.getSHA256Base64` hashes the **UTF-8** bytes of the script (the `script_sha256`
  digest-input-encoding seam, 0.13a).
- **Typed error code across the sandbox** is host-attested (P2): `structuredContent.code` derives
  ONLY from monotonic host signals (`budget_exceeded`/`reauth_required`), never the
  snippet-controlled post-sandbox message (a forged `[[code]]` collapses to `run_error`). The
  host-side audit/ledger that records denials (§7.2/7.3) is now **built + wired + tested** (P4,
  `sn/mutation-guard.ts` → AUDIT_KV/LEDGER_DO; `mutation-wiring.test.ts`).

## Posture decisions (plan §0.9) — RESOLVED

1. **`run_code` default mode** — `read_only` (Decision 1), the default in `config.ts`; flip via
   `DEFAULT_MODE` for private demos. ✅
2. **ServiceNow credential mode** — RESOLVED (operator-locked, plan Context): build **per-user
   ServiceNow OAuth** (`per_user_oauth`) on top of restrictive-ActorPolicy hardening. Landed
   state on this branch:
   - `per_user_oauth` is **wired end-to-end in source** (P6b) — selectable via
     `SERVICENOW_CREDENTIAL_MODE=per_user_oauth`.
   - `integration_user` (ROPC / shared Basic-Auth) remains the **default** (unset mode) so the
     live single-operator deployment is unchanged.
   - The **restrictive ActorPolicy is OPT-IN** (`ACTOR_POLICY_*` vars); with none set the
     permissive single-operator policy is used. A sane conservative restrictive config ships as a
     documented example in `.dev.vars.example`, not as the hardcoded runtime default.

## Notes

- A real Cloudflare account *connector* may be reachable in this environment, but **deploying
  to it is an outward-facing action** and has not been done without explicit authorization.
- ServiceNow has no connector available here, so that side is blocked regardless.
