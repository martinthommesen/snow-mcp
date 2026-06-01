# Threat model — implementation status (plan §11)

The full threat table is in `DEVELOPMENT_PLAN.md` §11 (T1–T20). This file annotates each
mitigation with its **current** status after the P0–P7 hardening branch
(`harden/code-review-closeout`):

- ✅ = **wired + locally tested**: the control is invoked by the live request path (call-graph
  evidence: module + function) AND has a green test. *Not* "merely implemented."
- 🟢-P8 = **source-complete; live-verified in P8**: code landed + locally tested, but its live
  behavior is provable only on the PDI (operator-gated P8). NOT a bare ✅.
- 🟡 = implemented, a sub-part still pending. ⬜ = not yet built.

| # | Threat | Mitigation | Status (wired-module · test) |
|---|---|---|---|
| T3 | Sandbox code calls `fetch("evil")` | `globalOutbound:null` makes fetch throw; no creds in sandbox | ✅ `sandbox/executor.ts` · `sandbox-contract.test.ts` (0.8a) |
| T4 | LLM code mutates records | effective-mode + ActorPolicy + attribution + idempotency ledger + audit-before-effect + recovery snapshot + approval | ✅ **wired** `sn/rpc.ts`→`sn/mutation-guard.ts` (`guardMutation` on every `tableUpdate`/`runServerScript`) · `mutation-wiring.test.ts`, `audit-recovery.test.ts` (P4) |
| T5 | Sensitive output in logs | redactor denylist + token patterns; hashes only in audit; redacted client errors | ✅ `observability/redact.ts` wired in `mapServiceNowError`/`toToolResult` · `auth-surface.test.ts` (P6a) |
| T7 | Schema cache leaks fields across users | user-aware cache key (ServiceNow sys_id + content-addressed roleHash); field masking | ✅ **wired** `cache/schema.ts` `roleHash()` → `SchemaCache` identity via `handlers.resolveSchemaIdentity`; missing per-user sys_id bypasses cache · `schema-cache.test.ts`, `actor-and-policy.test.ts` (P6b-2) |
| T8 | Replay of request/executor call | leveled idempotency (host); executor DB-unique-index nonce | ✅ host ledger `do/mutation-ledger.ts`→`guardMutation` · `mutation-wiring.test.ts`, `do-partition.test.ts` (S17); 🟢-P8 executor `x_1793136_mcp_nonce` unique-index race-close (INSERT-as-arbiter; DB enforcement provable only live) |
| T10 | Dynamic Worker cost explosion | multi-dim atomic reserve-before-load (reserves per-run MAX, refunds unused) + ENFORCED per-run row/byte caps + daily admission/accrual | ✅ `do/budget.ts` (mutexed global+per-user; `reserve` commits per-run maximums, `reconcile` refunds actuals — bounds concurrent overshoot, CDX-5) + `sn/run-budget.ts` (`countRows`/`countBytes` throw `budget_exceeded`); `run_code.ts` reconciles on every post-reserve exit incl. transpile failure · `run-budget.test.ts`, `do-partition.test.ts`, `run-code-pipeline.test.ts` (S14, P5) |
| T11 | MCP SDK cross-client leak (CVE) | per-request `McpServer` | ✅ `index.ts` `apiHandler` builds a per-request server · `health.test.ts` (§2.3) |
| T13 | DNS rebinding (missing Origin check) | reject invalid Origin (403); env-gated localhost | ✅ `observability/origin.ts` wired in BOTH the `/mcp` `apiHandler` and the top-level auth-surface wrapper; `allowLocalhost` env-gated · `auth-surface.test.ts` (S12, P6a) |
| T14 | OAuth flow abuse | exact redirect_uri, state/nonce, PKCE S256, signed consent state; consent-write admission cap | ✅ **wired** — MCP-client provider (`@cloudflare/workers-oauth-provider`, `allowPlainPKCE:false`); signed single-use consent nonce in OAUTH_KV (`servicenow-auth-handler.ts`, `requireOAuthKv` fail-closed); GET `/authorize` rejects unknown clients + rate-caps consent writes per SOURCE IP via `ConsentRateDO` (in-memory, HARD-capped key set with oldest-evict) before the KV put (CDX-4 + follow-up; keyed by IP not client_id so dynamic client registration can't multiply keys) · `auth-surface.test.ts`, `do-partition.test.ts`. Per-user SN OAuth PKCE: ✅ source `auth/servicenow-{ticket,callback-handler}.ts` · `servicenow-ticket.test.ts`, `servicenow-callback.test.ts`; 🟢-P8 the live authorize/callback dance |
| T15 | **Forged actor metadata** | host HMAC-signs (ASCII-canonical incl. signed `reason`); executor verifies (freshness + nonce + instance claim) | ✅ host signer `auth/actor.ts` (`reason` LAST in `CANONICAL_KEYS`; signed by `rpc.ts` `runServerScript`) · `actor-and-policy.test.ts`; 🟢-P8 in-scope executor verify (byte-identical canonical confirmed via Node harness; live HMAC match is the P8 gate) |
| T16 | **Mode escalation** via `mode` input | `effectiveMode=min(requested,scope,tenant,instance)`; unknown mode → max risk (fail-closed) | ✅ `authz/effective-mode.ts` + `actor-policy.ts` `modeRisk` · `effective-mode.test.ts` (B3/B4, P6a) |
| T17 | **integration_user over-reads** | ActorPolicy before every RPC (restrictive policy opt-in); mandatory rowFilter AND-ed into reads INCLUDING `tableGet` | ✅ host enforcement `authz/actor-policy.ts` `loadActorPolicy` (permissive default; restrictive when `ACTOR_POLICY_*` set); `tableGet` routes single-record lookups through the filtered list endpoint under a mandatory filter (CDX-8) · `actor-and-policy.test.ts`, `rpc-validation.test.ts`; 🟢-P8 live read-policy on the instance (B5; earlier live proof predates the restrictive loader) |
| T18 | `scriptedRest` bypasses executor | no generic `scriptedRest` RPC exists; add a guard with the adapter if this surface is introduced | ✅ current RPC surface exposes only typed tools (`server-tools.test.ts`); no standalone denylist helper is carried for an unwired adapter |
| T19 | **ServiceNow-side egress** via runServerScript | tenant toggle (fail-closed on either namespace) + approval + non-recoverable label + host audit/ledger/snapshot wrap; executor `execute()` cap-gated | ✅ host controls wired `sn/mutation-guard.ts` (audit/ledger/approval on `runServerScript`; signed+audited `reason`) · `mutation-wiring.test.ts` (P4); 🟢-P8 executor kill-switch honors BOTH old+new property namespaces (CDX-7) and `execute()` requires a wrapper-minted capability bound to the consumed nonce (CDX-6) — live behavior at P8 (SNOW_EGRESS.md) |
| T20 | Recovery snapshot store = 2nd sensitive DB | retention + KEK + PII class + explicit table enablement | ✅ **store built + wired** `recovery/snapshots.ts` → `SNAPSHOT_KV` (30-day TTL, sealed under versioned `SNAPSHOT_KEK` ring, fail-closed before mutate) · `audit-recovery.test.ts`, `mutation-wiring.test.ts`; policy in RETENTION.md (P4) |
| T1/T2 | Stolen Cloudflare/ServiceNow token | AES-GCM AAD-bound envelope; versioned-KEK ring; per-(user,instance) isolation | ✅ `auth/crypto.ts` (content-addressed KEK ring, rotation) + `auth/token-store.ts` + DO partition · `crypto.test.ts`, `token-store.test.ts`, `do-partition.test.ts` |
| T9 | PDI hibernation mid-flight | `/health` probe; typed `instance_hibernating` | 🟡 error mapping ✅ `sn/errors.ts`; splash detection pending |
| T12 | Endpoint exposed publicly | prod `/mcp` requires MCP-client token w/ audience/scope | ✅ **wired** `index.ts` exports `OAuthProvider` (`apiRoute:"/mcp"`, `allowPlainPKCE:false`); unauthenticated `/mcp` → 401 · `health.test.ts` (asserts the 401), `oauth-kv.test.ts` (KV fail-closed) |

**Net:** the host-side authorization, isolation, cost, redaction, idempotency, audit, recovery,
KEK-rotation, and OAuth mitigations are **wired into the live request path and locally tested**
(call-graph evidence above). The ServiceNow-side executor controls are **source-complete and
locally tested** but their live behavior is **verified in P8** (operator-gated): P7 changed the
signed actor payload (added `reason`; enforced `actor.instance`), so the earlier live executor
proof predates the hardened build and must be re-run after the coordinated host+executor
redeploy. The executor-side P8-live gates are: the `instance_name` property shape, the
`GlideDigest` SHA-256 UTF-8 encoding (0.13a), and the `x_1793136_mcp_nonce` unique-index DB enforcement
(the replay-race arbiter).
