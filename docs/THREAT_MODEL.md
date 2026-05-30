# Threat model — implementation status (plan §11)

The full threat table is in `DEVELOPMENT_PLAN.md` §11 (T1–T20). This file annotates each
mitigation with its **current** status: ✅ implemented + tested · 🟡 implemented, live/PDI
proof pending · ⬜ not yet built.

| # | Threat | Mitigation | Status |
|---|---|---|---|
| T3 | Sandbox code calls `fetch("evil")` | `globalOutbound:null` makes fetch throw; no creds in sandbox | ✅ (0.8a) |
| T4 | LLM code mutates records | effective-mode (§2.0.1) + ActorPolicy (§2.12) + attribution; recovery (§7.7) | ✅ gates (B3/B4/B5, capability); 🟡 recovery wiring |
| T5 | Sensitive output in logs | redactor denylist + token patterns; hashes only in audit | ✅ `observability/redact.ts` |
| T7 | Schema cache leaks fields across users | user-aware cache key; short TTL; field masking | 🟡 masking ✅ (live B5); KV cache not wired |
| T8 | Replay of request/executor call | leveled idempotency; executor nonce | ✅ ledger/S17; 🟡 nonce (executor unverified) |
| T10 | Dynamic Worker cost explosion | multi-dim atomic reserve-before-load + per-run caps | ✅ (S14) |
| T11 | MCP SDK cross-client leak (CVE) | per-request `McpServer` | ✅ (§2.3) |
| T13 | DNS rebinding (missing Origin check) | reject invalid Origin (403); localhost bind | ✅ (S12) |
| T14 | OAuth flow abuse | exact redirect_uri, state/nonce, PKCE, consent | ⬜ OAuth flow not wired (instance has no client) |
| T15 | **Forged actor metadata** | host HMAC-signs; executor verifies (freshness+nonce) | 🟡 host signer ✅ + ASCII-canonical (B1-shape); in-scope verify source-only |
| T16 | **Mode escalation** via `mode` input | `effectiveMode=min(requested,scope,tenant,instance)` | ✅ (B3/B4) |
| T17 | **integration_user over-reads** | ActorPolicy before every RPC | ✅ **live-verified** (B5) |
| T18 | `scriptedRest` bypasses executor | path denylist | ✅ (B2) |
| T19 | **ServiceNow-side egress** via runServerScript | tenant toggle + approval + non-recoverable label | 🟡 approval ✅ (§7.9); executor unverified (SNOW_EGRESS.md) |
| T20 | Recovery snapshot store = 2nd sensitive DB | retention + KEK + PII class + opt-out | 🟡 policy (RETENTION.md); store not built |
| T1/T2 | Stolen Cloudflare/ServiceNow token | AES-GCM AAD-bound envelope; KEK rotation; per-(user,instance) isolation | ✅ crypto + isolation (S7-shape, DO partition) |
| T9 | PDI hibernation mid-flight | `/health` probe; typed `instance_hibernating` | 🟡 error mapping ✅; splash detection pending |
| T12 | Endpoint exposed publicly | prod `/mcp` requires MCP-client token w/ audience/scope | ⬜ OAuth provider not wired |

**Net:** the host-side authorization, isolation, cost, redaction, and idempotency mitigations
are implemented and tested (several live-verified). The OAuth flow and the ServiceNow-side
executor are the two unverified spines — both blocked on provisioning the instance
(OAuth client, scoped-app install).
