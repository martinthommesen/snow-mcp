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
