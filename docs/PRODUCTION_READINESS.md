# Production Readiness

**Status date:** 2026-06-04
**App version:** 0.1.0  
**Worker compatibility date:** 2026-05-13  
**Posture:** source-complete for local T1 gates and manual live gates; live sub-prod evidence still operator-run.

This is the release ledger for the ServiceNow Code Mode MCP connector and the current source of
truth for production-readiness tracking.

## Release Gates

| Gate | Required evidence | Current status |
|---|---|---|
| Local host gates | `npm run copy-wasm`, `npm run typecheck`, `npm test`, `npm run check:verifier-sync` | Implemented in CI and locally runnable |
| Fluent build | `npm ci && npm run build` in `sn-executor-app/fluent` | Implemented in CI |
| Dependency audit | Root and Fluent `npm audit --audit-level=high` | Implemented in CI; Fluent dev/build-toolchain residuals tracked under Current Exceptions below |
| License policy | `node scripts/license-report.mjs --policy license-policy.json --enforce ...` | Implemented in CI with explicit build/deploy-toolchain exceptions |
| Secret scan | Gitleaks GitHub Action | Implemented in CI |
| Static analysis | GitHub CodeQL default setup | Enabled in repository settings; no checked-in advanced workflow while default setup is active |
| SBOM | CycloneDX npm SBOM artifact | Implemented in CI |
| Production posture | `DEPLOYMENT_PROFILE=production` preflight passes with OIDC identity, restrictive policy, strong secrets, pinned instance, scoped executor path, per-user OAuth, `MCP_ADMISSION_DO`, `AUDIT_SIEM_ATTESTED=true`, and admin-script verifier attestation when enabled | Implemented in source; requires real env |
| MCP admission | Authenticated `/mcp` requests are keyed by validated `userId`, capped at 60 req/min and 4 in-flight leases, and fail closed on limiter failure | Implemented and unit-tested |
| OIDC identity | IdP authorization-code + PKCE, signed ID-token validation, nonce/state replay rejection, refresh-time group/policy re-evaluation | Mock-IdP tests plus deployed browser E2E script implemented; live IdP tenant run pending |
| Executor proof | `scripts/executor-scoped-verify.mjs` against sub-prod proves executor-only execution, raw HMAC property read denial, forged-signature rejection, nonce uniqueness, and kill-switch restore | CI manual-dispatch hook added; operator-run pending |
| Deployed MCP e2e | OIDC authorization-code E2E against deployed Worker + sub-prod ServiceNow | CI manual-dispatch hook added via `production-oidc-deployed-e2e`; operator-run pending |
| KEK rotation drill | Current->previous rotation with existing grants decrypting | Pending live/sub-prod evidence |
| Kill-switch drill | Scoped executor toggles reject and then restore execution | Pending live/sub-prod evidence |
| Audit/SIEM | Host audit rows written to 30-day `AUDIT_KV` and emitted as redacted structured logs for Logpush/SIEM; production posture requires `AUDIT_SIEM_ATTESTED=true` after receipt is proven | Implemented in source; external SIEM receipt pending |

## Operator Inputs Required

- Non-PDI ServiceNow sub-production instance and scoped app prefix.
- Enterprise IdP tenant with an OIDC confidential client and refresh-token issuance.
- Low-privilege OIDC E2E account for `npm run production:oidc:e2e`; by default it requests
  `servicenow:write` and expects the refreshed MCP token to deny write after group-policy
  re-evaluation. Configure `OIDC_E2E_*_SELECTORS` only when the IdP login form is non-standard.
- Cloudflare environment/secrets for production deploy.
- SIEM or append-only audit sink destination, plus evidence that `event="mcp_audit_record"` reaches it.
- Optional executor-only ServiceNow verifier credentials (`SNOW_EXECUTOR_TEST_USERNAME` /
  `SNOW_EXECUTOR_TEST_PASSWORD`). If unset, the verifier creates and cleans up a temporary
  non-admin account with only `x_1793136_mcp.executor`.
- GitHub environments `sub-prod` and `production` with required reviewer protection and these
  environment secrets before live gates can run: `SNOW_INSTANCE_HOST`, `SNOW_DEV_ROPC_USERNAME`,
  `SNOW_DEV_ROPC_PASSWORD`, `X_MCP_EXECUTOR_HMAC_KEY`, `SNOW_EXECUTOR_PATH`, optional
  `SNOW_EXECUTOR_TEST_USERNAME` / `SNOW_EXECUTOR_TEST_PASSWORD`, plus the `OIDC_E2E_*` secrets for
  deployed OIDC browser proof.
- Branch protection and required-review settings in GitHub.

## Current Exceptions

- `@cloudflare/codemode` and `@cloudflare/workers-oauth-provider` are pre-1.0 runtime dependencies.
  Keep exact pins and record any signed risk acceptance before GA.
- `DEPLOYMENT_PROFILE=pilot` exists only for local dev/test via Wrangler. Alchemy deploys must pass
  `DEPLOYMENT_PROFILE=production` with `AUTH_MODE=oidc`; the shared operator-secret consent flow and
  `npm run pilot:e2e` are pilot/dev only.
- `sn-executor-app/fluent` remains `UNLICENSED` as a private ServiceNow scoped-app package. This is
  an explicit license-policy exception and must be resolved before external npm-style distribution.
- `sn-executor-app/fluent` `npm audit` reports dev/build-toolchain advisories (e.g. `@fastify/static`
  and `js-yaml`, transitively pinned by `@servicenow/sdk@4.7.1`). `npm audit fix --force` would force
  a breaking SDK downgrade, so no upgrade is applied; residual risk is dev-only (the SDK runs at build
  time, not in ServiceNow). Re-audit when ServiceNow ships an SDK that bumps these transitive pins.
- CIMD `global_fetch_strictly_public` remains intentionally unset; tests emit the upstream warning.
  Decide whether to enable it or retain this documented exception before GA.

## Evidence Log

Append one entry per release candidate:

| Date | Commit SHA | Environment | Evidence |
|---|---|---|---|
| 2026-06-04 | pending | local / GitHub config | Added admin-only HMAC property roles, executor-only live verifier path, masked-query normalization, MCP admission DO, mutation freeze, structured audit log fanout, SIEM posture gate, Dependabot, enforced license policy, protected `sub-prod`/`production` environments, and hardened main ruleset; live sub-prod/production secrets and evidence still pending |

## Live Evidence Template

Append one row per live run with: exact commit SHA, workflow URL, GitHub environment name,
ServiceNow instance, started/completed timestamps, verifier command, and exception notes. Required
evidence before GA: executor secret isolation, scoped executor verification, deployed OIDC E2E,
refresh-time write denial, masked-query semantics on the live instance, key rotation, kill switch,
rollback, SIEM receipt, and recovery drill.
