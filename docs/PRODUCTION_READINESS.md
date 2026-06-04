# Production Readiness

**Status date:** 2026-06-03  
**App version:** 0.1.0  
**Worker compatibility date:** 2026-05-13  
**Posture:** source-complete for local T1 gates; live sub-prod evidence still operator-gated.

This is the release ledger for the ServiceNow Code Mode MCP connector. It supersedes the historical
status notes in `docs/archive/GA_CHECKLIST.md` for current production-readiness tracking.

## Release Gates

| Gate | Required evidence | Current status |
|---|---|---|
| Local host gates | `npm run copy-wasm`, `npm run typecheck`, `npm test`, `npm run check:verifier-sync` | Implemented in CI and locally runnable |
| Fluent build | `npm ci && npm run build` in `sn-executor-app/fluent` | Implemented in CI |
| Dependency audit | Root and Fluent `npm audit --audit-level=high` | Implemented in CI; Fluent moderate residuals documented in `docs/archive/GA_CHECKLIST.md` |
| Secret scan | Gitleaks GitHub Action | Implemented in CI |
| Static analysis | CodeQL JavaScript/TypeScript | Implemented in CI |
| SBOM | CycloneDX npm SBOM artifact | Implemented in CI |
| Production posture | `DEPLOYMENT_PROFILE=production` preflight passes with restrictive policy, strong secrets, pinned instance, scoped executor path, OIDC/per-user OAuth, and admin-script verifier attestation when enabled | Implemented in source; requires real env |
| OIDC identity | IdP authorization-code + PKCE, signed ID-token validation, nonce/state replay rejection, refresh-time group/policy re-evaluation | Mock-IdP tests implemented; live IdP tenant pending |
| Executor proof | `scripts/executor-scoped-verify.mjs` against sub-prod | CI manual-dispatch hook added; operator-run pending |
| Deployed MCP e2e | `npm run deploy:e2e` against deployed Worker + sub-prod ServiceNow | CI manual-dispatch hook added; operator-run pending |
| KEK rotation drill | Current->previous rotation with existing grants decrypting | Pending live/sub-prod evidence |
| Kill-switch drill | Scoped executor toggles reject and then restore execution | Pending live/sub-prod evidence |
| Audit/SIEM | Host audit and ServiceNow audit rows forwarded to append-only sink | Design documented; SIEM sink operator-owned |

## Operator Inputs Required

- Non-PDI ServiceNow sub-production instance and scoped app prefix.
- Enterprise IdP tenant with an OIDC confidential client and refresh-token issuance.
- Cloudflare environment/secrets for production deploy.
- SIEM or append-only audit sink destination.
- Branch protection and required-review settings in GitHub.

## Current Exceptions

- `@cloudflare/codemode` and `@cloudflare/workers-oauth-provider` are pre-1.0 runtime dependencies.
  Keep exact pins and record any signed risk acceptance before GA.
- `DEPLOYMENT_PROFILE=pilot` skips production posture checks by design, including restrictive
  ActorPolicy validation, strong-secret checks, durable binding checks, pinned-instance checks, and
  executor HMAC-key validation. Use it only for isolated pilot environments; production deploys must
  pass `DEPLOYMENT_PROFILE=production`.
- `sn-executor-app/fluent` remains `UNLICENSED` while the root package is `MIT`; resolve before
  external distribution.
- CIMD `global_fetch_strictly_public` remains intentionally unset; tests emit the upstream warning.
  Decide whether to enable it or retain this documented exception before GA.

## Evidence Log

Append one entry per release candidate:

| Date | Commit SHA | Environment | Evidence |
|---|---|---|---|
| 2026-06-03 | pending | local | Source changes added for production posture, OIDC, CI/governance, and docs; live sub-prod gates not run |
