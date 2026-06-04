# Production Readiness

**Status date:** 2026-06-04
**App version:** 0.1.0  
**Worker compatibility date:** 2026-05-13  
**Posture:** source-complete for local T1 gates; live sub-prod evidence still operator-run.

This is the release ledger for the ServiceNow Code Mode MCP connector and the current source of
truth for production-readiness tracking.

## Release Gates

| Gate | Required evidence | Current status |
|---|---|---|
| Local host gates | `npm run copy-wasm`, `npm run typecheck`, `npm test`, `npm run check:verifier-sync` | Implemented in CI and locally runnable |
| Fluent build | `npm ci && npm run build` in `sn-executor-app/fluent` | Implemented in CI |
| Dependency audit | Root and Fluent `npm audit --audit-level=high` | Implemented in CI; Fluent dev/build-toolchain residuals tracked under Current Exceptions below |
| Secret scan | Gitleaks GitHub Action | Implemented in CI |
| Static analysis | CodeQL JavaScript/TypeScript workflow | Implemented in CI |
| SBOM | CycloneDX npm SBOM artifact | Implemented in CI |
| Production posture | `DEPLOYMENT_PROFILE=production` preflight passes with OIDC identity, restrictive policy, strong secrets, pinned instance, scoped executor path, per-user OAuth, and admin-script verifier attestation when enabled | Implemented in source; requires real env |
| OIDC identity | IdP authorization-code + PKCE, signed ID-token validation, nonce/state replay rejection, refresh-time group/policy re-evaluation | Mock-IdP tests implemented; live IdP tenant pending |
| Executor proof | `scripts/executor-scoped-verify.mjs` against sub-prod | CI manual-dispatch hook added; operator-run pending |
| Deployed MCP e2e | OIDC authorization-code E2E against deployed Worker + sub-prod ServiceNow | Pending; the checked-in `npm run pilot:e2e` script is operator-secret pilot/dev proof only |
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
- `DEPLOYMENT_PROFILE=pilot` exists only for local dev/test via Wrangler. Alchemy deploys must pass
  `DEPLOYMENT_PROFILE=production` with `AUTH_MODE=oidc`; the shared operator-secret consent flow and
  `npm run pilot:e2e` are pilot/dev only.
- `sn-executor-app/fluent` remains `UNLICENSED` while the root package is `MIT`; resolve before
  external distribution.
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
| 2026-06-04 | pending | local | Source changes require production OIDC, scoped executor path, CodeQL static analysis, hardened executor properties, and reconciled verifier comments; live sub-prod gates not run |
