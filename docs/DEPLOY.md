# Deploy runbook (Alchemy IaC, plan §1/§2.11)

Everything is prepared and dry-run-validated. Deploy is **one command** once a Cloudflare
API token is present.

## Status (prepared)

- ✅ KV namespaces created in the account: `servicenow-codemode-SCHEMA_KV`
  (`40c98ca0d717428e89e097ef30887b8a`), `servicenow-codemode-OAUTH_KV`
  (`8de4edaad4d8481988a80be5edc77b46`) — adopted by `alchemy.run.ts`.
- ✅ `alchemy.run.ts` — Worker + `LOADER` (Worker Loader) + both KV + four **sqlite**
  Durable Objects (AuthCorrelationDO/TokenStoreDO/BudgetDO/MutationLedgerDO) + secrets.
- ✅ `wrangler deploy --dry-run` passes: 4.1 MB gzip, **all bindings resolve** including
  Worker Loader.
- ✅ Secrets present in `.dev.vars` (instance host, ROPC creds, HMAC key, KEKs, OAuth client).

> **Secret entropy (M-8).** `TOKEN_KEK*`, `SNAPSHOT_KEK*`, `OAUTH_PROVIDER_SECRET`, and
> `X_MCP_EXECUTOR_HMAC_KEY` MUST be CSPRNG-generated 32-byte values — generate each with
> `openssl rand -base64 32`. KEK derivation is an unsalted single SHA-256 (kept deterministic so
> the versioned ring can still decrypt existing envelopes), so a low-entropy passphrase would be
> offline-guessable if envelopes ever leak. The Worker logs a structured `weak_secret_warning` at
> startup when a KEK does not look CSPRNG-strong — treat it as a release blocker, not noise. Do
> NOT change `deriveKeyBytes` to add salting/stretching without a KEK rotation (it would make every
> existing encrypted token/snapshot undecryptable).

## The one blocker: `CLOUDFLARE_API_TOKEN`

Alchemy authenticates via `CLOUDFLARE_API_TOKEN` (not wrangler's OAuth session). Mint one:

1. Cloudflare dashboard → **My Profile → API Tokens → Create Token**.
2. Use the **"Edit Cloudflare Workers"** template → Continue to summary → Create Token → Copy.
3. Add to `.dev.vars` (gitignored): `CLOUDFLARE_API_TOKEN="<paste>"`

> Note: requires **Workers Paid** on the account — Dynamic Workers / Worker Loader bill per
> §2.5 (1,000 unique workers/mo included, then +$0.002/worker/day; plus requests + CPU).

## Deploy

```bash
npx alchemy deploy      # reads .dev.vars; provisions Worker + bindings; prints the URL
# teardown:  npx alchemy destroy
```

## Post-deploy

1. Note the printed Worker URL; smoke-test `GET <url>/health` → `{ ok: true }`.
2. Connect MCP Inspector / Claude to `<url>/mcp`. `describe_table`/`list_tables` work against
   the ServiceNow instance via the dev Basic-Auth path; `run_code` runs in the real
   Worker-Loader sandbox (the piece this local env couldn't exercise).
3. For the executor (`runServerScript`), install `sn-executor-app/` on ServiceNow first and
   mirror `X_MCP_EXECUTOR_HMAC_KEY` to the `x_1793136_mcp.executor.hmac_secret` property (still
   pending — Studio install).

## Remaining external work (P8 — live verification + redeploy, operator-gated)

- Build + install the **canonical Fluent scoped-app executor** `x_1793136_mcp` (D11) — hardened
  in source in P7 (instance-claim, null-safe MAC, signed/audited `reason`, byte-safe sample,
  DB-unique-indexed `x_1793136_mcp_nonce` replay-close, admin ACLs); install via `now-sdk install` + the
  global `x_mcp_verify` helper, then prove S8/S9/S16, B1, B6 on `dev374488` in P8.
- The OAuthProvider consent/PKCE flow + per-user TokenStoreDO storage are now **wired in source**
  (P6a signed consent-state; P6b per-user OAuth authorize/callback + TokenStoreDO). The SN token
  grant was live-verified **pre-hardening** (B9); the per-user dance is re-verified in P8.
- Coordinated redeploy: P7's signed-`reason` canonical is a breaking payload change — deploy the
  Worker and reinstall the executor **together** (both or neither), and point `SNOW_EXECUTOR_PATH`
  at the literal two-segment scoped path **`/api/x_1793136_mcp/x_mcp/executor/run`** (namespace
  `x_1793136_mcp` + service `x_mcp`). NOT the numeric `/api/1793136/x_mcp/...` form (a deprecated
  global endpoint that bypassed verification — retired in P8) and NOT the one-segment
  `/api/x_1793136_mcp/executor/run` (404s). ✅ Live-verified 2026-05-31: `deploy:e2e` 13/13 and
  `executor-scoped-verify.mjs` 13/13 through the scoped endpoint.
- Move off the Basic-Auth dev path to `per_user_oauth` for multi-user deployments.
