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
   mirror `X_MCP_EXECUTOR_HMAC_KEY` to the `x_mcp.executor.hmac_secret` property (still
   pending — Studio install).

## Remaining external work (post-deploy)

- Install + prove the `x_mcp` scoped-app executor (S8/S9/S16, B1, B6) — ServiceNow Studio.
- Wire the OAuthProvider consent/PKCE flow into the request path (token grant already
  live-verified, B9) and per-user TokenStoreDO storage.
- Move off the Basic-Auth dev path to per-user OAuth for multi-user deployments.
