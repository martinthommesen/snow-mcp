# FORK.md — Clone, re-scope, and deploy your own instance

This is the complete clone-and-deploy guide for a **new operator** who wants to run the ServiceNow
"Code Mode" MCP server against their own ServiceNow instance and Cloudflare account.

The system has two halves:

- **Host** — a stateless Cloudflare Worker (`packages/mcp-server`). It has **ZERO hardcoded vendor
  prefix**; it reads the executor path from the `SNOW_EXECUTOR_PATH` env binding and the instance
  host from `SNOW_INSTANCE_HOST`. **You configure it with env vars only — no source change.**
- **Executor** — a ServiceNow Fluent scoped app (`sn-executor-app/fluent`). It hardcodes the vendor
  prefix `x_1793136_mcp` because **ServiceNow enforces at build time that scoped table/role/property
  names start with your real scope prefix**. The committed source ships a working example; you swap
  it for your own prefix once, with a single script. **This is the only structural fork action.**

The repo is intentionally left buildable as `x_1793136_mcp` so the green gate
(`npm run typecheck && npm test && npm run check:verifier-sync`) passes on a fresh clone with no
edits. Re-scoping is an explicit, one-time forker step.

---

## 0. Prerequisites

- **Your own ServiceNow instance** (a PDI / dev instance or a sub-prod instance) where you control
  a vendor scope prefix of the form `x_<vendor>_mcp` (keep the trailing `_mcp` segment; only the
  vendor part varies). Your developer account must be entitled to that prefix; if `now-sdk install`
  rejects the scope, run `now-sdk init` to reserve a prefix you own and port the metadata.
- **A Cloudflare account on the Workers Paid plan.** The host uses **Worker Loader / Dynamic
  Workers**, which bills on Workers Paid (1,000 unique workers/mo included, then per-worker/day;
  plus requests + CPU). A free account cannot provision Worker Loader.
- **Node >= 20** and **npm** (host toolchain; the root `package.json` pins `"engines": {"node": ">=20"}`).
- **The ServiceNow SDK CLI (`now-sdk`, version 4.7.1)** for the executor — installed as a dev
  dependency under `sn-executor-app/fluent`, so `npm install` there is enough.
- **`openssl`** to generate secrets, and a Cloudflare API token (minted in step 4).

---

## 1. Configure the host (env vars only)

The host source contains no vendor prefix; you only fill in secrets and identifiers.

```bash
cp .dev.vars.example .dev.vars     # .dev.vars is git-ignored — NEVER commit it
```

Then edit `.dev.vars`. The load-bearing variables:

### Deployment profile
- `DEPLOYMENT_PROFILE` — must be explicit. Use `pilot` for local/dev/PDI-style bring-up where the
  historical permissive single-operator defaults are acceptable. Use `production` to enable the
  fail-closed preflight: restrictive ActorPolicy, `per_user_oauth`, strong secrets, durable
  bindings, pinned instance host, non-admin ceilings, and the scoped executor path are all checked
  before deploy/runtime traffic proceeds. Leaving this unset now fails closed.

### ServiceNow connection
- `SNOW_INSTANCE_HOST` — your instance FQDN, e.g. `dev12345.service-now.com`. The host canonicalizes
  this against the `service-now.com` allowlist before any credentialed fetch.
- `SNOW_OAUTH_CLIENT_ID` / `SNOW_OAUTH_CLIENT_SECRET` — confidential OAuth client (Auth Code + PKCE +
  secret) for `per_user_oauth`. For a quick dev bring-up on a disposable PDI you can instead set
  `SNOW_DEV_ROPC=1` plus `SNOW_DEV_ROPC_USERNAME` / `SNOW_DEV_ROPC_PASSWORD` (MFA-exempt service
  identity; leave unset in production).

### Secrets — each MUST be a CSPRNG-generated 32-byte value
Generate every one of these with `openssl rand -base64 32`:

- `OAUTH_PROVIDER_SECRET` — signing/encryption secret for the MCP-client OAuth provider.
- `X_MCP_EXECUTOR_HMAC_KEY` — the executor actor-signing HMAC key. **You will mirror this exact
  value to the ServiceNow property `<scope>.executor.hmac_secret` in step 3.** Host and instance
  must hold the same secret or every executor signature fails 401.
- The **KEK ring**:
  - `TOKEN_KEK_CURRENT` — AES-256-GCM KEK for token envelopes (TokenStoreDO).
  - `SNAPSHOT_KEK_CURRENT` — AES-256-GCM KEK for recovery snapshots.

> **First-deploy KEK rule (fresh forker).** You have nothing to migrate, so this is simple:
> generate `TOKEN_KEK_CURRENT` and `SNAPSHOT_KEK_CURRENT` with `openssl rand -base64 32`, and
> **leave `TOKEN_KEK_PREV`, `SNAPSHOT_KEK_PREV`, and the bare one-release aliases
> `TOKEN_KEK` / `SNAPSHOT_KEK` empty.** The `*_PREV` slots and the rotation procedure in
> `docs/RECOVERY.md` are rotation-time material — you do not need them on first deploy.

> **Why strong entropy is mandatory (do not weaken).** KEK derivation is an *unsalted single
> SHA-256* (kept deterministic so the versioned ring can decrypt existing envelopes). A
> low-entropy passphrase would be offline-guessable if envelopes ever leaked. The Worker logs a
> `weak_secret_warning` for non-CSPRNG-looking KEKs / `OAUTH_PROVIDER_SECRET` — treat it as a
> release blocker. **Do NOT add salting/stretching to `deriveKeyBytes` without a coordinated KEK
> rotation** — it would make every existing encrypted token/snapshot undecryptable.

### MCP-client OAuth provider + operator identity
- `MCP_OPERATOR_SECRET` — single-operator consent secret for the MCP OAuth flow.
- `MCP_OPERATOR_USER_ID` — required stable MCP actor subject for consent grants.
- `MCP_OPERATOR_EMAIL` (optional) — actor email recorded in OAuth props / audit identity.
- `MCP_OPERATOR_ACCESS_GROUPS` (optional) — comma-separated groups for the admin_script second
  approval.

For enterprise identity, set `AUTH_MODE=oidc` instead of using the shared operator-secret consent
flow:

- `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` — OIDC confidential client for the Worker
  as a relying party. The Worker validates issuer, audience, signature algorithm, and nonce.
- `OIDC_SCOPES` — defaults to `openid profile email offline_access`. Keep `offline_access` when
  the IdP supports it; the Worker re-evaluates group claims before renewing MCP refresh grants.
- `OIDC_GROUP_POLICY_MAP` — JSON mapping IdP groups to `{ "maxMode": "...", "policy": "..." }`.
  The effective MCP ceiling is the minimum of the MCP client scopes and the mapped group ceiling.
- `ACTOR_POLICIES_JSON` — optional named ActorPolicies selected from the OIDC group mapping. Include
  a restrictive `"default"` entry if OIDC groups should fall back to a usable default policy. If no
  flat `ACTOR_POLICY_*` default and no JSON `"default"` are configured, the implicit default is
  deny-all; a grant naming any other missing policy is also deny-all.

When `AUTH_MODE=oidc`, leave `MCP_OPERATOR_SECRET` unset. The production preflight rejects an
operator secret in OIDC mode so the shared-secret path cannot remain accidentally enabled.

### Origins
- `WORKER_PUBLIC_ORIGIN` — canonical `https://<worker>` origin; required for `per_user_oauth`
  redirect/ticket URLs. (Set this after step 4 prints your Worker URL, or to your known URL.)
- `ALLOWED_ORIGINS` — comma-separated allowed Origins for `/mcp` and the auth surface.
- `ALLOW_LOCALHOST="true"` — dev only; permits `http://localhost` Origins.

### Executor path (set after re-scoping in step 2)
- `SNOW_EXECUTOR_PATH` — the literal **two-segment** scoped REST path. After re-scoping to
  `x_<vendor>_mcp` this is `/api/x_<vendor>_mcp/x_mcp/executor/run` (your scope namespace + the
  `x_mcp` service id, which **stays literal**). See the path warning in step 3.

> `admin_script` is **default-deny**. `run_code` in `admin_script` mode is rejected
> (`capability_denied`) unless the acting MCP user is in `ADMIN_SCRIPT_ALLOWLIST`. `read_only` and
> `write` modes are unaffected. In `DEPLOYMENT_PROFILE=pilot`, leaving the `ACTOR_POLICY_*` vars
> empty keeps the permissive single-operator default. In `DEPLOYMENT_PROFILE=production`, configure
> a restrictive default ActorPolicy via the flat `ACTOR_POLICY_*` vars or an explicit JSON
> `"default"` policy, or the preflight rejects the deploy/boot.

---

## 2. The one-time re-scope step (`scripts/rescope.mjs`)

This is the only structural fork action. It swaps the example prefix `x_1793136_mcp` for yours
across the Fluent app and the executor install/verify scripts, regenerates the build-managed key
file, and updates the scope id.

### Run it

```bash
node scripts/rescope.mjs x_<vendor>_mcp            # scopeId auto-generated
# or pin a specific scope id:
node scripts/rescope.mjs x_<vendor>_mcp <scopeId>
```

- **`<new-scope>` (required)** — your full vendor scope, e.g. `x_acme_mcp`. Must match
  `^((x|sn)_[a-z0-9_]+|global)$` **and** be 4–18 characters. Keep the trailing `_mcp` segment.
- **`<scopeId>` (optional)** — a 32-hex GUID matching `^([0-9a-f]{32}|global)$`. If omitted, the
  script generates one via `crypto.randomBytes(16).toString('hex')`. It must be valid and unique to
  you so deploys are reproducible; `now-sdk install` reconciles the app record on your instance.

### What it does (idempotent)

1. Validates `<new-scope>` (regex + 4–18 length) and `<scopeId>`; fails fast on bad input.
2. Reads the **current** scope from `now.config.json` and uses *that* as the search token (not a
   hardcoded literal), so a same-target re-run is a clean no-op and repeated re-scopes work.
3. Rewrites `sn-executor-app/fluent/now.config.json` `scope` + `scopeId`.
4. Does a full-token literal substitution of the current scope across:
   - `sn-executor-app/fluent/src/fluent/x_mcp.now.ts` (table / role / property / index / ACL names
     and the `GlideRecord('<scope>_nonce')` purge),
   - `sn-executor-app/fluent/src/server/x_mcp_executor.js`,
   - `sn-executor-app/fluent/src/server/x_mcp_verify.js` **and**
     `sn-executor-app/script-include/x_mcp_verify.js` — **both copies, with the identical
     replacement string** (this is what keeps `check:verifier-sync` green),
   - `scripts/executor-install.mjs` (it WRITES the live `<scope>.executor.*` properties the global
     verifier reads — must be re-scoped together with the app or signatures fail 401),
   - `scripts/executor-scoped-verify.mjs` (the post-install live smoke test).
5. **Deletes** the generated key file `sn-executor-app/fluent/src/fluent/generated/keys.ts` so the
   next `now-sdk build` regenerates it cleanly. **Do not hand-edit `keys.ts`** — it is build-managed
   and hand-editing keeps the author's `sys_id`s (causing insert-instead-of-update corruption).

### What it does NOT touch (intentionally)

The full-token (`x_1793136_mcp`) substitution leaves these literals alone, and they must stay:

- The REST **service id `x_mcp`**, the script-include **class `x_mcp_verify`**, the
  **`x_mcp_executor`** name, and the capability label **`x_mcp_exec_cap`**.
- The **intentional bare legacy namespace** `x_mcp.executor.*` in `x_mcp_executor.js` — the
  fail-closed kill-switch reads (`gs.getProperty('x_mcp.executor.enabled' | '...run_server_script_enabled')`).
  Do not let a naive `s/x_mcp/.../` "fix" rewrite these — it silently breaks fail-closed behavior.
- **Host source, host tests, docs, and `.dev.vars.example`** — host test fixtures are pinned to the
  default prefix by design and are self-consistent. The substitution must not be broadened to them.

### Notes on `keys.ts`
`keys.ts` is GENERATED on every `now-sdk build` (the committed Fluent build is plain `now-sdk build`,
no `--frozenKeys`). The explicit `$id` key names (`role_executor`, `t_audit`, `acl_executor`, …) are
prefix-free and stable; `sys_id`s are auto-minted against *your* instance on first build; the
composite `name:` values are rewritten with your new prefix. After re-scoping you regenerate it
(step 3) and **commit the regenerated file**.

---

## 3. Install the executor on ServiceNow

```bash
# Build the host first — the install/verify scripts import compiled JS from packages/mcp-server/dist
# (which is git-ignored, so a fresh clone has none). tsc -b is what emits it.
npm install
npm run typecheck                                                    # = tsc -b -> emits packages/mcp-server/dist

cd sn-executor-app/fluent
npm install
npx now-sdk auth --add https://<instance> --type basic --alias dev   # or --type oauth
npx now-sdk build                                                    # regenerates generated/keys.ts with your prefix + fresh sys_ids
npx now-sdk install -a dev                                           # creates scoped tables, roles, ACLs, REST endpoint, properties, purge job
cd ../..
node scripts/executor-install.mjs        # installs the GLOBAL x_mcp_verify core + properties only
node scripts/executor-scoped-verify.mjs  # live smoke test (role/ACL gate, audit-first row, HMAC verify, round-trip)
```

After installing, in ServiceNow:

- **Set the property `<scope>.executor.hmac_secret`** = the exact `X_MCP_EXECUTOR_HMAC_KEY` value
  from your `.dev.vars`. (`executor-install.mjs`, now re-scoped, writes the `<scope>.executor.*`
  namespace and creates the break-glass toggles disabled if they do not already exist; confirm
  `hmac_secret` matches the host secret.)
- **Assign the `<scope>.executor` role** to your integration user (e.g. `mcp_integration_user`).
- **Enable the break-glass executor deliberately** only after the role and HMAC are correct:
  set `<scope>.executor.enabled=true` and `<scope>.executor.run_server_script_enabled=true`.
  Fresh installs default both to `false`; upgrades preserve any existing operator-set value.

> **Architecture note (why the global core exists).** `new Function` (eval) and
> `GlideCertificateEncryption` (HMAC) are global-only — not permitted in scoped apps. So the scoped
> `executor/run` does what scope allows (audit-first, kill switch, byte cap, role-gated endpoint)
> and calls the GLOBAL `x_mcp_verify.verify()` before consuming the scoped nonce, then
> `x_mcp_verify.execute()` after the nonce insert succeeds. That is why there are two copies of
> `x_mcp_verify.js` and why `check:verifier-sync` enforces their bodies stay byte-identical.

> **`SNOW_EXECUTOR_PATH` — get the path form exactly right (silent-404 trap).** Set the Worker
> binding to the literal **two-segment** scoped path:
> ```
> SNOW_EXECUTOR_PATH=/api/<scope>/x_mcp/executor/run     # e.g. /api/x_acme_mcp/x_mcp/executor/run
> ```
> - NOT the one-segment form `/api/<scope>/executor/run` — it **404s**.
> - NOT a numeric global form `/api/<vendor-number>/x_mcp/...` — that was a deprecated, unverified
>   global endpoint and is retired.
> The `x_mcp` service id stays literal in the path even after you re-scope the namespace.

### Re-verify the green gate after re-scoping

```bash
npm run typecheck && npm test && npm run check:verifier-sync
```

This stays green after a forker re-scope: the verifier-sync transform is symmetric across both
`x_mcp_verify.js` copies, and the host tests use self-contained fixtures that are not re-scoped.

> **The green gate does NOT verify the Fluent app.** Root `tsc -b` covers only `packages/`
> (host); the Fluent scoped app is outside the `tsc` graph. So a passing gate proves the host and
> the verifier-sync invariant — **not** that the scoped app builds or that `keys.ts` regenerated
> correctly. The only checks that prove the executor are `npx now-sdk build`, `npx now-sdk install`,
> and `scripts/executor-scoped-verify.mjs` (step 3) against your live instance. Treat those as the
> real executor gate; they cannot be run offline.

---

## 4. Deploy the host (Cloudflare Worker)

The production deploy path is Alchemy IaC. It provisions the Worker + Worker Loader + KV + Durable
Objects + secrets from `.dev.vars`, and **adopts KV namespaces by title** (it does not pin the
author's namespace GUIDs), so it deploys cleanly into *your* account.

1. **Mint a Cloudflare API token.** Dashboard → My Profile → API Tokens → Create Token → use the
   **"Edit Cloudflare Workers"** template → Create Token → copy. Add it to `.dev.vars` (git-ignored):
   ```
   CLOUDFLARE_API_TOKEN="<paste>"
   ```
   Alchemy authenticates via this token, not wrangler's OAuth session.

2. **Deploy:**
   ```bash
   npm run deploy            # = copy-wasm + alchemy deploy; reads .dev.vars; prints YOUR Worker URL
   # teardown:  npm run deploy:destroy
   ```
   `DEPLOYMENT_PROFILE` is intentionally breaking: unset/unknown fails closed. For a production
   profile, Alchemy validates the assembled KV/DO bindings plus the raw secret/config values before
   uploading the Worker, so the terminal reports the misconfiguration list rather than relying on a
   later request path to discover it.
   The Worker URL is derived from **your** Cloudflare account subdomain
   (`servicenow-mcp.<your-subdomain>.workers.dev`) — it is not committed. If you set
   `WORKER_PUBLIC_ORIGIN` to a placeholder earlier, update it to the printed URL and redeploy.

3. **Smoke-test:**
   ```bash
   curl https://<your-worker-url>/health      # -> { "ok": true }
   ```
   Then connect your MCP client (e.g. MCP Inspector / Claude) to `https://<your-worker-url>/mcp`.

> **Coordinated deploy.** The signed `reason` canonical is shared between host and executor. A
> half-deploy (host without re-installing the executor, or vice versa) is a **total signature
> mismatch**. Deploy the Worker and (re)install the executor together — both or neither.

---

## 5. Verify-live gates you should run

Beyond `scripts/executor-scoped-verify.mjs`, confirm these on your live instance (full detail in
`docs/archive/GA_CHECKLIST.md`):

1. **`instance_name` property shape.** The instance `instance_name` property MUST return the **bare
   subdomain** (e.g. `dev12345`), not an FQDN and not empty. An FQDN/empty value makes
   `_instanceMatches` reject everything → **total 401 brick**.
2. **Duplicate-nonce rejection is real.** A concurrent duplicate-`value` nonce INSERT must actually
   be REJECTED. The **DB-enforced unique index** is the arbiter. Note: now-sdk 4.7.1 creates the
   physical DDL index but does **not** write the `sys_index` catalog row — so verify enforcement
   **functionally (concurrent INSERT), never by reading the catalog row**.
3. **KEK rotation drill** when you later rotate — follow `docs/RECOVERY.md`.

---

## 6. Caveats you will hit

- **Nonce purge interval.** The scoped **`MCP Nonce Purge`** job uses the SDK `Duration(...)`
  helper so `sysauto_script.run_period` builds as `1970-01-01 00:15:00`. Replay protection does not
  depend on the purge (the nonce unique index does), but `scripts/executor-scoped-verify.mjs` now
  fails if the live period is missing or wrong because otherwise table growth is unbounded.
- **Fluent SDK toolchain audit.** `sn-executor-app/fluent` keeps `@servicenow/sdk@4.7.1`, but pins
  patched transitive build-tool packages via `overrides`. Keep `npm audit --audit-level=moderate`
  clean in that nested package; **do not run `npm audit fix --force`** because it downgrades the SDK
  and pulls older critical-vulnerable toolchain packages.
- **Author-specific IDs remaining outside the re-scope set.** These are illustrative / status
  values, not used by the Alchemy deploy path, but genericize them if you run those tools directly:
  - `packages/mcp-server/wrangler.jsonc` pins the **author's KV namespace GUIDs**
    (`SCHEMA_KV` / `OAUTH_KV` / `AUDIT_KV` / `SNAPSHOT_KV` ids). The Alchemy deploy (`npm run deploy`)
    adopts KV by title and ignores these, but `wrangler dev` / `wrangler types` against *your*
    account need your own namespace ids. Replace them if you use wrangler directly.
  - Author host names (`dev374488` / `dev000000`) and the Cloudflare subdomain `lammesen` appear in
    docs/examples only — your values come from `.dev.vars` and your CF account.

---

## Quick reference: end-to-end order

```bash
# 1. Configure host
cp .dev.vars.example .dev.vars      # fill SNOW_INSTANCE_HOST, KEK ring, OAUTH_PROVIDER_SECRET,
                                    # X_MCP_EXECUTOR_HMAC_KEY, MCP_OPERATOR_*, ALLOWED_ORIGINS, ...

# 2. Re-scope the Fluent app (one-time)
node scripts/rescope.mjs x_<vendor>_mcp

# 3. Build the host (emits dist/ that the install/verify scripts import), then install the executor
npm install && npm run typecheck            # tsc -b -> packages/mcp-server/dist (git-ignored, absent in a fresh clone)
cd sn-executor-app/fluent && npm install
npx now-sdk auth --add https://<instance> --type basic --alias dev
npx now-sdk build && npx now-sdk install -a dev && cd ../..
node scripts/executor-install.mjs
node scripts/executor-scoped-verify.mjs
#   then in ServiceNow: set <scope>.executor.hmac_secret = X_MCP_EXECUTOR_HMAC_KEY,
#   assign the <scope>.executor role, set SNOW_EXECUTOR_PATH=/api/<scope>/x_mcp/executor/run

# 4. Verify the gate, then deploy the host
npm run typecheck && npm test && npm run check:verifier-sync
npm run deploy
curl https://<your-worker-url>/health     # { "ok": true }
git add -A && git commit   # commit the rescoped source AND the regenerated keys.ts (all files rescope.mjs touched)
```
