# ServiceNow Code Mode MCP Server

A stateless Cloudflare Worker that exposes three MCP tools — `run_code`,
`describe_table`, and `list_tables`. Instead of one MCP tool per ServiceNow
operation, the model writes **TypeScript** against a typed `servicenow.*` RPC
surface. That code is transpiled with `esbuild-wasm` and executed in a per-call
**Worker Loader** sandbox with **no network** (`globalOutbound: null`) and **no
credentials** — the sandbox can only call back into the host over a structured
RPC channel. `describe_table` and `list_tables` give the model the live schema it
needs to author that code.

The safety thesis is **maximum access, achieved safely** — every effect the model
can reach is recoverable, attributable, auditable, individually gateable, and
revocable, rather than purchased by lowering the access ceiling.

## Two components

- **Host** — a generic Cloudflare Worker (`packages/mcp-server`). It has **zero
  hardcoded vendor prefix**: it reads the executor path from `SNOW_EXECUTOR_PATH`
  and the instance host from `SNOW_INSTANCE_HOST` at runtime. Nothing about a
  specific ServiceNow instance or scoped app is baked into the host source.
- **Executor** — a ServiceNow Fluent scoped app (`sn-executor-app/fluent`) that
  runs in-instance and performs the privileged work behind a role-ACL-gated,
  HMAC-verified endpoint. The committed source hardcodes the vendor prefix
  `x_1793136_mcp` as a **working example** — ServiceNow enforces that scoped
  table/role/property names begin with the real scope prefix, so the source must
  contain a buildable one. You re-scope it to your own prefix when you fork.

## Fork it

To deploy against your own ServiceNow instance and Cloudflare account, see
[`FORK.md`](docs/FORK.md): set the environment variables and perform the one one-time
re-scope step that swaps `x_1793136_mcp` for your own prefix.

## Develop

```bash
npm install                 # exact-pinned deps; lockfile committed
npm run typecheck           # tsc -b (clean)
npm test                    # vitest, runs inside workerd
npm run check:verifier-sync # the two x_mcp_verify.js copies stay byte-identical
npm run dev                 # wrangler dev --port 8787  (local /mcp + /health)
```

The green gate is `npm run typecheck && npm test && npm run check:verifier-sync`:
`tsc -b` is clean, the vitest suite passes, and the two verifier bodies are
byte-identical.

`npm test` **must** run in workerd — the Code Mode path depends on Worker Loader
and `esbuild-wasm`, which only behave correctly under the
`@cloudflare/vitest-pool-workers` runtime. Copy `.dev.vars.example` → `.dev.vars`
(git-ignored) and fill secrets before any flow that touches ServiceNow or the
OAuth provider.

## Layout

```
packages/
  shared/                  # shared types (Mode / credential-mode / error-code)
  mcp-server/              # the host Worker: MCP tools, sandbox, RPC, auth, DOs
sn-executor-app/
  fluent/                  # the ServiceNow Fluent scoped-app executor
docs/                      # design, threat model, fork guide, ADRs, archive
```

## Security posture

The design rationale and the per-control reasoning live alongside the code:

- [`DESIGN.md`](docs/DESIGN.md) — architecture and the design decisions.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — per-control security rationale.
- [`FORK.md`](docs/FORK.md) — deployment (env vars + the one-time re-scope step).
- [`docs/ADR/0001-codemode-integration.md`](docs/ADR/0001-codemode-integration.md)
  — the Code Mode execution contract.
- [`docs/archive/`](docs/archive) — historical phase and review records.
