# Code Mode MCP Server for ServiceNow — Build-Ready Implementation Guide (Revised)

> ⚠️ **SUPERSEDED — background research only. Build from `DEVELOPMENT_PLAN.md`, not this report.**
>
> This report is retained as research context. Do **not** implement from its TL;DR, milestones, code, or caveats without checking `DEVELOPMENT_PLAN.md` (§10, "Report supersessions"). Where this report conflicts with the plan, **follow the plan.** Known supersessions:
> - **Dynamic Workers daily billing is ACTIVE as of 2026-05-26** (this report's "not yet active" wording is stale).
> - **`run_code` defaults to `read_only`**; the mode→capability map is enforced.
> - **MCP-layer authorization governs access**: a broad `integration_user` is *not* blanket authorization; effective capability = requested-mode ∩ MCP-token-scope ∩ tenant-policy ∩ credential-mode. Requested `mode` never grants, only narrows.
> - **TypeScript path** is `esbuild-wasm transform/bundle → JS string → DynamicWorkerExecutor.execute(...)` (worker-bundler is a fallback only); esbuild **strips types, it does not type-check**.
> - **Schema cache keys are user-aware**, not merely role-aware.
> - **Scoped-app executor** is **synchronous**, verifies a **signed actor payload**, checks the **kill switch after writing an audit row**, and exposes **no `allow_unsafe`**.
> - **`scriptedRest` is host-internal** in v1 — only typed, capability-mapped functions reach the sandbox.
> - **`OAUTH_KV`** binding + OAuthProvider hardening (`allowPlainPKCE:false`, scopes, resource metadata) are required; ServiceNow tokens never live in OAuth token props.
> - **Local MCP dev port is 8787**, not 8788.

**Research date / "as of":** May 30, 2026. All version numbers, beta statuses, and prices are valid as of that date and should be re-verified before a production cut.

## TL;DR

- Build the server as a **stateless Cloudflare Worker using `createMcpHandler`** from the Cloudflare Agents SDK, exposing three MCP tools — `run_code`, `describe_table`, `list_tables` — where `run_code` is implemented on top of the official `@cloudflare/codemode` SDK (`createCodeTool` + `DynamicWorkerExecutor`) and TypeScript is transpiled by `@cloudflare/worker-bundler` (esbuild-wasm inside workerd) before being handed to `env.LOADER`. Promote a stateful `McpAgent`/Durable-Object variant only when per-session OAuth token persistence or elicitation/sampling is actually needed.
- The connected identity should reach **any table, any REST API, any record, and run arbitrary server-side code** in ServiceNow; safety comes from making that reach **recoverable, attributable, auditable, individually gateable, and revocable** — not from removing capabilities. The arbitrary-script "executor" is preserved as a first-class capability but lives in a dedicated scoped application (`x_mcp`) with a custom role (`x_mcp.executor`), a REST_Endpoint ACL, per-request audit logging with code hash and user attribution, a system-property kill switch, and credentials that never enter the sandbox (only a typed RPC binding does).
- Pin every pre-1.0 dependency exactly and commit a lockfile: `@cloudflare/[email protected]`, `@cloudflare/[email protected]` (closed beta), `[email protected]` (`latest` channel; WorkerLoader binding shipped in v0.71.0), `[email protected]`, `@modelcontextprotocol/[email protected]`, `[email protected]`, `[email protected]`, `[email protected]`, `[email protected]`. Per the Cloudflare Dynamic Workers Pricing page: "The Dynamic Workers created daily charge is not yet active — you will not be billed for the number of Dynamic Workers created at this time. Pricing information is shared in advance so you can estimate future costs." (Included tier: 1,000 unique Dynamic Workers/month; overage: +$0.002 per Dynamic Worker per day.) Treat pricing as a moving target.

---

## Key Findings

1. **`createMcpHandler` is the recommended default shape** for new MCP servers on Cloudflare. The Cloudflare Agents Transport page is explicit: "MCP servers built with the Agents SDK use createMcpHandler to handle Streamable HTTP transport. Use createMcpHandler to create an MCP server that handles Streamable HTTP transport. This is the recommended approach for new MCP servers." `McpAgent` / Durable Objects are needed only when you require per-session state, elicitation, sampling, or WebSocket hibernation. We therefore make stateless `createMcpHandler` the v1 default and provide a stateful variant for the multi-tenant OAuth case.
2. **Code Mode SDK names**: the public exports are `createCodeTool` (from `@cloudflare/codemode/ai`) and `DynamicWorkerExecutor` (from `@cloudflare/codemode`), with `codeMcpServer` and `openApiMcpServer` available from `@cloudflare/codemode/mcp` for wrapping existing MCP servers / OpenAPI specs. The package was rewritten on 2026-02-20 around a runtime-agnostic `Executor` interface; `experimental_codemode()` and `CodeModeProxy` are gone. Latest is `0.3.8`, still labeled "Experimental — may have breaking changes" in Cloudflare's own Code Mode docs.
3. **TypeScript inside the sandbox**: Worker Loader (`env.LOADER`) accepts JavaScript (and Python via flag), not TypeScript. To meet the hard TS requirement, transpile/bundle in the host using `@cloudflare/worker-bundler`'s `createWorker({ files })`, which runs `esbuild-wasm` inside workerd and "handles TypeScript compilation, dependency resolution from npm, and bundling" (Cloudflare Dynamic Workers getting-started docs). That package is still **closed beta** (per its npm README — "Bundle and serve full-stack applications on Cloudflare's Worker Loader binding (closed beta)") and only runs inside workerd — not under plain Node — so tests that exercise it must use `@cloudflare/vitest-pool-workers`.
4. **ServiceNow MCP Server Console is more capable than the prior draft assumed.** Per the ServiceNow Community article *What's New in MCP Server Console: From Skills to Full Platform*: "What's new in v1.4: Knowledge Graph, Subflows, Scripted REST APIs, and AI Agent support." Scripted REST APIs are exposed for GET/POST/PUT only (DELETE/PATCH not eligible); Table API is *explicitly excluded* from being auto-converted to MCP tools. So the differentiator for this project is NOT "ServiceNow cannot expose REST"; it is **Code Mode-native + sandboxed + developer-controlled + open-source + dynamic code execution + Table/Aggregate/Attachment/Import-Set access that MCP Server Console deliberately omits**.
5. **Sandboxing**: per the Cloudflare Dynamic Workers Egress Control docs, setting `globalOutbound: null` "causes any fetch() or connect() request from the dynamic Worker to throw an exception. … This is the cleanest and most secure way to design your sandbox: block the Internet, then constructively offer specific capabilities via bindings." If `globalOutbound` is omitted, the child inherits the parent's network. Use `load()` (one-shot) for Code Mode runs; reserve `get(id, cb)` for warm-isolate patterns we don't need here.
6. **ServiceNow Scripted REST security**: Scripted REST resources are protected by a "REST_Endpoint" ACL bound to a role. The default `Scripted REST External Default` ACL uses the broad `snc_internal` role; we replace it with a custom role. Inside Scripted REST scripts, `GlideRecord` bypasses ACLs server-side; `GlideRecordSecure` honors them. We use a **scoped application** (`x_mcp`) that ships a custom role (`x_mcp.executor`) plus a REST_Endpoint ACL requiring that role on the executor resource — and use plain `GlideRecord` inside the executor to achieve "maximum reach," with the role + ACL + audit table as the real boundary.
7. **OAuth on ServiceNow**: Inbound OAuth 2.0 is supported via Application Registry on `oauth_token.do`. Per the Azure Databricks ServiceNow ingestion setup docs (citing ServiceNow platform behavior): "ServiceNow requires multi-factor authentication (MFA) by default for U2M OAuth. When you sign in, provide your second authentication method as part of the standard MFA flow. This requirement does not apply to ROPC authentication." ROPC is therefore not MFA-gated but exposes user passwords to the client and is being deprecated industry-wide. We recommend Authorization Code + PKCE for hosted multi-user; ROPC only as a disposable-PDI dev convenience.
8. **PDIs are dev/demo only.** Per the ServiceNow Developer Site Personal Developer Instance (PDI) Guide (Xanadu release): "PDIs are returned to the pool of available instances if they go unused for ten days. Duration may change due to availability. Availability is not guaranteed." Hibernation kicks in after ~6 hours of inactivity (~30 minutes if you wake without logging in). Reclamation is based on Developer Portal activity, not hibernation pings; per the ServiceNow blog *Hibernation and Developer Instances*: "creating records or changing data does not reset your activity time for your 10 day timeout."

---

## Details

### 1. Architecture (validated, with the contradiction resolved)

```
┌──────────────────────┐      Streamable HTTP / stdio (MCP 2025-11-25)
│   Claude Code / MCP  │ ─────────────────────────────────────────────┐
│   Inspector / client │                                              │
└──────────────────────┘                                              ▼
                                                  ┌────────────────────────────────────┐
                                                  │  Host Worker (Cloudflare)          │
                                                  │  - createMcpHandler (stateless)    │
                                                  │  - Tools: run_code, describe_table │
                                                  │           list_tables              │
                                                  │  - OAuth provider (Auth Code+PKCE) │
                                                  │  - Workers KV: schema cache (24h)  │
                                                  │  - Durable Object SQLite: tokens   │
                                                  │  - WorkerLoader binding (LOADER)   │
                                                  │  - ServiceNowRPC (typed binding)   │
                                                  └─────────────┬──────────────────────┘
                                                                │   RPC (Workers RPC / Cap'n Web)
                                                                ▼
                                                  ┌─────────────────────────────┐
                                                  │  Dynamic Worker (per call)  │
                                                  │  - bundled JS from TS       │
                                                  │  - globalOutbound: null     │
                                                  │  - sees codemode.* only     │
                                                  │  - no creds, no fetch()     │
                                                  └─────────────┬───────────────┘
                                                                │ RPC: typed methods
                                                                ▼
                                                  ┌─────────────────────────────┐
                                                  │  Host-side ServiceNowClient │
                                                  │  - OAuth header injected    │
                                                  │  - Table/Aggregate/...      │
                                                  │  - x_mcp executor (scoped)  │
                                                  └─────────────────────────────┘
```

**Stateless default (`createMcpHandler`)** vs **stateful (`McpAgent` / DO + WorkerTransport)**:

- v1 default — `createMcpHandler` (stateless Worker, no Durable Object). Per Cloudflare's createMcpHandler API reference: "Many MCP Servers are stateless, meaning they do not maintain any session state between requests. The createMcpHandler function is a lightweight alternative to the McpAgent class…"
- v1.5 stateful — `createMcpHandler` *inside* an `Agent` with `WorkerTransport`, only if you need per-user OAuth token persistence, elicitation, or sampling. Same Cloudflare doc: "If your MCP server needs to maintain state across requests, use createMcpHandler with a WorkerTransport inside an Agent class."

Important MCP-SDK gotcha: SDK 1.26+ throws if `McpServer` / transport instances are connected twice (CVE fix for cross-client response leakage). Always **construct fresh `McpServer` and transport per request** when running stateless.

**MCP transport & spec.** Target spec revision `2025-11-25` (modelcontextprotocol.io/specification/2025-11-25/basic/transports). Streamable HTTP is the current stable remote transport; SSE was deprecated in `2025-03-26`. For local dev, expose stdio (`StdioServerTransport`) from the same tool definitions.

### 2. TypeScript transpile-then-load pipeline (hard requirement)

LLM-generated TypeScript is never given to `env.LOADER` raw. The host bundles it inside workerd via `@cloudflare/worker-bundler` and passes the resulting JS module map to Worker Loader.

```ts
// src/sandbox/transpile.ts
import { createWorker } from "@cloudflare/worker-bundler";

export async function buildSandboxModules(userTs: string) {
  const wrapperTs = `
    import * as user from "./user.ts";
    export default {
      async evaluate(rpc) {
        const codemode = rpc;
        return await user.default(codemode);
      }
    };
  `;
  const { mainModule, modules, wranglerConfig } = await createWorker({
    files: {
      "src/entry.ts": wrapperTs,
      "src/user.ts": userTs,
      "wrangler.toml": `
        main = "src/entry.ts"
        compatibility_date = "2026-05-27"
        compatibility_flags = ["nodejs_compat"]
      `,
    },
  });
  return { mainModule, modules, compatibilityDate: wranglerConfig?.compatibilityDate ?? "2026-05-27" };
}
```

Because `@cloudflare/worker-bundler` (v0.1.3, closed beta) bundles via `esbuild-wasm` inside workerd, **the host Worker must enable `compatibility_flags = ["nodejs_compat"]`** in its own `wrangler.toml`, and unit tests must use `@cloudflare/vitest-pool-workers` (per the npm README: "It will not work under plain Node.js. In particular, importing it from a Vitest/Jest test that uses the default Node pool will surface an error pointing you here.").

The official `DynamicWorkerExecutor` does *not* transpile TypeScript itself — it accepts a JS string (after `normalizeCode`/AST parsing via acorn). Two options:

- **Option A (recommended v1)**: Keep `createCodeTool` + `DynamicWorkerExecutor` as the run_code core, but pre-bundle the user code with `@cloudflare/worker-bundler` *before* calling `executor.execute(...)`. Keeps the SDK's RPC dispatcher, Proxy, type generation, log capture, and timeout.
- **Option B**: Skip `createCodeTool` and call `env.LOADER.load(...)` directly with the bundler output. Use only if you want to expose typed `ServiceNowRPC` methods directly inside the sandbox instead of as `codemode.servicenow.*`. Do not ship as default.

### 3. The `run_code` tool, built on the official SDK

```ts
import { createMcpHandler } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { createCodeTool } from "@cloudflare/codemode/ai";
import { DynamicWorkerExecutor } from "@cloudflare/codemode";
import { ServiceNowRPC } from "./sn/rpc";
import { buildSandboxModules } from "./sandbox/transpile";

const MAX_CODE_BYTES = 64 * 1024;
const EXEC_TIMEOUT_MS = 30_000;
const MAX_OUTPUT_BYTES = 256 * 1024;

export default {
  fetch(req: Request, env: Env, ctx: ExecutionContext) {
    const server = new McpServer({ name: "servicenow-codemode", version: "0.1.0" });
    registerDiscoveryTools(server, env);
    const sn = new ServiceNowRPC(env, ctx);
    const executor = new DynamicWorkerExecutor({
      loader: env.LOADER, globalOutbound: null, timeout: EXEC_TIMEOUT_MS,
    });
    const codemode = createCodeTool({ tools: sn.toolset(), executor });

    server.tool("run_code", { code: z.string().max(MAX_CODE_BYTES) }, async ({ code }) => {
      const { modules } = await buildSandboxModules(code);
      const jsEntry = modules["src/entry.js"] ?? modules["src/entry.ts"];
      const result = await executor.execute(jsEntry as string, sn.fns(), { timeout: EXEC_TIMEOUT_MS });
      return {
        content: [{ type: "text", text: serialize(result, MAX_OUTPUT_BYTES) }],
        isError: !!result.error,
      };
    });

    return createMcpHandler(server, { route: "/mcp" })(req, env, ctx);
  },
};
```

`serialize(result, cap)` truncates large arrays/strings to `{ truncated: true, total: N, sample: first-K }`, captures `result.logs`, and maps thrown errors to MCP `isError: true` with a typed `code` field.

### 4. Narrow, typed ServiceNow RPC binding (credentials never enter the sandbox)

The dynamic Worker must never receive an OAuth token. The host exposes a `ServiceNowRPC` RpcTarget whose methods are the only ServiceNow capabilities the sandbox can call. The OAuth header is injected on the way out.

```ts
export class ServiceNowRPC extends RpcTarget {
  constructor(private env: Env, private ctx: ExecutionContext) { super(); }
  async listTables(prefix?: string)   { /* sys_db_object via cache */ }
  async describeTable(name: string)   { /* sys_dictionary via cache */ }
  async tableQuery(args: TableQueryArgs): Promise<Page<Row>> { /* keyset paginated */ }
  async tableGet(table: string, sysId: string, fields?: string[]) {}
  async tableCreate(table: string, body: Record<string, unknown>) {}
  async tableUpdate(table: string, sysId: string, patch: Record<string, unknown>) {}
  async tableDelete(table: string, sysId: string) {}
  async aggregate(args: AggregateArgs)  { /* /api/now/stats */ }
  async attachmentGet(sysId: string)    {}
  async importSet(staging: string, rows: object[]) { /* /api/now/import */ }
  async cmdbGet(className: string, sysId: string) {}
  async knowledgeSearch(q: string, kbSysId?: string) {}
  async catalogAddToCart(itemSysId: string, vars: object) {}
  async catalogSubmitOrder() {}
  async scriptedRest(path: string, method: "GET"|"POST"|"PUT"|"DELETE", body?: unknown) {}
  async runServerScript(script: string, opts?: { timeoutMs?: number }) { /* x_mcp executor */ }
  toolset(): Record<string, AiTool> {}
  fns(): Record<string, Function>   {}
}
```

Inside the sandbox, the LLM-written TS sees only `codemode.servicenow.tableQuery({...})` — no `env`, no fetch, no token. Per Cloudflare's Code Mode docs: "Sandboxed code can only interact with the host through codemode.* tool calls."

### 5. `describe_table`, `list_tables`, schema cache

- Tables: read from `sys_db_object` via Table API, then column metadata from `sys_dictionary`. The integration role must have explicit read ACLs (or be elevated via the role matrix). Required base reads: `sys_db_object`, `sys_dictionary`, `sys_glide_object`; cache 24 h in Workers KV with **role-aware cache keys** (`schema:v1:{instance}:{role-hash}:{table}`) because column visibility differs per role under ACLs.
- Provide `schema_invalidate(table?)` as a host-only admin command (HTTP route, not an MCP tool). Bump a `schemaVersion` system property to invalidate everything.
- **Never** cache record data, query results, or attachment contents.
- Tokens live in **Durable Object SQLite**, encrypted at rest (see §7), partitioned by `(user_id, instance_url)`.

### 6. The hardened, role-governed server-side executor (preserves maximum reach)

The arbitrary-server-side-script capability is preserved as a first-class tool but lives in a **scoped application** with its own custom role and a REST_Endpoint ACL. The prior draft's plan to `eval` under the admin account is replaced by this design.

**Scoped app `x_mcp` ships:**

| Artifact | Purpose |
|---|---|
| Role `x_mcp.executor` | The only role allowed to hit the executor endpoint. |
| Scripted REST API resource `x_mcp/executor/run` (POST) | The sole entrypoint for arbitrary scripts. |
| ACL of type `REST_Endpoint` on that resource | Replaces `Scripted REST External Default`; requires `x_mcp.executor`. |
| Audit table `x_mcp_audit_log` | Every request: who, when, instance, code SHA-256, byte length, duration, status, output size, error class. **No script body, no raw output.** |
| System property `x_mcp.executor.enabled` (bool) | The kill switch. 503 when false. |
| System property `x_mcp.executor.max_bytes` (int) | Enforced before evaluation. |
| System property `x_mcp.executor.timeout_ms` (int) | Hard ceiling, default 15000. |
| System property `x_mcp.executor.allow_unsafe` (bool) | Controls whether `GlideRecord` (ACL-bypassing) is exposed vs. `GlideRecordSecure` only. Default true. |

```javascript
// x_mcp.executor.run (Scripted REST resource, scoped app, role-gated)
(function process(req, res) {
  if (gs.getProperty('x_mcp.executor.enabled', 'true') !== 'true') {
    res.setStatus(503); res.setBody({ error: 'executor_disabled' }); return;
  }
  var code = String((req.body.data || {}).script || '');
  var maxB = parseInt(gs.getProperty('x_mcp.executor.max_bytes', '32768'), 10);
  if (code.length === 0 || code.length > maxB) {
    res.setStatus(413); res.setBody({ error: 'code_size' }); return;
  }
  var hash = new GlideDigest().getSHA256Base64(code);
  var start = new GlideDateTime();
  var audit = new GlideRecord('x_mcp_audit_log');
  audit.initialize();
  audit.user = gs.getUserID(); audit.user_name = gs.getUserName();
  audit.code_hash = hash; audit.code_size = code.length;
  audit.started_at = start; audit.status = 'running';
  audit.insert();

  var result, err = null, status = 'ok';
  try {
    var fn = new Function('gs','GlideRecord','GlideRecordSecure','GlideAggregate',
      'return (async () => { ' + code + ' })()');
    result = fn(gs, GlideRecord, GlideRecordSecure, GlideAggregate);
  } catch (e) { err = String(e); status = 'error'; }

  var serialized = JSON.stringify(result === undefined ? null : result);
  if (serialized && serialized.length > 64*1024) {
    serialized = serialized.slice(0, 64*1024);
    status = status === 'ok' ? 'truncated' : status;
  }
  audit.status = status;
  audit.duration = (new GlideDateTime()).getNumericValue() - start.getNumericValue();
  audit.output_size = serialized ? serialized.length : 0;
  audit.error_class = err ? err.split(':')[0] : '';
  audit.update();
  // Do NOT call gs.info / gs.log with the script body or output.
  res.setStatus(err ? 500 : 200);
  res.setBody({ ok: !err, result: err ? null : JSON.parse(serialized || 'null'),
                truncated: status === 'truncated', error: err, audit_id: audit.sys_id + '' });
})(request, response);
```

**Notes vs. the prior draft.** The default `Scripted REST External Default` ACL uses `snc_internal`, which is broad; we replace it with a custom REST_Endpoint ACL bound to `x_mcp.executor`. Scoped apps cannot create ACLs in the global scope, but a REST_Endpoint ACL on a scoped Scripted REST resource lives in the scoped app and ships in the update set. `GlideRecord` inside a scoped app eval bypasses ACLs server-side — that's the "maximum reach"; the boundary is now the **role + REST_Endpoint ACL + audit log + kill switch**. The **sys_trigger-row-creation fallback** is labeled *unsupported/experimental*; do not ship it.

### 7. Threat model

| # | Threat | Impact | Mitigation |
|---|---|---|---|
| T1 | Stolen Cloudflare account / API token | Read encrypted DO storage / re-deploy worker | Tokens encrypted (AES-GCM, key in Cloudflare secret); Cloudflare Access + IP allow-list on deploy path; rotate keys. |
| T2 | Stolen ServiceNow OAuth refresh token | Full reach to the user's surface in SN | Partition tokens by `(user, instance)`; short access-token lifetimes; rotate refresh tokens; revoke on logout; alert on refreshes from new IPs. |
| T3 | LLM prompt-injection exfiltrates data | Sandboxed code calls `fetch("evil")` | `globalOutbound: null` makes `fetch()`/`connect()` throw; verified by S1. No creds in dynamic Worker `env`; only typed RPC. |
| T4 | LLM-written code mutates records | Unintended writes | Capability is intentional; mitigation is *attributive*: every RPC method records `(user, instance, table, sys_id, op, before-hash, after-hash, request-id)`; SHA-256 of executor scripts; `sys_audit` for row-level rollback; optional `dry_run`. |
| T5 | Sensitive output bleeds into Cloudflare logs / Tail | PII in observability stream | Denylist body fields (`u_ssn`, `secret`, `password`, `auth`); never `console.log` script body or full RPC response; Tail Worker hashes results; audit table stores hashes. |
| T6 | Over-broad role on integration user | Defeats role matrix | Use §8 matrix; never reuse human admin; one-click rotate-executor-role runbook. |
| T7 | Schema cache leaks fields across users | Cross-role disclosure of metadata | Cache key includes `(instance, role-hash)`; short TTL during rollout; explicit invalidation command. |
| T8 | Replay of old MCP request | Duplicated side effects | Per-request `Idempotency-Key` from client; DO stores recent keys with TTL; reject duplicates. |
| T9 | PDI hibernation / reclamation mid-flight | Hangs, half-applied changes | PDIs as dev/demo only; `/health` probe; MCP returns typed `instance_hibernating` rather than hanging. |
| T10 | Dynamic Worker pricing change | Cost explosion when beta charge unfreezes | One-shot `load()` per call; monthly cap with hard breaker; quarterly pricing review. |
| T11 | MCP SDK 1.26 cross-client response leak (CVE) | One client sees another's responses | Construct `McpServer`/transport per request (never globally), per SDK guard. |
| T12 | MCP Inspector exposed publicly | Anyone can invoke run_code | Inspector is dev-only; production `/mcp` requires OAuth bearer. |

### 8. Role matrix — maximum access via explicit, attributable roles

The goal is *maximum reach with attribution*, not least-privilege-at-all-costs. Reach stays high; what changes is the reach travels via a named identity with an inspectable role footprint, not a shared `admin` login.

| Identity / Role | Where | What it grants | Why |
|---|---|---|---|
| `mcp_integration_user` (system user) | ServiceNow `sys_user` | Roles: `rest_api_explorer`, `itil`, `sn_customerservice_agent`, `import_transformer`, `snc_platform_rest_api_access`, read-ACLs on `sys_db_object`/`sys_dictionary`/`sys_glide_object`. | Primary integration identity. High aggregate access via well-known roles, not literal admin. Revocable. |
| `x_mcp.executor` (custom role, scoped app) | ServiceNow scoped app | Required for the executor REST_Endpoint ACL. Only the executor consumes it. | Decouples "can run arbitrary script" from "can hit Table API." Revoke this one role to kill executor reach without touching other integration capabilities. |
| `x_mcp.admin` (custom role) | ServiceNow scoped app | Manages `x_mcp_audit_log`, kill-switch property, role assignments. | Separation of duty: executor identity cannot turn its own audit log off. |
| Cloudflare deploy identity | Cloudflare Account | wrangler / Alchemy IaC permissions | Per-engineer scoped tokens; rotate. |
| MCP client OAuth identity (per end user) | Cloudflare DO SQLite | Maps end-user → ServiceNow refresh token. | Per-user attribution propagates into `x_mcp_audit_log.user`. |

If the customer wants "even higher" reach (e.g., write to system tables in global scope), grant `admin` to `mcp_integration_user` explicitly and document the change — the matrix accommodates that, it just makes the elevation visible and reversible.

### 9. ServiceNow client hardening

```ts
const TABLE_NAME = /^[a-z][a-z0-9_]{0,79}$/;
const MAX_LIMIT  = 1000;

export class ServiceNowClient {
  constructor(private baseUrl: string, private auth: AuthProvider) {
    new URL(baseUrl);
    if (!/^https:\/\/[a-z0-9-]+\.service-now\.com\/?$/.test(baseUrl))
      throw new Error("bad_instance_url");
  }
  async tableQuery(args: { table: string; query?: string; fields?: string[];
                           limit?: number; cursor?: string; displayValue?: "true"|"false"|"all" }) {
    if (!TABLE_NAME.test(args.table)) throw new Error("bad_table_name");
    const limit = Math.min(args.limit ?? 100, MAX_LIMIT);
    const params = new URLSearchParams({
      sysparm_limit: String(limit),
      sysparm_exclude_reference_link: "true",
      sysparm_display_value: args.displayValue ?? "false",
    });
    if (args.fields?.length) params.set("sysparm_fields", args.fields.join(","));
    const q = [args.query, args.cursor ? `sys_id>${args.cursor}` : null, "ORDERBYsys_id"]
      .filter(Boolean).join("^");
    if (q) params.set("sysparm_query", q);
    const url = `${this.baseUrl}/api/now/table/${args.table}?${params}`;
    const res = await this.fetchWithRetry(url); // 429/5xx backoff with jitter
    const json = await res.json();
    const rows = json.result as any[];
    const next = rows.length === limit ? rows[rows.length - 1].sys_id : null;
    return { rows, nextCursor: next, truncated: !!next };
  }
}
```

**Pagination warning.** Keyset on `sys_id` beats `sysparm_offset` (which forces re-scans on large tables) but has edge cases that **must** be in the test plan: duplicates at boundary, missing rows from inserts mid-pagination, updates mid-pagination not isolated, ordering ties (safe with unique `sys_id`).

**Per-API prerequisites matrix.**

| API | Path | Roles / plugins | Gotchas |
|---|---|---|---|
| Table API | `/api/now/table/{table}` | Read/write ACLs on the table; `snc_platform_rest_api_access` if strict REST security on. | Default cap 1000; `display_value` triples response size; use `sysparm_exclude_reference_link=true`. |
| Aggregate API | `/api/now/stats/{table}` | Read access; `sysparm_count`, `sysparm_group_by`, `sysparm_avg_fields`. | Server-side aggregations, cheaper than client-side counting. |
| Attachment API | `/api/now/attachment` | Read ACL on the parent record; 1024 MB upload cap default. | Stream; do not buffer in Worker memory. |
| Import Set API | `/api/now/import/{staging}` (and `/insertMultiple`) | `import_transformer` (or explicit write ACL); `snc_platform_rest_api_access`. | Staging extends `sys_import_set_row`; user-created fields are `u_*` unless scoped. |
| CMDB Instance API | `/api/now/cmdb/instance/{class}/{sys_id}` | `itil` typical; **one record per call**. | Class hierarchy under `cmdb_ci`; relationships are separate calls. |
| Knowledge Mgmt API | `/api/sn_km_api/knowledge/articles` | KB user-criteria + read ACL on `kb_knowledge`; some content needs `itil`. | Honors KB ACLs strictly; counts differ between admin and integration user. |
| Service Catalog API | `/api/sn_sc/servicecatalog/*` | Catalog roles for variables; three calls (add_to_cart → checkout → submit_order), or `order_now` in one. | `requested_for` is the calling user unless impersonated; references need `sys_id`. |
| Scripted REST | `/api/{scope}/{api}/{resource}` | Whatever the resource's REST_Endpoint ACL requires; for `x_mcp.executor.run`, `x_mcp.executor`. | Default ACL is `snc_internal` — override it. `GlideRecord` bypasses ACLs server-side. |

### 10. OAuth + token handling

- **Inbound OAuth 2.0**: *System OAuth → Application Registry → Create an OAuth API endpoint for external clients*. Token endpoint: `https://{instance}.service-now.com/oauth_token.do`.
- **Flow:** Authorization Code + PKCE (`code_challenge_method=S256`). ServiceNow supports PKCE per the Now Support KB *How to setup PKCE for oAuth2.0 - Authorization Grant type* (KB1645540).
- **MFA:** Per the Azure Databricks ServiceNow ingestion docs: "ServiceNow requires multi-factor authentication (MFA) by default for U2M OAuth. … This requirement does not apply to ROPC authentication." Let the browser handle MFA on the PKCE path.
- **ROPC**: disposable-PDI dev only — handles user passwords directly and skips MFA. Not allowed in production.
- **Token storage:** Durable Object SQLite, one row per `(user_id, instance_url)`. Ciphertext via AES-GCM; DEK in `env.TOKEN_KEK` (Cloudflare secret); rotate quarterly. On refresh: rotate the refresh token, update DO, audit `token.refreshed`. On revoke: delete row + `POST oauth_revoke_token.do`. Scrub `bearer`/`access_token`/`refresh_token` from all logs.

### 11. Corrected ServiceNow MCP positioning

ServiceNow MCP Server Console is real and capable. The ServiceNow Community v1.4 announcement is explicit: "What's new in v1.4: Knowledge Graph, Subflows, Scripted REST APIs, and AI Agent support." Scripted REST exposure is GET/POST/PUT only (DELETE/PATCH not eligible); Table APIs are deliberately excluded; AI Agents are exposable via Scripted REST.

**What this project differentiates on:**

1. **Code Mode native.** One `run_code` + two discovery helpers, ~1k tokens of tool surface vs. one tool per Skill/Subflow/REST endpoint.
2. **Dynamic-code execution against a typed RPC.** The LLM writes TypeScript; we transpile, sandbox, and run it. MCP Server Console does not run arbitrary developer-supplied code.
3. **Full Table / Aggregate / Attachment / Import-Set / CMDB Instance access** — none of which Server Console exposes.
4. **Open-source, self-hosted, version-pinnable.** No Now Assist licensing dependency.
5. **Cloudflare-edge deployment.** Different latency/geo/quota profile.

Where Server Console wins: governed Now Assist Skills, Knowledge Graph traversal with ACL-aware relationship walks, native AI Agents exposure. Complementary, not exclusive.

### 12. PDI guidance (softened)

PDIs are *learning/experimentation* instances. Per the ServiceNow Developer Site PDI Guide (Xanadu): "PDIs are returned to the pool of available instances if they go unused for ten days. Duration may change due to availability. Availability is not guaranteed." Hibernation: ~6h inactive, ~30 min if you wake-and-leave. Reclamation is based on Developer Portal activity (script changes, configuration changes, update-set activity), not hibernation pings; per the *Hibernation and Developer Instances* blog: "creating records or changing data does not reset your activity time for your 10 day timeout."

Implications:

- Do **not** point staging or any pre-prod at a PDI.
- Any keepalive is best-effort and subject to Developer Program policy; do not ship cron-style ping loops. A `/health` MCP tool returning `{ instance: "hibernating" | "online" }` is fine.
- PDIs cannot be clone targets/sources for customer instances; many Store apps cannot install; ML/IDR/MetricBase unavailable.
- Backups exist with an unspecified retention window (announced in the ServiceNow blog *Backup and Restore your Personal Developer Instance*).

### 13. Versioning / dependency strategy

| Dependency | Min | Tested (2026-05-30) | Why | Upgrade risk | Pin rule |
|---|---|---|---|---|---|
| `@cloudflare/codemode` | 0.3.0 | **0.3.8** | `createCodeTool`, `DynamicWorkerExecutor`, `codeMcpServer`, `openApiMcpServer` | Pre-1.0, "Experimental" | EXACT |
| `@cloudflare/worker-bundler` | 0.1.0 | **0.1.3** (closed beta) | TS transpile + npm resolution inside workerd | Closed beta | EXACT |
| `agents` (CF Agents SDK) | 0.12.0 | **0.13.3** | `createMcpHandler`, `WorkerTransport`, `Agent` | Pre-1.0 | EXACT |
| `@modelcontextprotocol/sdk` | 1.26.0 (CVE fix) | **1.29.0** | `McpServer`, transports, schema | v2 forecast Q1 2026 (third-party) | `^1.29.0` |
| `wrangler` | 4.0.0 | **4.95.0** | Dev runtime | Major releases occasional | `^4.95.0` |
| `hono` | 4.0.0 | **4.12.23** | Routing inside host Worker | Stable | `^4.12.23` |
| `@hono/node-server` | 2.0.0 | **2.0.4** | Optional Node stdio dev shim | Stable | `^2.0.4` |
| `zod` | 4.0.0 | **4.4.3** | Required by codemode/Agents as `^4.0.0` | Zod 3 unsupported | `^4.4.3` |
| `esbuild` | 0.25.0 | **0.28.0** | Local TS build (host) | Stable | `^0.28.0` |
| `alchemy` (v1) | 0.71.0 (WorkerLoader binding) | **0.87.0** | IaC | v2 is separate beta (`[email protected]`) | EXACT to `0.87.0` |
| `@modelcontextprotocol/inspector` | 0.21.0 | **0.21.2** | Dev/test MCP client | Dev-only | `^0.21.2` |

**Pre-1.0 rule:** pin EXACT for `@cloudflare/codemode`, `@cloudflare/worker-bundler`, `agents`, `alchemy`. Commit `package-lock.json`; `npm ci` in CI.

### 14. Monorepo layout

```
servicenow-codemode-mcp/
├─ packages/
│  ├─ mcp-server/
│  │  ├─ src/{index,tools,sandbox,sn,observability}.ts
│  │  └─ wrangler.toml
│  ├─ sn-executor-app/             # scoped app update set
│  │  ├─ tables/x_mcp_audit_log.xml
│  │  ├─ roles/{x_mcp.executor,x_mcp.admin}.xml
│  │  ├─ scripted_rest/x_mcp.executor.run.js
│  │  └─ properties/x_mcp.executor.*.xml
│  └─ shared/types.ts
├─ infra/alchemy.run.ts
├─ tests/{unit,integration}/
└─ docs/{threat-model,role-matrix,runbooks}/
```

### 15. Build sequence / milestones

1. **M0 — Skeleton (1d).** Bare `createMcpHandler` Worker; `hello` tool; deploy via Alchemy; MCP Inspector connects locally and remotely.
2. **M1 — ServiceNow Client (3d).** `ServiceNowClient` + OAuth Auth Code + PKCE; tokens in DO SQLite; `describe_table`/`list_tables` E2E against a PDI.
3. **M2 — Schema cache (1d).** KV 24h TTL, role-aware keys, `schema_invalidate` admin route.
4. **M3 — ServiceNowRPC binding (3d).** Typed methods for Table/Aggregate/Attachment/Import-Set/CMDB/Knowledge/Catalog/Scripted-REST; keyset pagination; retry policy.
5. **M4 — `run_code` (3d).** `@cloudflare/worker-bundler` TS pipeline + `createCodeTool` + `DynamicWorkerExecutor` with `globalOutbound: null`. Output serialization, timeout, code-size cap.
6. **M5 — Scoped executor app (3d).** `x_mcp` update set: role, REST_Endpoint ACL, Scripted REST resource, audit table, properties, kill switch.
7. **M6 — Threat-model tests (3d).** §16.
8. **M7 — Production hardening (3d).** Token encryption, log scrubbing, idempotency keys, Tail Worker, `/health`.
9. **M8 — Stateful variant (optional).** `McpAgent`/WorkerTransport for per-user OAuth/elicitation.

### 16. Full Test Plan

Automated under Vitest + `@cloudflare/vitest-pool-workers`, with a real PDI in CI for ServiceNow tests.

**S1 — Sandbox cannot reach external network when `globalOutbound: null`.** `run_code` is given `await fetch("https://example.com")` and `await connect({hostname:"example.com",port:443})`. Both throw; MCP response is `isError: true` with the runtime error in `DynamicWorkerExecutor`'s log capture. CI fails if either returns a body. Also call `codemode.servicenow.tableQuery({table:"sys_user",limit:1})` to confirm the binding still works.

**S2 — Sandbox cannot read OAuth tokens or any credentials.** Host sets `env.CANARY = "do-not-leak"` plus real `env.TOKEN_KEK`. Sandbox enumerates its own `env`/globals (`JSON.stringify(Object.keys(env ?? {}))`, `globalThis`, `import.meta.env`). Sandbox sees only the typed RPC binding — no `CANARY`, no `TOKEN_KEK`. Fails if canary appears anywhere.

**S3 — TypeScript input transpiles/bundles successfully, or fails clearly.** Three inputs: (a) valid TS with `interface`/`async`/`await`, (b) TS importing `zod`, (c) intentionally broken TS (`const x: number = "string"`). (a) returns computed value; (b) returns valid zod-validated execution; (c) returns `isError:true` with parse/type error including file+line, no stack into host code. Host never crashes.

**S4 — `run_code` enforces all guardrails.** (a) code > `MAX_CODE_BYTES` → 413-style error pre-transpile; (b) infinite loop → timeout after `EXEC_TIMEOUT_MS`, shape preserved; (c) 5MB array return → `{ truncated:true, total:N }` envelope, body ≤ `MAX_OUTPUT_BYTES`; (d) thrown → `isError:true` with thrown message; (e) `console.log/warn/error` all captured into `result.logs`.

**S5 — Table API wrapper handles real-world failures.** Against a PDI: 10k-row pagination, ACL-restricted table, nonexistent table, invalid field, synthetic 429, synthetic 500. Pagination yields all rows; correctly signals `truncated:true` at last page; ACL error → `{code:"acl_denied"}`; nonexistent → `{code:"table_not_found"}`; invalid field → `{code:"field_not_found"}`; 429/500 → backoff + retry then structured surface; all errors carry `requestId`.

**S6 — Schema cache invalidates correctly and does not leak fields across users.** Two users: A has ACL access to `incident.u_secret_field`, B does not. A's `describe_table("incident")` includes the field; B's does not. Cache keys differ. After `schema_invalidate("incident")`, next request re-fetches from ServiceNow (counter on `sys_dictionary` reads). Bumping `schemaVersion` invalidates all keys.

**S7 — OAuth refresh works; revoked/expired tokens fail safely.** (a) Access-token expiry mid-session → auto-refresh, audit entry, request continues. (b) Revoke refresh token via `oauth_revoke_token.do` → `{code:"reauth_required"}`, DO row cleared. (c) Corrupt ciphertext in DO → `{code:"reauth_required"}`, no panic. (d) Clock skew host by 10 min → refresh still works (use `expires_in`, not absolute clocks).

**S8 — Scoped-app executor requires `x_mcp.executor` and logs every request.** Three identities — one with `x_mcp.executor`, one with `admin` but not `x_mcp.executor`, one with neither. Each submits `return gs.getUserName();`. Only the first succeeds; others get HTTP 403 from the REST_Endpoint ACL. Successful call produces an `x_mcp_audit_log` row with `user`, `code_hash`, `code_size`, `duration`, `status="ok"`, `output_size`, no script body or output text. MCP response carries `audit_id`.

**S9 — Kill switch disables the executor instantly.** Set `x_mcp.executor.enabled = false`. Submit a script. HTTP 503 with `{error:"executor_disabled"}` within one request cycle (no cached "yes"). Audit row recorded with `status="killed"`. Setting property back to `true` resumes normal behavior on the next call (no Worker redeploy).

**S10 — End-to-end via MCP Inspector.** Launch `npx @modelcontextprotocol/inspector`, connect to local `http://localhost:8788/mcp` over Streamable HTTP, then to deployed remote endpoint with OAuth. Inspector lists `run_code`, `describe_table`, `list_tables`. `list_tables` returns a paginated list. `describe_table("incident")` returns a schema document. `run_code` with the safe example below executes and returns five short_descriptions:

```ts
export default async (codemode) => {
  const page = await codemode.servicenow.tableQuery({
    table: "incident", fields: ["number","short_description"], limit: 5
  });
  return page.rows.map(r => r.short_description);
};
```

All three flows pass against a freshly-deployed instance with no manual configuration outside the documented runbook.

---

## Recommendations

1. **Start with the stateless `createMcpHandler` shape** and a single PDI. Build M0–M4 against that. Do not adopt `McpAgent`/DO until you actually need per-user OAuth in production — M8, not M1.
2. **Treat `@cloudflare/codemode` and `@cloudflare/worker-bundler` as moving targets.** Pin exact versions, subscribe to the Cloudflare changelog feed, and budget for breaking changes every 4–8 weeks until they hit 1.0 and "closed beta" respectively. The `0.1.x` / `0.3.x` line is not a stable contract.
3. **Ship the scoped app `x_mcp` as the very first ServiceNow artifact**, even before the Worker is feature-complete. Customers who can't accept a scoped-app install will not be able to use the executor at all; find that out on day one.
4. **Make the kill switch a documented runbook step**, not just a feature. SRE needs to know `x_mcp.executor.enabled` flips the executor off without redeploys.
5. **Re-verify pricing and beta status quarterly.** Build a usage report emitting unique-Workers-per-day to logs so a price flip can be costed before it lands. Per the Cloudflare Dynamic Workers Pricing page, the daily charge is "not yet active … Pricing information is shared in advance so you can estimate future costs."
6. **GA threshold:** all 10 §16 tests green for 14 consecutive days; `@cloudflare/codemode` ≥ 1.0 *or* exemption signed; `@cloudflare/worker-bundler` out of closed beta *or* the same; tested against at least one non-PDI instance.
7. **Stateful-variant threshold:** more than one human end-user per deployment, OR elicitation/sampling needed, OR per-user audit attribution at the OAuth layer that `gs.getUserID()` alone can't satisfy.
8. **Never document the `sys_trigger` fallback as a path.** Point customers at the scoped-app executor and the role matrix.

---

## Caveats

- **Forward-looking claims to retest.** The MCP TypeScript SDK v2 "expected Q1 2026" timeline is a third-party forecast, not an MCP-team commitment; treat v1.29 as the production target until v2 is on `latest`. The MCP Server Console v1.4 capabilities (Scripted REST, Knowledge Graph, Subflows, AI Agents) come from the ServiceNow Community article cited above and the Zurich-line documentation; re-confirm against `servicenow.com/docs/r/release-notes/mcp-server-console-rn.html` at integration time.
- **Closed-vs-open beta wording.** `@cloudflare/worker-bundler`'s own npm README says "closed beta"; Dynamic Workers is "open beta." These are different beta statuses on related products. Don't assume one implies the other.
- **Bundler is workerd-only.** `@cloudflare/worker-bundler` does not run under plain Node. CI must use `@cloudflare/vitest-pool-workers`.
- **`GlideRecord` in scoped apps bypasses ACLs server-side.** Documented intentional behavior; the basis for the executor's "maximum reach." If a customer wants the executor itself to honor ACLs, flip `x_mcp.executor.allow_unsafe=false` and the resource uses `GlideRecordSecure` — but then "maximum reach" stops being literally maximum and is bounded by the integration user's ACL footprint.
- **PDI uptime/persistence/performance is not guaranteed.** Anything that *depends* on a PDI being available is fragile by definition. Build the project so a hibernated PDI surfaces as a clean MCP error, not a hung tool call.
- **Pricing.** Dynamic Workers' included tier is 1,000 unique Dynamic Workers per month, with overage at +$0.002 per Dynamic Worker per day, currently not yet billed per the Cloudflare Dynamic Workers Pricing page. Once active, our default "one-shot `load()` per `run_code` invocation" means cost scales linearly with `run_code` calls. Build a budget alert before billing activates.
- **Cursor pagination edge cases** (duplicates on `sys_id` ties, mid-pagination inserts, deletes) must be exercised in S5 every release; do not silently switch to `sysparm_offset` without a parity test.
- **Documentation snapshots cited here are as of May 30, 2026.** URLs, version numbers, blog dates, and feature names should be re-fetched before a customer-facing publication.