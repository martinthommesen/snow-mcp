import { env } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildHandlers, type HandlerEnv } from "../src/tools/handlers.js";
import { TokenStore } from "../src/auth/token-store.js";
import { buildKekRing } from "../src/auth/crypto.js";

// ─── §6b — host-attested reauth_required (+authorizeUrl) on ALL THREE tools ─────
// In per_user_oauth with NO stored token, every tool must surface reauth_required carrying the
// authorizeUrl ticket detail — run_code via the pre-sandbox preflight (before any billable
// Worker), describe_table/list_tables via getServiceNowBearer through their catch→toToolResult
// path (which carries `detail` since P2). Crucially, the per_user path NEVER mints via ROPC.

interface TestEnv {
  LOADER: WorkerLoader;
  TOKEN_DO: DurableObjectNamespace;
  BUDGET_DO: DurableObjectNamespace;
  LEDGER_DO: DurableObjectNamespace;
  AUDIT_KV: KVNamespace;
}
const E = env as unknown as TestEnv;

// Note on the "never ROPC" guarantee: a per_user_oauth no-token boot reauths inside
// getServiceNowBearer BEFORE any fetch (getAuthorization throws before SnFetchClient calls the
// network), so no SN request / ROPC ever fires. The precise call-counted proof of "zero network
// calls" lives in servicenow-oauth.test.ts (§6b missing-token unit test, mock fetch); here we
// assert the END-TO-END surfacing: each tool returns reauth_required + the authorizeUrl detail.

function perUserEnv(): HandlerEnv {
  return {
    LOADER: E.LOADER,
    TOKEN_DO: E.TOKEN_DO,
    BUDGET_DO: E.BUDGET_DO,
    SNOW_INSTANCE_HOST: "dev999.service-now.com",
    SNOW_OAUTH_CLIENT_ID: "cid",
    SNOW_OAUTH_CLIENT_SECRET: "csec",
    TOKEN_KEK_CURRENT: "kek-passphrase",
    OAUTH_PROVIDER_SECRET: "host-secret",
    SERVICENOW_CREDENTIAL_MODE: "per_user_oauth",
  };
}

const auth = {
  userId: "reauthUser",
  scopeMaxMode: "admin_script" as const,
  props: { userId: "reauthUser", scopes: ["servicenow:read"], maxMode: "admin_script" },
  workerOrigin: "https://mcp.example.workers.dev",
};

afterEach(() => vi.unstubAllGlobals());

describe("§6b reauth_required surfaces on all three tools (per_user_oauth, no token)", () => {
  it("run_code → reauth_required with authorizeUrl, before any Worker/network (preflight)", async () => {
    const handlers = buildHandlers(perUserEnv(), auth);
    const res = await handlers.runCode({ code: "async () => 1" });
    expect(res.isError).toBe(true);
    expect((res.structuredContent as { code: string }).code).toBe("reauth_required");
    const detail = (res.structuredContent as { detail?: { authorizeUrl?: string } }).detail;
    expect(detail?.authorizeUrl).toContain("/servicenow/authorize?ticket=");
  });

  it("run_code fails closed when per_user_oauth lacks a configured public worker origin", async () => {
    const handlers = buildHandlers(perUserEnv(), { ...auth, workerOrigin: undefined });
    const res = await handlers.runCode({ code: "async () => 1" });
    expect(res.isError).toBe(true);
    expect((res.structuredContent as { code: string }).code).toBe("reauth_required");
    expect(res.content[0]!.text).toContain("WORKER_PUBLIC_ORIGIN");
    expect((res.structuredContent as { detail?: { authorizeUrl?: string } }).detail?.authorizeUrl).toBeUndefined();
  });

  it("describe_table → reauth_required with authorizeUrl (catch → toToolResult carries detail)", async () => {
    const handlers = buildHandlers(perUserEnv(), auth);
    const res = await handlers.describeTable({ table: "incident" });
    expect(res.isError).toBe(true);
    expect((res.structuredContent as { code: string }).code).toBe("reauth_required");
    expect((res.structuredContent as { detail?: { authorizeUrl?: string } }).detail?.authorizeUrl).toContain("/servicenow/authorize?ticket=");
  });

  it("list_tables → reauth_required with authorizeUrl", async () => {
    const handlers = buildHandlers(perUserEnv(), auth);
    const res = await handlers.listTables({});
    expect(res.isError).toBe(true);
    expect((res.structuredContent as { code: string }).code).toBe("reauth_required");
    expect((res.structuredContent as { detail?: { authorizeUrl?: string } }).detail?.authorizeUrl).toContain("/servicenow/authorize?ticket=");
  });

  it("explicit per_user_oauth with incomplete OAuth wiring fails closed and never falls back to Basic dev creds", async () => {
    let networkCalls = 0;
    vi.stubGlobal("fetch", (async () => {
      networkCalls++;
      return new Response(JSON.stringify({ result: [{ name: "incident", label: "Incident" }] }), {
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch);

    const handlers = buildHandlers(
      {
        LOADER: E.LOADER,
        BUDGET_DO: E.BUDGET_DO,
        SNOW_INSTANCE_HOST: "dev999.service-now.com",
        SNOW_DEV_ROPC_USERNAME: "dev-user",
        SNOW_DEV_ROPC_PASSWORD: "dev-pass",
        SERVICENOW_CREDENTIAL_MODE: "per_user_oauth",
      },
      auth,
    );
    const res = await handlers.listTables({});
    expect(res.isError).toBe(true);
    expect((res.structuredContent as { code: string }).code).toBe("reauth_required");
    expect(res.content[0]!.text).toContain("per_user_oauth");
    expect(networkCalls).toBe(0);
  });

  it("an invalid SERVICENOW_CREDENTIAL_MODE fails closed at runtime instead of selecting Basic auth", async () => {
    let networkCalls = 0;
    vi.stubGlobal("fetch", (async () => {
      networkCalls++;
      return new Response(JSON.stringify({ result: [{ name: "incident", label: "Incident" }] }), {
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch);

    const handlers = buildHandlers(
      {
        LOADER: E.LOADER,
        BUDGET_DO: E.BUDGET_DO,
        SNOW_INSTANCE_HOST: "dev999.service-now.com",
        SNOW_DEV_ROPC_USERNAME: "dev-user",
        SNOW_DEV_ROPC_PASSWORD: "dev-pass",
        SERVICENOW_CREDENTIAL_MODE: "per-user" as "per_user_oauth",
      },
      auth,
    );
    const res = await handlers.listTables({});
    expect(res.isError).toBe(true);
    expect((res.structuredContent as { code: string }).code).toBe("reauth_required");
    expect(res.content[0]!.text).toContain("SERVICENOW_CREDENTIAL_MODE");
    expect(networkCalls).toBe(0);
  });

  it("dev Basic auth stays disabled when SNOW_DEV_ROPC is absent even if credentials are present", async () => {
    let networkCalls = 0;
    vi.stubGlobal("fetch", (async () => {
      networkCalls++;
      return new Response(JSON.stringify({ result: [{ name: "incident", label: "Incident" }] }), {
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch);

    const handlers = buildHandlers(
      {
        LOADER: E.LOADER,
        BUDGET_DO: E.BUDGET_DO,
        SNOW_INSTANCE_HOST: "dev999.service-now.com",
        SNOW_DEV_ROPC_USERNAME: "dev-user",
        SNOW_DEV_ROPC_PASSWORD: "dev-pass",
      },
      auth,
    );
    const res = await handlers.listTables({});
    expect(res.isError).toBe(true);
    expect((res.structuredContent as { code: string }).code).toBe("reauth_required");
    expect(networkCalls).toBe(0);
  });

  it("dev Basic auth stays disabled when SNOW_DEV_ROPC is not exactly 1", async () => {
    let networkCalls = 0;
    vi.stubGlobal("fetch", (async () => {
      networkCalls++;
      return new Response(JSON.stringify({ result: [{ name: "incident", label: "Incident" }] }), {
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch);

    const handlers = buildHandlers(
      {
        LOADER: E.LOADER,
        BUDGET_DO: E.BUDGET_DO,
        SNOW_INSTANCE_HOST: "dev999.service-now.com",
        SNOW_DEV_ROPC: "0",
        SNOW_DEV_ROPC_USERNAME: "dev-user",
        SNOW_DEV_ROPC_PASSWORD: "dev-pass",
      },
      auth,
    );
    const res = await handlers.listTables({});
    expect(res.isError).toBe(true);
    expect((res.structuredContent as { code: string }).code).toBe("reauth_required");
    expect(networkCalls).toBe(0);
  });

  it("dev Basic auth is enabled only when SNOW_DEV_ROPC=1", async () => {
    const calls: { authorization?: string }[] = [];
    vi.stubGlobal("fetch", (async (_url: string, init?: RequestInit) => {
      calls.push({ authorization: (init?.headers as Record<string, string> | undefined)?.authorization });
      return new Response(JSON.stringify({ result: [{ name: "incident", label: "Incident" }] }), {
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch);

    const handlers = buildHandlers(
      {
        LOADER: E.LOADER,
        BUDGET_DO: E.BUDGET_DO,
        SNOW_INSTANCE_HOST: "dev999.service-now.com",
        SNOW_DEV_ROPC: "1",
        SNOW_DEV_ROPC_USERNAME: "dev-user",
        SNOW_DEV_ROPC_PASSWORD: "dev-pass",
      },
      auth,
    );
    const res = await handlers.listTables({});
    expect(res.isError).not.toBe(true);
    expect(calls[0]?.authorization).toBe(`Basic ${btoa("dev-user:dev-pass")}`);
  });

  it("OAuth ROPC credentials are ignored unless SNOW_DEV_ROPC=1", async () => {
    let networkCalls = 0;
    vi.stubGlobal("fetch", (async () => {
      networkCalls++;
      return new Response(JSON.stringify({ access_token: "SHOULD_NOT_MINT", expires_in: 1800 }), {
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch);

    const handlers = buildHandlers(
      {
        LOADER: E.LOADER,
        TOKEN_DO: E.TOKEN_DO,
        BUDGET_DO: E.BUDGET_DO,
        SNOW_INSTANCE_HOST: "dev999.service-now.com",
        SNOW_OAUTH_CLIENT_ID: "cid",
        SNOW_OAUTH_CLIENT_SECRET: "csec",
        TOKEN_KEK_CURRENT: "kek-passphrase",
        SNOW_DEV_ROPC_USERNAME: "dev-user",
        SNOW_DEV_ROPC_PASSWORD: "dev-pass",
      },
      auth,
    );
    const res = await handlers.listTables({});
    expect(res.isError).toBe(true);
    expect((res.structuredContent as { code: string }).code).toBe("reauth_required");
    expect(networkCalls).toBe(0);
  });

  it("reuses one decrypted bearer across multiple ServiceNow requests for the same handler", async () => {
    const HOST = "dev999.service-now.com";
    const USER = "bearerCacheUser";
    const ring = await buildKekRing("kek-passphrase");
    let rawToken: string | undefined;
    let tokenReads = 0;
    const backend = {
      async putToken(_tokenType: string, opaque: string): Promise<void> {
        rawToken = opaque;
      },
      async getToken(_tokenType: string): Promise<string | undefined> {
        tokenReads++;
        return rawToken;
      },
    };
    await new TokenStore(backend, ring, USER, HOST).put("servicenow", {
      access_token: "AT_CACHE",
      refresh_token: "RT_CACHE",
      expires_at: Date.now() + 3_600_000,
    });
    tokenReads = 0;

    const tokenDo = {
      idFromName: (name: string) => name,
      get: () => backend,
    } as unknown as DurableObjectNamespace;
    const authorizations: string[] = [];
    vi.stubGlobal("fetch", (async (_url: string, init?: RequestInit) => {
      authorizations.push((init?.headers as Record<string, string> | undefined)?.authorization ?? "");
      return new Response(JSON.stringify({ result: [{ name: "incident", label: "Incident" }] }), {
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch);

    const handlers = buildHandlers(
      {
        LOADER: E.LOADER,
        TOKEN_DO: tokenDo,
        SNOW_INSTANCE_HOST: HOST,
        SNOW_OAUTH_CLIENT_ID: "cid",
        SNOW_OAUTH_CLIENT_SECRET: "csec",
        TOKEN_KEK_CURRENT: "kek-passphrase",
        SERVICENOW_CREDENTIAL_MODE: "per_user_oauth",
      },
      {
        userId: USER,
        scopeMaxMode: "read_only",
        props: { userId: USER, scopes: ["servicenow:read"], maxMode: "read_only" },
        workerOrigin: "https://mcp.example.workers.dev",
      },
    );

    expect((await handlers.listTables({})).isError).not.toBe(true);
    expect((await handlers.listTables({ filter: "inc" })).isError).not.toBe(true);
    expect(authorizations).toEqual(["Bearer AT_CACHE", "Bearer AT_CACHE"]);
    expect(tokenReads).toBe(1);
  });
});

// ─── §6b-1 FIX 3 — live resolve-and-persist of the per-user principal (integrity glue) ──
// The §6b mutation-wiring tests stub signing.resolveEffectiveUserSysId() directly; this drives
// the REAL resolver buildHandlers wires (resolveEffectiveSysId → resolveSnPrincipal) end-to-end
// through run_code → runServerScript → the signed executor POST. It exercises the exact upstream
// boundary that the unit mocks bypass: the host's global fetch hits /current_user + the role
// table (and the executor POST). SnFetchClient + resolveSnPrincipal both late-bind global fetch
// at call time, so one URL-routed stubGlobal covers all three. Pre-store a token WITH access_token
// but WITHOUT sys_id; assert the signed actor carries the resolved sys_id, the principal is
// persisted, and the concurrent-safe re-read-merge (FIX 2) leaves access_token intact.
describe("§6b-1 buildHandlers resolves + persists the per-user principal at sign time", () => {
  const RESOLVE_HOST = "dev999.service-now.com"; // canonical form of SNOW_INSTANCE_HOST below
  const RESOLVE_USER = "resolveUser";

  function resolveEnv(): HandlerEnv {
    return {
      LOADER: E.LOADER,
      TOKEN_DO: E.TOKEN_DO,
      BUDGET_DO: E.BUDGET_DO,
      LEDGER_DO: E.LEDGER_DO,
      AUDIT_KV: E.AUDIT_KV,
      SNOW_INSTANCE_HOST: RESOLVE_HOST,
      SNOW_OAUTH_CLIENT_ID: "cid",
      SNOW_OAUTH_CLIENT_SECRET: "csec",
      TOKEN_KEK_CURRENT: "kek-passphrase",
      OAUTH_PROVIDER_SECRET: "host-secret",
      SERVICENOW_CREDENTIAL_MODE: "per_user_oauth",
      // Executor signing wiring so runServerScript reaches signing.resolveEffectiveUserSysId().
      X_MCP_EXECUTOR_HMAC_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(7))),
      SNOW_EXECUTOR_PATH: "/api/x_1793136_mcp/x_mcp/executor/run",
      ADMIN_SCRIPT_ALLOWLIST: RESOLVE_USER,
      ADMIN_SCRIPT_REQUIRED_GROUP: "mcp-admins",
      MCP_OPERATOR_ACCESS_GROUPS: "mcp-admins",
    };
  }
  const resolveAuth = {
    userId: RESOLVE_USER,
    scopeMaxMode: "admin_script" as const,
    props: { userId: RESOLVE_USER, scopes: ["servicenow:admin_script"], maxMode: "admin_script" },
    workerOrigin: "https://mcp.example.workers.dev",
  };

  // A store over the SAME (user|instance) DO + KEK ring buildHandlers uses, so a token we
  // pre-store here is decryptable inside getServiceNowBearer / resolveEffectiveSysId.
  async function resolveStore(): Promise<TokenStore> {
    const ring = await buildKekRing("kek-passphrase");
    const stub = E.TOKEN_DO.get(E.TOKEN_DO.idFromName(`${RESOLVE_USER}|${RESOLVE_HOST}`)) as unknown as ConstructorParameters<typeof TokenStore>[0];
    return new TokenStore(stub, ring, RESOLVE_USER, RESOLVE_HOST);
  }

  it("binds the resolved sys_id into the signed actor AND persists the principal without clobbering access_token", async () => {
    const s = await resolveStore();
    // Pre-store: a valid (unexpired) token WITH access_token but WITHOUT sys_id/roles.
    await s.put("servicenow", { access_token: "AT_LIVE", refresh_token: "RT_LIVE", expires_at: Date.now() + 3_600_000 });

    let postBody: unknown;
    const fetchImpl = (async (url: string, init?: RequestInit) => {
      // "who am I": the bearer's identity (NOT a sys_user table-order row).
      if (url.includes("/api/now/ui/user/current_user")) {
        return new Response(JSON.stringify({ result: { user_sys_id: "BEARER_SYS", user_name: "bob" } }), { headers: { "content-type": "application/json" } });
      }
      if (url.includes("/api/now/table/sys_user_has_role")) {
        return new Response(JSON.stringify({ result: [{ "role.name": "itil" }, { "role.name": "catalog_admin" }] }), { headers: { "content-type": "application/json" } });
      }
      // The signed executor POST — capture its body and ack.
      if (url.includes("/api/x_1793136_mcp/x_mcp/executor/run")) {
        postBody = JSON.parse(String(init?.body));
        return new Response(JSON.stringify({ result: { ok: true } }), { headers: { "content-type": "application/json" } });
      }
      return new Response("{}", { headers: { "content-type": "application/json" } });
    }) as unknown as typeof fetch;
    vi.stubGlobal("fetch", fetchImpl);

    const handlers = buildHandlers(resolveEnv(), resolveAuth);
    const res = await handlers.runCode({
      code: `async () => { await servicenow.runServerScript({ script: "gs.info('x')" }); return "done"; }`,
      mode: "admin_script",
      reason: "rotate",
      idempotencyKey: "k1",
    });
    expect(res.isError).toBe(false);

    // 1) The signed actor carries the LIVE-resolved sys_id (not the base "").
    const actor = (postBody as { actor: { snow_effective_user_sys_id: string } }).actor;
    expect(actor.snow_effective_user_sys_id).toBe("BEARER_SYS");

    // 2) The principal was persisted onto the stored token (sys_id + roles).
    const after = await s.get("servicenow");
    expect(after?.sys_id).toBe("BEARER_SYS");
    expect(after?.roles).toEqual(["itil", "catalog_admin"]);
    expect(after?.principal_resolved_at).toEqual(expect.any(Number));
    // 3) Invariant: the resolve-and-persist writes back a COMPLETE token (the re-read-merge
    //    target of FIX 2), never a sys_id-only partial — the existing access_token/refresh_token
    //    survive. (This asserts the merge invariant, not FIX 2's mid-flight race-safety, which is
    //    verified by construction: re-read `latest` then merge sys_id/roles onto it.)
    expect(after?.access_token).toBe("AT_LIVE");
    expect(after?.refresh_token).toBe("RT_LIVE");
  });
});
