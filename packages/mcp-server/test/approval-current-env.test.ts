import { env } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildHandlers, type HandlerEnv } from "../src/tools/handlers.js";

interface TestEnv {
  LOADER: WorkerLoader;
  LEDGER_DO: DurableObjectNamespace;
  AUDIT_KV: KVNamespace;
}
const E = env as unknown as TestEnv;

function executorEnv(overrides: Partial<HandlerEnv> = {}): HandlerEnv {
  return {
    LOADER: E.LOADER,
    LEDGER_DO: E.LEDGER_DO,
    AUDIT_KV: E.AUDIT_KV,
    SNOW_INSTANCE_HOST: "dev999.service-now.com",
    SERVICENOW_CREDENTIAL_MODE: "integration_user",
    SNOW_DEV_ROPC: "1",
    SNOW_DEV_ROPC_USERNAME: "dev-user",
    SNOW_DEV_ROPC_PASSWORD: "dev-pass",
    X_MCP_EXECUTOR_HMAC_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(7))),
    SNOW_EXECUTOR_PATH: "/api/x_1793136_mcp/x_mcp/executor/run",
    ACTOR_POLICY_MAX_MODE: "admin_script",
    ADMIN_SCRIPT_ALLOWLIST: "operator",
    ADMIN_SCRIPT_REQUIRED_GROUP: "mcp-admins",
    ...overrides,
  };
}

describe("admin_script group approval uses current env config", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("rejects an executor HMAC key that is not a 32-byte base64 secret", () => {
    expect(() =>
      buildHandlers(executorEnv({ X_MCP_EXECUTOR_HMAC_KEY: btoa("short") }), {
        userId: "operator",
        scopeMaxMode: "admin_script",
        props: { userId: "operator", scopes: ["servicenow:admin_script"], maxMode: "admin_script" },
      }),
    ).toThrow(/X_MCP_EXECUTOR_HMAC_KEY.*32 bytes/);
  });

  it("does not honor stale accessGroups copied from an existing OAuth grant", async () => {
    let executorPosts = 0;
    vi.stubGlobal("fetch", (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.includes("/api/x_1793136_mcp/x_mcp/executor/run")) executorPosts++;
      return new Response(JSON.stringify({ result: { ok: true } }), { headers: { "content-type": "application/json" } });
    }) as unknown as typeof fetch);

    const handlers = buildHandlers(executorEnv(), {
      userId: "operator",
      scopeMaxMode: "admin_script",
      props: {
        userId: "operator",
        scopes: ["servicenow:admin_script"],
        maxMode: "admin_script",
        accessGroups: ["mcp-admins"],
      },
    });
    const res = await handlers.runCode({
      code: `async () => { await servicenow.runServerScript({ script: "gs.info('x')" }); return "done"; }`,
      mode: "admin_script",
      reason: "rotate",
      idempotencyKey: "k1",
    });

    expect(res.isError).toBe(true);
    expect(res.content[0]!.text).toContain("second approval");
    expect(executorPosts).toBe(0);
  });

  it("does not honor static operator groups for an OIDC actor", async () => {
    let executorPosts = 0;
    vi.stubGlobal("fetch", (async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.includes("/api/x_1793136_mcp/x_mcp/executor/run")) executorPosts++;
      return new Response(JSON.stringify({ result: { ok: true } }), { headers: { "content-type": "application/json" } });
    }) as unknown as typeof fetch);

    const handlers = buildHandlers(executorEnv({ MCP_OPERATOR_ACCESS_GROUPS: "mcp-admins" }), {
      userId: "operator",
      scopeMaxMode: "admin_script",
      props: {
        userId: "operator",
        authMode: "oidc",
        scopes: ["servicenow:admin_script"],
        maxMode: "admin_script",
        oidcGroups: [],
      },
    });
    const res = await handlers.runCode({
      code: `async () => { await servicenow.runServerScript({ script: "gs.info('x')" }); return "done"; }`,
      mode: "admin_script",
      reason: "rotate",
      idempotencyKey: "k-oidc-static",
    });

    expect(res.isError).toBe(true);
    expect(res.content[0]!.text).toContain("second approval");
    expect(executorPosts).toBe(0);
  });

  it("uses OIDC grant groups for the admin_script second-approval group branch", async () => {
    let executorPosts = 0;
    vi.stubGlobal("fetch", (async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.includes("/api/x_1793136_mcp/x_mcp/executor/run")) executorPosts++;
      return new Response(JSON.stringify({ result: { ok: true } }), { headers: { "content-type": "application/json" } });
    }) as unknown as typeof fetch);

    const handlers = buildHandlers(executorEnv({ SNOW_DEV_ROPC: "1" }), {
      userId: "operator",
      scopeMaxMode: "admin_script",
      props: {
        userId: "operator",
        authMode: "oidc",
        scopes: ["servicenow:admin_script"],
        maxMode: "admin_script",
        oidcGroups: ["mcp-admins"],
      },
    });
    const res = await handlers.runCode({
      code: `async () => { await servicenow.runServerScript({ script: "gs.info('x')" }); return "done"; }`,
      mode: "admin_script",
      reason: "rotate",
      idempotencyKey: "k-oidc-groups",
    });

    expect(res.isError).toBe(false);
    expect(executorPosts).toBe(1);
  });

  it("warns when auth props request an unknown ActorPolicy name", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      buildHandlers(executorEnv(), {
        userId: "operator",
        scopeMaxMode: "read_only",
        props: { userId: "operator", scopes: ["servicenow:read"], maxMode: "read_only", actorPolicyName: "missing" },
      });
      expect(warn).toHaveBeenCalledWith(expect.stringContaining('"event":"actor_policy_missing"'));
      expect(warn).toHaveBeenCalledWith(expect.stringContaining('"requestedPolicyName":"missing"'));
    } finally {
      warn.mockRestore();
    }
  });
});
