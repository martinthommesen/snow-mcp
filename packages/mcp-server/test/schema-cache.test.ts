import { env } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SchemaCache, roleHash, type SchemaCacheIdentity } from "../src/cache/schema.js";
import type { FieldInfo, ListTablesResult, TableInfo } from "../src/sn/discovery.js";
import { buildHandlers, resolveSchemaIdentity, type HandlerEnv } from "../src/tools/handlers.js";
import { TokenStore } from "../src/auth/token-store.js";
import { buildKekRing } from "../src/auth/crypto.js";

// ─── §2.6 / S6 — user-aware schema cache ──────────────────────────────────────
interface TestEnv {
  LOADER: WorkerLoader;
  SCHEMA_KV: KVNamespace;
  TOKEN_DO: DurableObjectNamespace<import("../src/do/token-store.js").TokenStoreDO>;
}
const KV = (env as unknown as TestEnv).SCHEMA_KV;
const TOKEN_DO = (env as unknown as TestEnv).TOKEN_DO;
const LOADER = (env as unknown as TestEnv).LOADER;

const idA: SchemaCacheIdentity = { instanceHost: "inst1", principalId: "userA", roleHash: "r1" };
const idB: SchemaCacheIdentity = { instanceHost: "inst1", principalId: "userB", roleHash: "r1" };

const fieldsWith = (names: string[]): FieldInfo[] => names.map((n) => ({ name: n, label: n, type: "string", mandatory: false }));
const tableListWith = (names: string[], extra: Partial<Omit<ListTablesResult, "tables">> = {}): ListTablesResult => ({
  tables: names.map((n) => ({ name: n, label: n })),
  partial: false,
  ...extra,
});

describe("§2.6 SchemaCache", () => {
  it("caches per table and serves a hit on the second call (no re-fetch)", async () => {
    const cache = new SchemaCache(KV, idA);
    let fetches = 0;
    const fetcher = async () => { fetches++; return fieldsWith(["number", "caller_id"]); };
    const first = await cache.describeTable("incident", fetcher);
    const second = await cache.describeTable("incident", fetcher);
    expect(first.cached).toBe(false);
    expect(second.cached).toBe(true);
    expect(fetches).toBe(1);
    expect(second.fields.map((f) => f.name)).toEqual(["number", "caller_id"]);
  });

  it("coalesces concurrent cold describeTable misses for the same identity/key", async () => {
    const cache = new SchemaCache(KV, { ...idA, instanceHost: `inst-coalesce-${crypto.randomUUID()}` });
    let fetches = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const fetcher = async () => {
      fetches++;
      await gate;
      return fieldsWith(["number"]);
    };
    const first = cache.describeTable("incident", fetcher);
    const second = cache.describeTable("incident", fetcher);
    release();
    const results = await Promise.all([first, second]);
    expect(fetches).toBe(1);
    expect(results.map((r) => r.fields.map((f) => f.name))).toEqual([["number"], ["number"]]);
  });

  it("S6 — does NOT leak one user's fields to another (user-aware key)", async () => {
    // User A (broad) sees caller_id; user B (same role, failing a field ACL) must not.
    const cacheA = new SchemaCache(KV, { ...idA, instanceHost: "inst2" });
    const cacheB = new SchemaCache(KV, { ...idB, instanceHost: "inst2" });
    await cacheA.describeTable("incident", async () => fieldsWith(["number", "caller_id"]));
    const bResult = await cacheB.describeTable("incident", async () => fieldsWith(["number"])); // B's own fetch
    expect(bResult.cached).toBe(false); // B did not hit A's entry
    expect(bResult.fields.some((f) => f.name === "caller_id")).toBe(false);
  });

  it("roleHash is order-independent and busts on role change", async () => {
    expect(await roleHash(["itil", "admin"])).toBe(await roleHash(["admin", "itil"]));
    expect(await roleHash(["itil"])).not.toBe(await roleHash(["itil", "admin"]));
  });

  // ─── P6b — listTables cache-key collision: '*' filter must NOT alias the no-filter case ──
  // Pre-P6b the key used `filter ?? "*"`, so listTables(undefined) and listTables("*") collided.
  it("a literal '*' filter does NOT collide with the no-filter case (distinct keys)", async () => {
    const cache = new SchemaCache(KV, { ...idA, instanceHost: "inst-collision" });
    const none = await cache.listTables(undefined, async () => tableListWith(["all_tables"], { partial: true, total: 50 }));
    const star = await cache.listTables("*", async () => tableListWith(["star_filtered"]));
    expect(none.cached).toBe(false);
    expect(star.cached).toBe(false); // distinct key ⇒ NOT served from the no-filter entry
    expect(star.tables.map((t) => t.name)).toEqual(["star_filtered"]);
    expect(none.partial).toBe(true);
    expect(none.total).toBe(50);
    // And each is independently cached on a second call.
    const noneHit = await cache.listTables(undefined, async () => tableListWith(["x"]));
    expect(noneHit.cached).toBe(true);
    expect(noneHit.partial).toBe(true);
    expect(noneHit.total).toBe(50);
    expect((await cache.listTables("*", async () => tableListWith(["x"]))).cached).toBe(true);
  });

  it("coalesces concurrent cold listTables misses for the same identity/filter", async () => {
    const cache = new SchemaCache(KV, { ...idA, instanceHost: `inst-list-coalesce-${crypto.randomUUID()}` });
    let fetches = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const fetcher = async () => {
      fetches++;
      await gate;
      return { tables: [{ name: "incident", label: "Incident" }] as TableInfo[], partial: true };
    };
    const first = cache.listTables("inc", fetcher);
    const second = cache.listTables("inc", fetcher);
    release();
    const results = await Promise.all([first, second]);
    expect(fetches).toBe(1);
    expect(results.map((r) => r.tables.map((t) => t.name))).toEqual([["incident"], ["incident"]]);
    expect(results.map((r) => r.partial)).toEqual([true, true]);
  });
});

// ─── P6b — resolveSchemaIdentity wiring (apiHandler → SchemaCache identity) ─────
describe("§6b resolveSchemaIdentity wiring", () => {
  afterEach(() => vi.unstubAllGlobals());

  const SECRET = "test-token-kek-passphrase-0123456789";
  const HOST = "inst-rolehash.service-now.com";
  const baseEnv: Partial<HandlerEnv> = {
    SERVICENOW_CREDENTIAL_MODE: "per_user_oauth",
    SNOW_OAUTH_CLIENT_ID: "cid",
    SNOW_OAUTH_CLIENT_SECRET: "csecret",
    SNOW_INSTANCE_HOST: HOST,
    TOKEN_KEK_CURRENT: SECRET,
    // TOKEN_DO is typed <TokenStoreDO> for seedToken's TokenStore stub, but HandlerEnv.TOKEN_DO is
    // the unbranded DurableObjectNamespace (<undefined>); bridge at this one assignment site (same
    // `as unknown as` pattern handlers.ts uses for its DO stubs) so the test project typechecks.
    TOKEN_DO: TOKEN_DO as unknown as DurableObjectNamespace,
  };

  async function seedToken(
    userId: string,
    token: { sys_id?: string; roles?: string[]; principal_resolved_at?: number },
  ): Promise<void> {
    const ring = await buildKekRing(SECRET);
    // The DO stub IS the TokenStoreBackend (putToken/getToken), same as token-store.test.
    const stub = TOKEN_DO.get(TOKEN_DO.idFromName(`${userId}|${HOST}`));
    const store = new TokenStore(stub, ring, userId, HOST);
    await store.put("servicenow", {
      access_token: "a",
      ...token,
      ...(token.sys_id && token.principal_resolved_at === undefined ? { principal_resolved_at: Date.now() } : {}),
    });
  }

  it("returns the MCP actor identity in integration_user mode (no extra decrypt; live deployment untouched)", async () => {
    const out = await resolveSchemaIdentity({ ...baseEnv, SERVICENOW_CREDENTIAL_MODE: "integration_user" } as HandlerEnv, "u-int");
    expect(out).toEqual({ principalId: "u-int", roleHash: "default" });
  });

  it("disables cache when per_user_oauth is not fully configured", async () => {
    const out = await resolveSchemaIdentity({ SERVICENOW_CREDENTIAL_MODE: "per_user_oauth" } as HandlerEnv, "u-unconfigured");
    expect(out).toBeUndefined();
  });

  it("disables cache when no token or no ServiceNow sys_id is stored", async () => {
    const out = await resolveSchemaIdentity(baseEnv as HandlerEnv, "u-no-token");
    expect(out).toBeUndefined();
    vi.stubGlobal("fetch", (async (url: string) => {
      if (url.includes("/api/now/ui/user/current_user")) {
        return new Response(JSON.stringify({ result: {} }), { headers: { "content-type": "application/json" } });
      }
      return new Response("{}", { headers: { "content-type": "application/json" } });
    }) as unknown as typeof fetch);
    await seedToken("u-no-sys-id", { roles: ["itil"] });
    expect(await resolveSchemaIdentity(baseEnv as HandlerEnv, "u-no-sys-id")).toBeUndefined();
  });

  it("keys per_user_oauth by ServiceNow sys_id and roleHash", async () => {
    await seedToken("u-roles", { sys_id: "SN-A", roles: ["itil", "admin"] });
    const firstIdentity = await resolveSchemaIdentity(baseEnv as HandlerEnv, "u-roles");
    expect(firstIdentity).toEqual({ principalId: "SN-A", roleHash: await roleHash(["itil", "admin"]) });

    // A role change ⇒ a DIFFERENT roleHash ⇒ a DIFFERENT SchemaCache key (cache busted).
    await seedToken("u-roles", { sys_id: "SN-A", roles: ["itil"] });
    const roleChangedIdentity = await resolveSchemaIdentity(baseEnv as HandlerEnv, "u-roles");
    expect(roleChangedIdentity).toEqual({ principalId: "SN-A", roleHash: await roleHash(["itil"]) });
    expect(roleChangedIdentity?.roleHash).not.toBe(firstIdentity?.roleHash);

    const before = new SchemaCache(KV, { instanceHost: HOST, ...firstIdentity! });
    const after = new SchemaCache(KV, { instanceHost: HOST, ...roleChangedIdentity! });
    let fetches = 0;
    const fetcher = async () => { fetches++; return [{ name: "number", label: "Number", type: "string", mandatory: false }] as FieldInfo[]; };
    await before.describeTable("incident", fetcher);
    const afterResult = await after.describeTable("incident", fetcher);
    expect(afterResult.cached).toBe(false); // role changed ⇒ cache miss
    expect(fetches).toBe(2);

    // Same MCP actor, same roles, different ServiceNow sys_id ⇒ also a cache miss.
    await seedToken("u-roles", { sys_id: "SN-B", roles: ["itil"] });
    const principalChangedIdentity = await resolveSchemaIdentity(baseEnv as HandlerEnv, "u-roles");
    expect(principalChangedIdentity).toEqual(roleChangedIdentity ? { ...roleChangedIdentity, principalId: "SN-B" } : undefined);
    const principalChanged = new SchemaCache(KV, { instanceHost: HOST, ...principalChangedIdentity! });
    const principalChangedResult = await principalChanged.describeTable("incident", fetcher);
    expect(principalChangedResult.cached).toBe(false);
    expect(fetches).toBe(3);
  });

  it("refreshes a stale stored ServiceNow principal before keying schema cache", async () => {
    await seedToken("u-stale-principal", {
      sys_id: "SN-OLD",
      roles: ["old_role"],
      principal_resolved_at: Date.now() - 10 * 60 * 1000,
    });
    vi.stubGlobal("fetch", (async (url: string, init?: RequestInit) => {
      expect((init?.headers as Record<string, string>).authorization).toBe("Bearer a");
      if (url.includes("/api/now/ui/user/current_user")) {
        return new Response(JSON.stringify({ result: { user_sys_id: "SN-NEW" } }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (url.includes("/api/now/table/sys_user_has_role")) {
        return new Response(JSON.stringify({ result: [{ "role.name": "new_role" }] }), {
          headers: { "content-type": "application/json" },
        });
      }
      return new Response("{}", { headers: { "content-type": "application/json" } });
    }) as unknown as typeof fetch);

    const identity = await resolveSchemaIdentity(baseEnv as HandlerEnv, "u-stale-principal");
    expect(identity).toEqual({ principalId: "SN-NEW", roleHash: await roleHash(["new_role"]) });
  });

  it("resolves schema identity lazily only when a schema tool needs SchemaCache", async () => {
    const host = `inst-${crypto.randomUUID()}.service-now.com`;
    let identityCalls = 0;
    let fetches = 0;
    vi.stubGlobal("fetch", (async () => {
      fetches++;
      return new Response(JSON.stringify({ result: [{ name: "incident", label: "Incident" }] }), {
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch);

    const handlers = buildHandlers(
      {
        LOADER,
        SCHEMA_KV: KV,
        SNOW_INSTANCE_HOST: host,
        SNOW_DEV_ROPC: "1",
        SNOW_DEV_ROPC_USERNAME: "dev-user",
        SNOW_DEV_ROPC_PASSWORD: "dev-pass",
      } as HandlerEnv,
      {
        userId: "lazy-role-user",
        scopeMaxMode: "read_only",
        props: { userId: "lazy-role-user", scopes: ["servicenow:read"], maxMode: "read_only" },
        schemaIdentityResolver: async () => {
          identityCalls++;
          return { principalId: "lazy-principal", roleHash: "lazy-role" };
        },
      },
    );

    const run = await handlers.runCode({ code: "async () => 1", mode: "read_only" });
    expect(run.isError).not.toBe(true);
    expect(identityCalls).toBe(0);

    expect((await handlers.listTables({})).isError).not.toBe(true);
    expect(identityCalls).toBe(1);
    expect(fetches).toBe(1);

    expect((await handlers.listTables({})).structuredContent).toMatchObject({ cached: true });
    expect(identityCalls).toBe(1);
    expect(fetches).toBe(1);
  });

  it("threads list_tables partial/total through uncached and cached handler results", async () => {
    const host = `inst-list-meta-${crypto.randomUUID()}.service-now.com`;
    let fetches = 0;
    vi.stubGlobal("fetch", (async () => {
      fetches++;
      const rows = Array.from({ length: 1000 }, (_, i) => ({ name: `u_table_${i}`, label: `Table ${i}` }));
      return new Response(JSON.stringify({ result: rows }), {
        headers: { "content-type": "application/json", "x-total-count": "1200" },
      });
    }) as unknown as typeof fetch);

    const handlers = buildHandlers(
      {
        LOADER,
        SCHEMA_KV: KV,
        SNOW_INSTANCE_HOST: host,
        SNOW_DEV_ROPC: "1",
        SNOW_DEV_ROPC_USERNAME: "dev-user",
        SNOW_DEV_ROPC_PASSWORD: "dev-pass",
      } as HandlerEnv,
      {
        userId: "list-meta-user",
        scopeMaxMode: "read_only",
        props: { userId: "list-meta-user", scopes: ["servicenow:read"], maxMode: "read_only" },
        schemaIdentityResolver: async () => ({ principalId: "list-meta-principal", roleHash: "list-meta-role" }),
      },
    );

    const first = await handlers.listTables({});
    const firstText = JSON.parse(first.content[0]!.text) as { tables: unknown[]; partial: boolean; total?: number };
    expect(firstText.tables).toHaveLength(1000);
    expect(firstText.partial).toBe(true);
    expect(firstText.total).toBe(1200);
    expect(first.structuredContent).toMatchObject({ cached: false, partial: true, total: 1200 });

    const second = await handlers.listTables({});
    const secondText = JSON.parse(second.content[0]!.text) as { partial: boolean; total?: number };
    expect(secondText.partial).toBe(true);
    expect(secondText.total).toBe(1200);
    expect(second.structuredContent).toMatchObject({ cached: true, partial: true, total: 1200 });
    expect(fetches).toBe(1);
  });

  it("wraps uncached list_tables ServiceNow fetches in a daily budget reserve/reconcile", async () => {
    const host = `inst-discovery-budget-${crypto.randomUUID()}.service-now.com`;
    const reserves: Array<{ req: Record<string, number>; userId?: string }> = [];
    const reconciles: Array<{ delta: Record<string, number>; userId?: string }> = [];
    let fetches = 0;
    vi.stubGlobal("fetch", (async () => {
      fetches++;
      return new Response(JSON.stringify({ result: [{ name: "incident", label: "Incident" }] }), {
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch);
    const budget = {
      reserve: async (req: Record<string, number>, _cap?: Record<string, number>, userId?: string) => {
        reserves.push({ req, userId });
        return { ok: true };
      },
      reconcile: async (delta: Record<string, number>, userId?: string) => {
        reconciles.push({ delta, userId });
      },
    };

    const handlers = buildHandlers(
      {
        LOADER,
        BUDGET_DO: {
          idFromName: (name: string) => name,
          get: () => budget,
        } as unknown as DurableObjectNamespace,
        SNOW_INSTANCE_HOST: host,
        SNOW_DEV_ROPC: "1",
        SNOW_DEV_ROPC_USERNAME: "dev-user",
        SNOW_DEV_ROPC_PASSWORD: "dev-pass",
      } as HandlerEnv,
      {
        userId: "discovery-budget-user",
        scopeMaxMode: "read_only",
        props: { userId: "discovery-budget-user", scopes: ["servicenow:read"], maxMode: "read_only" },
      },
    );

    const res = await handlers.listTables({});
    expect(res.isError).not.toBe(true);
    expect(fetches).toBe(1);
    expect(reserves).toEqual([
      {
        req: expect.objectContaining({ serviceNowRequests: expect.any(Number), outboundBytesSent: expect.any(Number) }) as Record<string, number>,
        userId: "discovery-budget-user",
      },
    ]);
    expect(reconciles).toHaveLength(1);
    expect(reconciles[0]!.userId).toBe("discovery-budget-user");
    expect(reconciles[0]!.delta.rowsReturned).toBe(1);
    expect(reconciles[0]!.delta.bytesReturned).toBeGreaterThan(0);
    expect(reconciles[0]!.delta.outboundBytesSent).toBeLessThan(0);
  });

  it("does not serve stale broad cached schema after ActorPolicy is tightened", async () => {
    const host = `inst-policy-${crypto.randomUUID()}.service-now.com`;
    const identity = { principalId: "policy-principal", roleHash: "policy-role" };
    vi.stubGlobal("fetch", (async (url: string) => {
      const u = new URL(url);
      if (u.pathname === "/api/now/table/sys_db_object") {
        const fields = u.searchParams.get("sysparm_fields") ?? "";
        if (fields === "super_class.name") {
          return new Response(JSON.stringify({ result: [{ "super_class.name": "" }] }), {
            headers: { "content-type": "application/json" },
          });
        }
        return new Response(JSON.stringify({ result: [
          { name: "incident", label: "Incident" },
          { name: "sys_user", label: "User" },
        ] }), { headers: { "content-type": "application/json" } });
      }
      if (u.pathname === "/api/now/table/sys_dictionary") {
        return new Response(JSON.stringify({ result: [
          { element: "number", column_label: "Number", internal_type: "string", mandatory: "false" },
          { element: "caller_id", column_label: "Caller", internal_type: "reference", mandatory: "false" },
        ] }), { headers: { "content-type": "application/json" } });
      }
      return new Response(JSON.stringify({ result: [] }), { headers: { "content-type": "application/json" } });
    }) as unknown as typeof fetch);

    function handlers(env: Partial<HandlerEnv> = {}) {
      return buildHandlers(
        {
          LOADER,
          SCHEMA_KV: KV,
          SNOW_INSTANCE_HOST: host,
          SNOW_DEV_ROPC: "1",
          SNOW_DEV_ROPC_USERNAME: "dev-user",
          SNOW_DEV_ROPC_PASSWORD: "dev-pass",
          ...env,
        } as HandlerEnv,
        {
          userId: "policy-user",
          scopeMaxMode: "read_only",
          props: { userId: "policy-user", scopes: ["servicenow:read"], maxMode: "read_only" },
          schemaIdentityResolver: async () => identity,
        },
      );
    }

    const broad = handlers();
    const broadTables = JSON.parse((await broad.listTables({})).content[0]!.text) as { tables: { name: string }[] };
    expect(broadTables.tables.map((t) => t.name)).toContain("sys_user");
    const broadFields = JSON.parse((await broad.describeTable({ table: "incident" })).content[0]!.text) as { fields: { name: string }[] };
    expect(broadFields.fields.map((f) => f.name)).toContain("caller_id");

    const restricted = handlers({
      ACTOR_POLICY_TABLE_ALLOWLIST: "incident",
      ACTOR_POLICY_FIELD_MASKS: "incident:caller_id",
      ACTOR_POLICY_MAX_MODE: "read_only",
    });
    const restrictedTables = JSON.parse((await restricted.listTables({})).content[0]!.text) as { tables: { name: string }[] };
    expect(restrictedTables.tables.map((t) => t.name)).toEqual(["incident"]);
    const restrictedFields = JSON.parse((await restricted.describeTable({ table: "incident" })).content[0]!.text) as { fields: { name: string }[] };
    expect(restrictedFields.fields.map((f) => f.name)).toEqual(["number"]);
  });
});
