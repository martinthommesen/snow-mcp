import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { SchemaCache, roleHash, type SchemaCacheIdentity } from "../src/cache/schema.js";
import type { FieldInfo, TableInfo } from "../src/sn/discovery.js";
import { resolveRoleHash, type HandlerEnv } from "../src/tools/handlers.js";
import { TokenStore } from "../src/auth/token-store.js";
import { buildKekRing } from "../src/auth/crypto.js";

// ─── §2.6 / S6 — user-aware schema cache ──────────────────────────────────────
interface TestEnv {
  SCHEMA_KV: KVNamespace;
  TOKEN_DO: DurableObjectNamespace<import("../src/do/token-store.js").TokenStoreDO>;
}
const KV = (env as unknown as TestEnv).SCHEMA_KV;
const TOKEN_DO = (env as unknown as TestEnv).TOKEN_DO;

const idA: SchemaCacheIdentity = { instanceHost: "inst1", userId: "userA", roleHash: "r1" };
const idB: SchemaCacheIdentity = { instanceHost: "inst1", userId: "userB", roleHash: "r1" };

const fieldsWith = (names: string[]): FieldInfo[] => names.map((n) => ({ name: n, label: n, type: "string", mandatory: false }));

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

  it("S6 — does NOT leak one user's fields to another (user-aware key)", async () => {
    // User A (broad) sees caller_id; user B (same role, failing a field ACL) must not.
    const cacheA = new SchemaCache(KV, { ...idA, instanceHost: "inst2" });
    const cacheB = new SchemaCache(KV, { ...idB, instanceHost: "inst2" });
    await cacheA.describeTable("incident", async () => fieldsWith(["number", "caller_id"]));
    const bResult = await cacheB.describeTable("incident", async () => fieldsWith(["number"])); // B's own fetch
    expect(bResult.cached).toBe(false); // B did not hit A's entry
    expect(bResult.fields.some((f) => f.name === "caller_id")).toBe(false);
  });

  it("invalidation forces a re-fetch", async () => {
    const cache = new SchemaCache(KV, { ...idA, instanceHost: "inst3" });
    let fetches = 0;
    const fetcher = async () => { fetches++; return fieldsWith(["a"]); };
    await cache.describeTable("problem", fetcher);
    await cache.invalidateTable("problem");
    const after = await cache.describeTable("problem", fetcher);
    expect(after.cached).toBe(false);
    expect(fetches).toBe(2);
  });

  it("roleHash is order-independent and busts on role change", async () => {
    expect(await roleHash(["itil", "admin"])).toBe(await roleHash(["admin", "itil"]));
    expect(await roleHash(["itil"])).not.toBe(await roleHash(["itil", "admin"]));
  });

  // ─── P6b — listTables cache-key collision: '*' filter must NOT alias the no-filter case ──
  // Pre-P6b the key used `filter ?? "*"`, so listTables(undefined) and listTables("*") collided.
  it("a literal '*' filter does NOT collide with the no-filter case (distinct keys)", async () => {
    const cache = new SchemaCache(KV, { ...idA, instanceHost: "inst-collision" });
    const tablesWith = (names: string[]): TableInfo[] => names.map((n) => ({ name: n, label: n }));
    const none = await cache.listTables(undefined, async () => tablesWith(["all_tables"]));
    const star = await cache.listTables("*", async () => tablesWith(["star_filtered"]));
    expect(none.cached).toBe(false);
    expect(star.cached).toBe(false); // distinct key ⇒ NOT served from the no-filter entry
    expect(star.tables.map((t) => t.name)).toEqual(["star_filtered"]);
    // And each is independently cached on a second call.
    expect((await cache.listTables(undefined, async () => tablesWith(["x"]))).cached).toBe(true);
    expect((await cache.listTables("*", async () => tablesWith(["x"]))).cached).toBe(true);
  });
});

// ─── P6b — resolveRoleHash wiring (apiHandler → SchemaCache identity) ──────────
describe("§6b resolveRoleHash wiring", () => {
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

  async function seedToken(userId: string, roles: string[] | undefined): Promise<void> {
    const ring = await buildKekRing(SECRET);
    // The DO stub IS the TokenStoreBackend (putToken/getToken/revokeAll), same as token-store.test.
    const stub = TOKEN_DO.get(TOKEN_DO.idFromName(`${userId}|${HOST}`));
    const store = new TokenStore(stub, ring, userId, HOST);
    await store.put("servicenow", { access_token: "a", ...(roles ? { roles } : {}) });
  }

  it("returns 'default' in integration_user mode (no extra decrypt; live deployment untouched)", async () => {
    const out = await resolveRoleHash({ ...baseEnv, SERVICENOW_CREDENTIAL_MODE: "integration_user" } as HandlerEnv, "u-int");
    expect(out).toBe("default");
  });

  it("returns 'default' when the OAuth path is not fully configured", async () => {
    const out = await resolveRoleHash({ SERVICENOW_CREDENTIAL_MODE: "per_user_oauth" } as HandlerEnv, "u-unconfigured");
    expect(out).toBe("default");
  });

  it("returns 'default' when no token / no roles are stored (best-effort, never throws)", async () => {
    const out = await resolveRoleHash(baseEnv as HandlerEnv, "u-no-token");
    expect(out).toBe("default");
    await seedToken("u-no-roles", undefined);
    expect(await resolveRoleHash(baseEnv as HandlerEnv, "u-no-roles")).toBe("default");
  });

  it("computes the principal's roleHash in per_user_oauth — and a role change busts the cache key", async () => {
    await seedToken("u-roles", ["itil", "admin"]);
    const h1 = await resolveRoleHash(baseEnv as HandlerEnv, "u-roles");
    expect(h1).toBe(await roleHash(["itil", "admin"]));
    expect(h1).not.toBe("default");

    // A role change ⇒ a DIFFERENT roleHash ⇒ a DIFFERENT SchemaCache key (cache busted).
    await seedToken("u-roles", ["itil"]);
    const h2 = await resolveRoleHash(baseEnv as HandlerEnv, "u-roles");
    expect(h2).toBe(await roleHash(["itil"]));
    expect(h2).not.toBe(h1);

    const idBefore: SchemaCacheIdentity = { instanceHost: HOST, userId: "u-roles", roleHash: h1 };
    const idAfter: SchemaCacheIdentity = { instanceHost: HOST, userId: "u-roles", roleHash: h2 };
    const before = new SchemaCache(KV, idBefore);
    const after = new SchemaCache(KV, idAfter);
    let fetches = 0;
    const fetcher = async () => { fetches++; return [{ name: "number", label: "Number", type: "string", mandatory: false }] as FieldInfo[]; };
    await before.describeTable("incident", fetcher);
    const afterResult = await after.describeTable("incident", fetcher);
    expect(afterResult.cached).toBe(false); // role changed ⇒ cache miss
    expect(fetches).toBe(2);
  });
});
