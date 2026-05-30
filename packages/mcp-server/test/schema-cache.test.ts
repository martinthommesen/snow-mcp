import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { SchemaCache, roleHash, type SchemaCacheIdentity } from "../src/cache/schema.js";
import type { FieldInfo } from "../src/sn/discovery.js";

// ─── §2.6 / S6 — user-aware schema cache ──────────────────────────────────────
interface TestEnv { SCHEMA_KV: KVNamespace; }
const KV = (env as unknown as TestEnv).SCHEMA_KV;

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
});
