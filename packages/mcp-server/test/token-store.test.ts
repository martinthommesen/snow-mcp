import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { TokenStore } from "../src/auth/token-store.js";
import type { KekRing } from "../src/auth/crypto.js";

// ─── §2.7 / §7.5 / S7 — token lifecycle; S2-auth — per-(user,instance) isolation ──
interface TestEnv { TOKEN_DO: DurableObjectNamespace<import("../src/do/token-store.js").TokenStoreDO>; }
const NS = (env as unknown as TestEnv).TOKEN_DO;

function backend(userId: string, instanceHost: string) {
  const id = NS.idFromName(`${userId}|${instanceHost}`);
  return NS.get(id); // the DO stub IS the TokenStoreBackend (putToken/getToken/revokeAll)
}
const ring: KekRing = { current: { version: "2026-05", keyBytes: new Uint8Array(32).fill(5) } };
const store = (u: string, h: string, r: KekRing = ring) => new TokenStore(backend(u, h), r, u, h);

describe("§2.7 / S7 token store", () => {
  it("encrypts at rest: raw DO value is NOT the plaintext token", async () => {
    await store("uA", "inst1").put("servicenow", { access_token: "SECRET-AT-123", refresh_token: "R1" });
    const raw = await backend("uA", "inst1").getToken("servicenow");
    expect(raw).toBeDefined();
    expect(raw).not.toContain("SECRET-AT-123"); // ciphertext, not plaintext
    expect(await store("uA", "inst1").get("servicenow")).toEqual({ access_token: "SECRET-AT-123", refresh_token: "R1" });
  });

  it("rotate replaces tokens; revoke clears them", async () => {
    const s = store("uRot", "inst1");
    await s.put("servicenow", { access_token: "a1", refresh_token: "r1" });
    await s.rotate("servicenow", { access_token: "a2", refresh_token: "r2" });
    expect((await s.get("servicenow"))?.access_token).toBe("a2");
    await s.revoke();
    expect(await s.get("servicenow")).toBeNull();
  });

  it("S2-auth — one user's tokens never decrypt under another user's store (AAD-bound)", async () => {
    await store("uX", "inst1").put("servicenow", { access_token: "x-token" });
    // userY has its OWN DO instance — no leakage.
    expect(await store("uY", "inst1").get("servicenow")).toBeNull();
    // Even reusing uX's ciphertext under uY's AAD fails closed.
    const cipher = await backend("uX", "inst1").getToken("servicenow");
    await backend("uY", "inst2").putToken("servicenow", cipher!);
    await expect(store("uY", "inst2").get("servicenow")).rejects.toThrow(); // AAD mismatch
  });

  it("decrypts under the previous KEK during rotation, fails once it ages out", async () => {
    await store("uKek", "inst1").put("servicenow", { access_token: "k-token" });
    const rotated: KekRing = { current: { version: "2026-06", keyBytes: new Uint8Array(32).fill(9) }, previous: { version: "2026-05", keyBytes: new Uint8Array(32).fill(5) } };
    expect((await store("uKek", "inst1", rotated).get("servicenow"))?.access_token).toBe("k-token");
    const aged: KekRing = { current: { version: "2026-07", keyBytes: new Uint8Array(32).fill(1) } };
    await expect(store("uKek", "inst1", aged).get("servicenow")).rejects.toThrow();
  });
});
