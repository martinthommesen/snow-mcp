import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { getServiceNowBearer, type SnOAuthConfig } from "../src/auth/servicenow-oauth.js";
import { TokenStore } from "../src/auth/token-store.js";
import { McpToolError } from "../src/sn/errors.js";
import type { KekRing } from "../src/auth/crypto.js";

// ─── §2.8 / §7.5 — ServiceNow OAuth token mint / reuse / refresh ──────────────
interface TestEnv { TOKEN_DO: DurableObjectNamespace<import("../src/do/token-store.js").TokenStoreDO>; }
const NS = (env as unknown as TestEnv).TOKEN_DO;
const ring: KekRing = { current: { version: "current", keyBytes: new Uint8Array(32).fill(7) } };
const store = (u: string) => new TokenStore(NS.get(NS.idFromName(`${u}|inst1`)), ring, u, "inst1");

function mockFetch(responses: Record<string, unknown>) {
  const calls: { grant: string }[] = [];
  const fetchImpl = (async (_url: string, init: RequestInit) => {
    const body = new URLSearchParams(String(init.body));
    const grant = body.get("grant_type") ?? "";
    calls.push({ grant });
    return new Response(JSON.stringify(responses[grant] ?? { error: "unsupported" }), { headers: { "content-type": "application/json" } });
  }) as unknown as typeof fetch;
  return { fetchImpl, calls };
}

const baseCfg = (fetchImpl: typeof fetch): SnOAuthConfig => ({
  instanceHost: "inst1", clientId: "cid", clientSecret: "sec", ropcUsername: "u", ropcPassword: "p", fetchImpl,
});

describe("§2.8 getServiceNowBearer", () => {
  it("mints via ROPC on first use and stores the token encrypted", async () => {
    const { fetchImpl, calls } = mockFetch({ password: { access_token: "AT1", refresh_token: "RT1", expires_in: 1800 } });
    const s = store("oa1");
    const tok = await getServiceNowBearer(baseCfg(fetchImpl), s, 1000);
    expect(tok).toBe("AT1");
    expect(calls).toEqual([{ grant: "password" }]);
    expect((await s.get("servicenow"))?.refresh_token).toBe("RT1");
  });

  it("reuses a still-valid stored token without a network call", async () => {
    const s = store("oa2");
    await s.put("servicenow", { access_token: "STORED", refresh_token: "R", expires_at: 10_000 });
    const { fetchImpl, calls } = mockFetch({});
    const tok = await getServiceNowBearer(baseCfg(fetchImpl), s, 5_000); // before expiry
    expect(tok).toBe("STORED");
    expect(calls).toEqual([]);
  });

  it("refreshes an expired token and carries the refresh token forward (B9: no rotation)", async () => {
    const s = store("oa3");
    await s.put("servicenow", { access_token: "OLD", refresh_token: "RKEEP", expires_at: 1_000 });
    const { fetchImpl, calls } = mockFetch({ refresh_token: { access_token: "NEW", expires_in: 1800 } }); // no refresh_token returned
    const tok = await getServiceNowBearer(baseCfg(fetchImpl), s, 5_000); // after expiry
    expect(tok).toBe("NEW");
    expect(calls).toEqual([{ grant: "refresh_token" }]);
    expect((await s.get("servicenow"))?.refresh_token).toBe("RKEEP"); // carried forward
  });
});

// ─── P3 — fail-closed re-mint on an undecryptable stored token (closes finding 29) ──
// Seal a token under ring A, then read it back through a store over the SAME (user|instance)
// DO but a different KEK (key mismatch → store.get() throws). The decrypt failure must never
// escape past recovery: integration_user re-mints; per_user_oauth raises reauth_required.
const ringA: KekRing = { current: { version: "current", keyBytes: new Uint8Array(32).fill(1) } };
const ringB: KekRing = { current: { version: "current", keyBytes: new Uint8Array(32).fill(2) } };
const corruptStore = (u: string) => {
  const id = NS.idFromName(`${u}|inst1`);
  return { writer: new TokenStore(NS.get(id), ringA, u, "inst1"), reader: new TokenStore(NS.get(id), ringB, u, "inst1") };
};

describe("§P3 getServiceNowBearer — corrupt token fail-closed re-mint", () => {
  it("integration_user: an undecryptable token is re-minted via ROPC (no throw)", async () => {
    const { writer, reader } = corruptStore("oaCorruptIU");
    await writer.put("servicenow", { access_token: "UNDECRYPTABLE", refresh_token: "R", expires_at: 10_000 });
    const { fetchImpl, calls } = mockFetch({ password: { access_token: "REMINT", refresh_token: "RT", expires_in: 1800 } });
    const tok = await getServiceNowBearer(baseCfg(fetchImpl), reader, 5_000, "integration_user");
    expect(tok).toBe("REMINT");
    expect(calls).toEqual([{ grant: "password" }]); // re-minted, never refreshed the corrupt token
  });

  it("per_user_oauth: an undecryptable token raises reauth_required and NEVER hits the network", async () => {
    const { writer, reader } = corruptStore("oaCorruptPU");
    await writer.put("servicenow", { access_token: "UNDECRYPTABLE", refresh_token: "R", expires_at: 10_000 });
    const { fetchImpl, calls } = mockFetch({ password: { access_token: "SHOULD_NOT_MINT" } });
    const err = await getServiceNowBearer(baseCfg(fetchImpl), reader, 5_000, "per_user_oauth").catch((e) => e);
    expect(err).toBeInstanceOf(McpToolError);
    expect((err as McpToolError).code).toBe("reauth_required");
    expect(calls).toEqual([]); // no ROPC, no refresh
  });
});
