import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  getServiceNowBearer,
  preflightAuth,
  resolveSnPrincipal,
  generatePkce,
  type SnOAuthConfig,
} from "../src/auth/servicenow-oauth.js";
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

// ─── §6b — per_user_oauth MISSING-token path NEVER ROPCs (closes the P3-deferred :71) ──
// Pre-6b, getServiceNowBearer fell through to an unconditional ROPC mint when no token existed.
// In per_user_oauth there is no shared credential for a real human, so a missing/expired-
// unrefreshable token MUST raise reauth_required (carrying the authorizeUrl ticket), never ROPC.
describe("§6b getServiceNowBearer — per_user_oauth missing token reauths (never ROPC)", () => {
  it("missing token → reauth_required with the authorizeUrl detail, and ZERO network calls", async () => {
    const s = store("oaMissingPU");
    const { fetchImpl, calls } = mockFetch({ password: { access_token: "SHOULD_NOT_MINT" } });
    const err = await getServiceNowBearer(baseCfg(fetchImpl), s, 1000, "per_user_oauth", "https://w/servicenow/authorize?ticket=T").catch((e) => e);
    expect(err).toBeInstanceOf(McpToolError);
    expect((err as McpToolError).code).toBe("reauth_required");
    expect((err as McpToolError).detail?.authorizeUrl).toBe("https://w/servicenow/authorize?ticket=T");
    expect(calls).toEqual([]); // the crucial assertion: no `password` grant ever fired
  });

  it("expired token with NO refresh token → reauth_required (never ROPC) in per_user_oauth", async () => {
    const s = store("oaExpiredNoRefreshPU");
    await s.put("servicenow", { access_token: "OLD", expires_at: 1_000 }); // no refresh_token
    const { fetchImpl, calls } = mockFetch({ password: { access_token: "SHOULD_NOT_MINT" } });
    const err = await getServiceNowBearer(baseCfg(fetchImpl), s, 5_000, "per_user_oauth").catch((e) => e);
    expect((err as McpToolError).code).toBe("reauth_required");
    expect(calls).toEqual([]);
  });

  it("integration_user STILL mints via ROPC on a missing token (unchanged)", async () => {
    const s = store("oaMissingIU");
    const { fetchImpl, calls } = mockFetch({ password: { access_token: "MINTED", expires_in: 1800 } });
    const tok = await getServiceNowBearer(baseCfg(fetchImpl), s, 1000, "integration_user");
    expect(tok).toBe("MINTED");
    expect(calls).toEqual([{ grant: "password" }]);
  });

  it("per_user_oauth: a refresh that carries the principal forward keeps sys_id/roles", async () => {
    const s = store("oaRefreshPrincipalPU");
    await s.put("servicenow", { access_token: "OLD", refresh_token: "RKEEP", expires_at: 1_000, sys_id: "U123", roles: ["itil"] });
    const { fetchImpl } = mockFetch({ refresh_token: { access_token: "NEW", expires_in: 1800 } });
    const tok = await getServiceNowBearer(baseCfg(fetchImpl), s, 5_000, "per_user_oauth");
    expect(tok).toBe("NEW");
    const after = await s.get("servicenow");
    expect(after?.sys_id).toBe("U123"); // principal not dropped on refresh
    expect(after?.roles).toEqual(["itil"]);
  });
});

// ─── §6b — preflightAuth (pre-sandbox reauth, no minting) ──────────────────────
describe("§6b preflightAuth", () => {
  it("per_user_oauth: NO token → throws reauth_required with authorizeUrl, mints nothing", async () => {
    const s = store("oaPreflightMissing");
    const err = await preflightAuth(s, "per_user_oauth", "https://w/servicenow/authorize?ticket=PF").catch((e) => e);
    expect(err).toBeInstanceOf(McpToolError);
    expect((err as McpToolError).code).toBe("reauth_required");
    expect((err as McpToolError).detail?.authorizeUrl).toBe("https://w/servicenow/authorize?ticket=PF");
  });

  it("per_user_oauth: a present, still-valid token passes preflight (no throw)", async () => {
    const s = store("oaPreflightValid");
    await s.put("servicenow", { access_token: "AT", refresh_token: "R", expires_at: 10_000 });
    await expect(preflightAuth(s, "per_user_oauth")).resolves.toBeUndefined();
  });

  it("per_user_oauth: an expired token WITH a refresh token passes preflight (refresh at use time)", async () => {
    const s = store("oaPreflightExpiredRefreshable");
    await s.put("servicenow", { access_token: "AT", refresh_token: "R", expires_at: 1_000 });
    await expect(preflightAuth(s, "per_user_oauth")).resolves.toBeUndefined();
  });

  it("integration_user: preflight is a no-op even with no token (ROPC mints on demand)", async () => {
    const s = store("oaPreflightIU");
    await expect(preflightAuth(s, "integration_user")).resolves.toBeUndefined();
  });
});

// ─── §6b — resolveSnPrincipal (current user sys_id + roles) ────────────────────
describe("§6b resolveSnPrincipal", () => {
  it("reads the current user's sys_id from /current_user and roles from sys_user_has_role", async () => {
    const fetchImpl = (async (url: string) => {
      if (url.includes("/api/now/ui/user/current_user")) {
        return new Response(JSON.stringify({ result: { user_sys_id: "SYS123", user_name: "alice" } }), { headers: { "content-type": "application/json" } });
      }
      if (url.includes("/api/now/table/sys_user_has_role")) {
        return new Response(JSON.stringify({ result: [{ "role.name": "itil" }, { "role.name": "admin" }] }), { headers: { "content-type": "application/json" } });
      }
      return new Response("{}", { headers: { "content-type": "application/json" } });
    }) as unknown as typeof fetch;
    const cfg: SnOAuthConfig = { instanceHost: "inst1", clientId: "c", clientSecret: "s", fetchImpl };
    const principal = await resolveSnPrincipal(cfg, "BEARER");
    expect(principal).toEqual({ sys_id: "SYS123", roles: ["itil", "admin"] });
  });

  it("resolves the BEARER's sys_id (current_user), NOT the first sys_user table row", async () => {
    // Discriminating against the OLD bug: the OLD code issued an unfiltered
    // `sys_user?sysparm_limit=1` and took result[0].sys_id — which, because ServiceNow applies
    // sysparm_limit BEFORE ACLs and returns TABLE ORDER, is a DECOY (admin), not the bearer.
    // current_user returns the bearer (BEARER_SYS). The roles fetch is keyed on the bearer.
    let roleQuery = "";
    const fetchImpl = (async (url: string) => {
      if (url.includes("/api/now/ui/user/current_user")) {
        return new Response(JSON.stringify({ result: { user_sys_id: "BEARER_SYS", user_name: "alice" } }), { headers: { "content-type": "application/json" } });
      }
      if (url.includes("/api/now/table/sys_user?")) {
        // The OLD query's first table row — a DIFFERENT user (admin). New code never reads this.
        return new Response(JSON.stringify({ result: [{ sys_id: "ADMIN_SYS", user_name: "admin" }] }), { headers: { "content-type": "application/json" } });
      }
      if (url.includes("/api/now/table/sys_user_has_role")) {
        roleQuery = url;
        return new Response(JSON.stringify({ result: [{ "role.name": "itil" }] }), { headers: { "content-type": "application/json" } });
      }
      return new Response("{}", { headers: { "content-type": "application/json" } });
    }) as unknown as typeof fetch;
    const cfg: SnOAuthConfig = { instanceHost: "inst1", clientId: "c", clientSecret: "s", fetchImpl };
    const principal = await resolveSnPrincipal(cfg, "BEARER");
    expect(principal?.sys_id).toBe("BEARER_SYS"); // NOT "ADMIN_SYS" (the old limit=1 table row)
    expect(roleQuery).toContain("user=BEARER_SYS"); // roles resolved for the bearer, not the decoy
  });

  it("returns null (best-effort) when the current-user fetch yields no user_sys_id", async () => {
    const fetchImpl = (async () => new Response(JSON.stringify({ result: {} }), { headers: { "content-type": "application/json" } })) as unknown as typeof fetch;
    const cfg: SnOAuthConfig = { instanceHost: "inst1", clientId: "c", clientSecret: "s", fetchImpl };
    expect(await resolveSnPrincipal(cfg, "BEARER")).toBeNull();
  });
});

// ─── §6b — PKCE generation (S256) ──────────────────────────────────────────────
describe("§6b generatePkce", () => {
  it("produces a fresh high-entropy verifier and a deterministic S256 challenge for it", async () => {
    const a = await generatePkce();
    const b = await generatePkce();
    expect(a.verifier).not.toBe(b.verifier); // fresh per call
    expect(a.verifier.length).toBeGreaterThanOrEqual(43); // 32 bytes base64url
    expect(a.challenge).toMatch(/^[A-Za-z0-9_-]+$/); // base64url, no padding
    // Recompute the challenge to confirm it is S256(verifier).
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(a.verifier)));
    const expected = btoa(String.fromCharCode(...digest)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(a.challenge).toBe(expected);
  });
});
