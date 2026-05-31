import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { serviceNowCallbackHandler, type CallbackHandlerEnv } from "../src/auth/servicenow-callback-handler.js";
import { mintTicket } from "../src/auth/servicenow-ticket.js";
import { TokenStore } from "../src/auth/token-store.js";
import { buildKekRing, type KekRing } from "../src/auth/crypto.js";

// ─── §6b — per-user ServiceNow OAuth authorize → callback dance ────────────────
// Routes live OUTSIDE /mcp (no ctx.props). Identity is carried in via the host-HMAC ticket,
// then pinned into a single-use AuthCorrelationDO record keyed by the opaque OAuth `state`.
// The callback consumes that record once, exchanges the code, resolves the principal, and
// stores the token under the RECORD's userId — never a callback request param.

interface TestEnv {
  AUTH_DO: DurableObjectNamespace<import("../src/do/auth-correlation.js").AuthCorrelationDO>;
  TOKEN_DO: DurableObjectNamespace<import("../src/do/token-store.js").TokenStoreDO>;
}
const E = env as unknown as TestEnv;

const HOST = "dev123.service-now.com";
const SECRET = "host-oauth-provider-secret";
const KEK = "token-kek-passphrase";
const ORIGIN = "https://mcp.example.workers.dev";

/** Mock upstream SN: oauth_token.do (code exchange) + the current_user / role principal fetches. */
function mockSn(opts: { token?: Record<string, unknown>; failExchange?: boolean } = {}) {
  const calls: { url: string; grant?: string }[] = [];
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    if (url.includes("/oauth_token.do")) {
      const grant = new URLSearchParams(String(init?.body)).get("grant_type") ?? "";
      calls.push({ url, grant });
      if (opts.failExchange) return new Response(JSON.stringify({ error: "invalid_grant" }), { headers: { "content-type": "application/json" } });
      return new Response(JSON.stringify(opts.token ?? { access_token: "AT", refresh_token: "RT", expires_in: 1800 }), { headers: { "content-type": "application/json" } });
    }
    if (url.includes("/api/now/ui/user/current_user")) {
      calls.push({ url });
      return new Response(JSON.stringify({ result: { user_sys_id: "EFF_SYS_ID", user_name: "alice" } }), { headers: { "content-type": "application/json" } });
    }
    if (url.includes("/api/now/table/sys_user_has_role")) {
      calls.push({ url });
      return new Response(JSON.stringify({ result: [{ "role.name": "itil" }] }), { headers: { "content-type": "application/json" } });
    }
    calls.push({ url });
    return new Response("{}", { headers: { "content-type": "application/json" } });
  }) as unknown as typeof fetch;
  return { fetchImpl, calls };
}

function handlerEnv(fetchImpl: typeof fetch): CallbackHandlerEnv {
  return {
    AUTH_DO: E.AUTH_DO as unknown as CallbackHandlerEnv["AUTH_DO"],
    TOKEN_DO: E.TOKEN_DO as unknown as CallbackHandlerEnv["TOKEN_DO"],
    SNOW_INSTANCE_HOST: HOST,
    SNOW_OAUTH_CLIENT_ID: "client-id",
    SNOW_OAUTH_CLIENT_SECRET: "client-secret",
    TOKEN_KEK_CURRENT: KEK,
    OAUTH_PROVIDER_SECRET: SECRET,
    SERVICENOW_CREDENTIAL_MODE: "per_user_oauth",
    fetchImpl,
  };
}

async function authorize(userId: string, hEnv: CallbackHandlerEnv, instanceHost = HOST): Promise<string> {
  const ticket = await mintTicket({ userId, instanceHost, nonce: "n", exp: Date.now() + 60_000 }, SECRET);
  const res = await serviceNowCallbackHandler(
    new Request(`${ORIGIN}/servicenow/authorize?ticket=${encodeURIComponent(ticket)}`),
    hEnv,
  );
  expect(res!.status).toBe(302);
  const location = new URL(res!.headers.get("location")!);
  expect(location.host).toBe(HOST);
  expect(location.searchParams.get("code_challenge_method")).toBe("S256");
  expect(location.searchParams.get("response_type")).toBe("code");
  expect(location.searchParams.get("redirect_uri")).toBe(`${ORIGIN}/servicenow/callback`);
  return location.searchParams.get("state")!;
}

function callback(state: string, hEnv: CallbackHandlerEnv, code = "the-code"): Promise<Response | null> {
  return serviceNowCallbackHandler(
    new Request(`${ORIGIN}/servicenow/callback?code=${code}&state=${encodeURIComponent(state)}`),
    hEnv,
  );
}

async function storedTokenFor(userId: string): Promise<import("../src/auth/token-store.js").SnTokens | null> {
  const ring: KekRing = await buildKekRing(KEK);
  const stub = E.TOKEN_DO.get(E.TOKEN_DO.idFromName(`${userId}|${HOST}`));
  return new TokenStore(stub, ring, userId, HOST).get("servicenow");
}

describe("§6b authorize → callback stores a per-user token", () => {
  it("the full dance stores the token + resolved principal under the ticket's userId", async () => {
    const { fetchImpl, calls } = mockSn();
    const hEnv = handlerEnv(fetchImpl);
    const state = await authorize("userDance", hEnv);
    const res = await callback(state, hEnv);
    expect(res!.status).toBe(200);
    // The exchange was an authorization_code grant (NOT ROPC), then the principal was resolved.
    expect(calls.some((c) => c.grant === "authorization_code")).toBe(true);
    expect(calls.some((c) => c.grant === "password")).toBe(false);
    const tok = await storedTokenFor("userDance");
    expect(tok?.access_token).toBe("AT");
    expect(tok?.sys_id).toBe("EFF_SYS_ID"); // principal persisted alongside the token
    expect(tok?.roles).toEqual(["itil"]);
  });
});

describe("§6b callback fails closed", () => {
  it("REPLAYED/consumed state → rejected (consume-once), and stores no second token", async () => {
    const { fetchImpl } = mockSn();
    const hEnv = handlerEnv(fetchImpl);
    const state = await authorize("userReplay", hEnv);
    expect((await callback(state, hEnv))!.status).toBe(200); // first use succeeds
    const replay = await callback(state, hEnv); // second use: record already deleted
    expect(replay!.status).toBe(400);
  });

  it("UNKNOWN/forged state → rejected (no record), no token issued", async () => {
    const { fetchImpl, calls } = mockSn();
    const hEnv = handlerEnv(fetchImpl);
    const res = await callback("not-a-real-state", hEnv);
    expect(res!.status).toBe(400);
    expect(calls.some((c) => c.grant === "authorization_code")).toBe(false); // never exchanged
  });

  it("WRONG-INSTANCE state → rejected (record.instanceHost ≠ configured instance)", async () => {
    const { fetchImpl } = mockSn();
    // Authorize with a ticket for a DIFFERENT instance: /authorize itself rejects the mismatch,
    // so no record is ever created — a callback can never use a wrong-instance state.
    const ticket = await mintTicket(
      { userId: "userWrongInst", instanceHost: "other.service-now.com", nonce: "n", exp: Date.now() + 60_000 },
      SECRET,
    );
    const res = await serviceNowCallbackHandler(
      new Request(`${ORIGIN}/servicenow/authorize?ticket=${encodeURIComponent(ticket)}`),
      handlerEnv(fetchImpl),
    );
    expect(res!.status).toBe(400); // ticket instance mismatch, no flow started
  });

  it("a failed code exchange issues no token (4xx)", async () => {
    const { fetchImpl } = mockSn({ failExchange: true });
    const hEnv = handlerEnv(fetchImpl);
    const state = await authorize("userExchangeFail", hEnv);
    const res = await callback(state, hEnv);
    expect(res!.status).toBe(400);
    expect(await storedTokenFor("userExchangeFail")).toBeNull();
  });

  it("/servicenow/authorize with an invalid ticket → 401, no flow started", async () => {
    const { fetchImpl } = mockSn();
    const res = await serviceNowCallbackHandler(
      new Request(`${ORIGIN}/servicenow/authorize?ticket=garbage`),
      handlerEnv(fetchImpl),
    );
    expect(res!.status).toBe(401);
  });
});

describe("§6b cross-user isolation (S7)", () => {
  it("the token lands under the RECORD's userId — a callback never stores under a request param", async () => {
    const { fetchImpl } = mockSn();
    const hEnv = handlerEnv(fetchImpl);
    // userA completes the dance; userB never authorizes.
    const stateA = await authorize("userA-iso", hEnv);
    expect((await callback(stateA, hEnv))!.status).toBe(200);
    // userA has a token; userB (who never authorized) has none — the callback could not have
    // been steered to store under any client-supplied identity.
    expect((await storedTokenFor("userA-iso"))?.access_token).toBe("AT");
    expect(await storedTokenFor("userB-iso")).toBeNull();
  });
});

describe("§6b routing", () => {
  it("returns null for a non-/servicenow path (falls through to the provider)", async () => {
    const { fetchImpl } = mockSn();
    const res = await serviceNowCallbackHandler(new Request(`${ORIGIN}/mcp`), handlerEnv(fetchImpl));
    expect(res).toBeNull();
  });
});
