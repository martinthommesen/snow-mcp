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
function mockSn(opts: {
  token?: Record<string, unknown>;
  failExchange?: boolean;
  failPrincipal?: boolean;
  principal?: Record<string, unknown>;
} = {}) {
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
      if (opts.failPrincipal) {
        return new Response(JSON.stringify({ result: {} }), { headers: { "content-type": "application/json" } });
      }
      return new Response(JSON.stringify({
        result: opts.principal ?? { user_sys_id: "EFF_SYS_ID", user_name: "alice@example.com", email: "alice@example.com" },
      }), { headers: { "content-type": "application/json" } });
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
    WORKER_PUBLIC_ORIGIN: ORIGIN,
    SERVICENOW_CREDENTIAL_MODE: "per_user_oauth",
    fetchImpl,
  };
}

async function authorize(
  userId: string,
  hEnv: CallbackHandlerEnv,
  instanceHost = HOST,
  requestOrigin = ORIGIN,
  actorEmail: string | undefined = "alice@example.com",
  expectedSnSysId?: string,
): Promise<string> {
  const ticket = await mintTicket({
    userId,
    ...(actorEmail ? { actorEmail } : {}),
    instanceHost,
    nonce: crypto.randomUUID(),
    ...(expectedSnSysId ? { expectedSnSysId } : {}),
    exp: Date.now() + 60_000,
  }, SECRET);
  const res = await serviceNowCallbackHandler(
    new Request(`${requestOrigin}/servicenow/authorize?ticket=${encodeURIComponent(ticket)}`),
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
    expect(tok?.user_name).toBe("alice@example.com");
    expect(tok?.email).toBe("alice@example.com");
    expect(tok?.principal_resolved_at).toEqual(expect.any(Number));
  });

  it("rejects a first-time binding when neither actor email nor expected sys_id is available", async () => {
    const { fetchImpl } = mockSn({
      principal: { user_sys_id: "EMAILLESS_SYS", user_name: "sn-user", email: "" },
    });
    const hEnv = handlerEnv(fetchImpl);
    const state = await authorize("userNoEmailClaim", hEnv, HOST, ORIGIN, "");
    const res = await callback(state, hEnv);
    expect(res!.status).toBe(403);
    expect(await storedTokenFor("userNoEmailClaim")).toBeNull();
  });

  it("allows no-email reauth when the ticket is pinned to an expected ServiceNow sys_id", async () => {
    const { fetchImpl } = mockSn({
      principal: { user_sys_id: "EMAILLESS_SYS", user_name: "sn-user", email: "" },
    });
    const hEnv = handlerEnv(fetchImpl);
    const state = await authorize("userNoEmailReauth", hEnv, HOST, ORIGIN, "", "EMAILLESS_SYS");
    const res = await callback(state, hEnv);
    expect(res!.status).toBe(200);
    const tok = await storedTokenFor("userNoEmailReauth");
    expect(tok?.sys_id).toBe("EMAILLESS_SYS");
    expect(tok?.user_name).toBe("sn-user");
  });

  it("pins redirect_uri to WORKER_PUBLIC_ORIGIN instead of the request host", async () => {
    const { fetchImpl } = mockSn();
    await authorize("userPinnedOrigin", handlerEnv(fetchImpl), HOST, "https://spoofed.example");
  });

  it("consumes each reauth ticket once before creating OAuth state", async () => {
    const { fetchImpl } = mockSn();
    const ticket = await mintTicket(
      { userId: "userTicketReplay", actorEmail: "alice@example.com", instanceHost: HOST, nonce: crypto.randomUUID(), exp: Date.now() + 60_000 },
      SECRET,
    );
    const first = await serviceNowCallbackHandler(
      new Request(`${ORIGIN}/servicenow/authorize?ticket=${encodeURIComponent(ticket)}`),
      handlerEnv(fetchImpl),
    );
    expect(first!.status).toBe(302);
    const second = await serviceNowCallbackHandler(
      new Request(`${ORIGIN}/servicenow/authorize?ticket=${encodeURIComponent(ticket)}`),
      handlerEnv(fetchImpl),
    );
    expect(second!.status).toBe(401);
  });
});

describe("§6b callback fails closed", () => {
  it("requires explicit per_user_oauth mode and a configured public origin", async () => {
    const { fetchImpl } = mockSn();
    const ticket = await mintTicket({ userId: "userNoOrigin", actorEmail: "alice@example.com", instanceHost: HOST, nonce: "n", exp: Date.now() + 60_000 }, SECRET);

    const missingOrigin = await serviceNowCallbackHandler(
      new Request(`${ORIGIN}/servicenow/authorize?ticket=${encodeURIComponent(ticket)}`),
      { ...handlerEnv(fetchImpl), WORKER_PUBLIC_ORIGIN: undefined },
    );
    expect(missingOrigin!.status).toBe(400);

    const inactiveMode = await serviceNowCallbackHandler(
      new Request(`${ORIGIN}/servicenow/authorize?ticket=${encodeURIComponent(ticket)}`),
      { ...handlerEnv(fetchImpl), SERVICENOW_CREDENTIAL_MODE: "integration_user" },
    );
    expect(inactiveMode!.status).toBe(400);
  });

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
      { userId: "userWrongInst", actorEmail: "alice@example.com", instanceHost: "other.service-now.com", nonce: "n", exp: Date.now() + 60_000 },
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

  it("a failed principal resolution issues no token (fail closed)", async () => {
    const { fetchImpl } = mockSn({ failPrincipal: true });
    const hEnv = handlerEnv(fetchImpl);
    const state = await authorize("userPrincipalFail", hEnv);
    const res = await callback(state, hEnv);
    expect(res!.status).toBe(400);
    expect(await storedTokenFor("userPrincipalFail")).toBeNull();
  });

  it("a ServiceNow principal whose email/user_name does not match the MCP actor issues no token", async () => {
    const { fetchImpl } = mockSn({
      principal: { user_sys_id: "VICTIM_SYS", user_name: "victim@example.com", email: "victim@example.com" },
    });
    const hEnv = handlerEnv(fetchImpl);
    const state = await authorize("attackerUser", hEnv, HOST, ORIGIN, "attacker@example.com");
    const res = await callback(state, hEnv);
    expect(res!.status).toBe(403);
    expect(await storedTokenFor("attackerUser")).toBeNull();
  });

  it("an expected ServiceNow sys_id binding cannot be swapped even when email matches", async () => {
    const { fetchImpl } = mockSn({
      principal: { user_sys_id: "NEW_SYS", user_name: "alice@example.com", email: "alice@example.com" },
    });
    const hEnv = handlerEnv(fetchImpl);
    const state = await authorize("userBound", hEnv, HOST, ORIGIN, "alice@example.com", "OLD_SYS");
    const res = await callback(state, hEnv);
    expect(res!.status).toBe(403);
    expect(await storedTokenFor("userBound")).toBeNull();
  });

  it("allows reauth to replace an unreadable stored token while preserving actor-email binding", async () => {
    const { fetchImpl } = mockSn({
      principal: { user_sys_id: "REPLACEMENT_SYS", user_name: "alice@example.com", email: "alice@example.com" },
    });
    const userId = "userUnreadableReauth";
    const hEnv = handlerEnv(fetchImpl);
    const corruptBackend = E.TOKEN_DO.get(E.TOKEN_DO.idFromName(`${userId}|${HOST}`));
    await corruptBackend.putToken("servicenow", "not-json-not-decryptable");

    const state = await authorize(userId, hEnv);
    const res = await callback(state, hEnv);
    expect(res!.status).toBe(200);
    const tok = await storedTokenFor(userId);
    expect(tok?.access_token).toBe("AT");
    expect(tok?.sys_id).toBe("REPLACEMENT_SYS");
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

describe("§6b AuthCorrelationDO expiry cleanup", () => {
  it("purges abandoned expired states without consuming a callback", async () => {
    const state = `expired-${crypto.randomUUID()}`;
    const stub = E.AUTH_DO.get(E.AUTH_DO.idFromName(`state:${state}`));
    await stub.createRecord(state, {
      userId: "abandonedUser",
      actorEmail: "alice@example.com",
      instanceHost: HOST,
      pkceVerifier: "verifier",
      expiresAt: Date.now() - 1,
    });

    await stub.cleanupExpired(Date.now());
    expect(await stub.consumeRecord(state)).toBeNull();
  });

  it("keeps unexpired states while cleaning older records", async () => {
    const state = `future-${crypto.randomUUID()}`;
    const stub = E.AUTH_DO.get(E.AUTH_DO.idFromName(`state:${state}`));
    const record = {
      userId: "futureUser",
      actorEmail: "alice@example.com",
      instanceHost: HOST,
      pkceVerifier: "verifier",
      expiresAt: Date.now() + 60_000,
    };
    await stub.createRecord(state, record);

    await stub.cleanupExpired(Date.now());
    expect(await stub.consumeRecord(state)).toEqual(record);
  });

  it("expires consumed ticket nonces so a future same nonce can be claimed after expiry", async () => {
    const nonce = `nonce-${crypto.randomUUID()}`;
    const stub = E.AUTH_DO.get(E.AUTH_DO.idFromName(`ticket:${nonce}`));
    expect(await stub.consumeTicketNonce(nonce, Date.now() - 1, Date.now() - 2)).toBe(true);
    expect(await stub.consumeTicketNonce(nonce, Date.now() + 60_000, Date.now())).toBe(true);
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
