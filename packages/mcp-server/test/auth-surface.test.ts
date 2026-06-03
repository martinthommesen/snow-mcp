import { SELF, env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { serviceNowAuthHandler } from "../src/auth/servicenow-auth-handler.js";
import { MissingOAuthKvError } from "../src/auth/oauth-kv.js";
import { authenticatedUserId } from "../src/index.js";
import type { OidcConsentRecord, OidcCorrelationRecord } from "../src/do/auth-correlation.js";
import {
  OIDC_ISSUER,
  OIDC_CLIENT_ID,
  OIDC_CLIENT_SECRET,
  oidcSigner,
  oidcIdToken,
  fakeOidcFetch,
} from "./oidc-fixtures.js";

// ─── Phase P6a — Auth-surface hardening ───────────────────────────────────────
// The top-level fetch wrapper (index.ts) runs the SAME OriginConfig as /mcp on the
// auth-surface paths the OAuthProvider routes BEFORE apiHandler. In the test runtime
// ALLOW_LOCALHOST is unset, so allowLocalhost defaults to FALSE (prod default).

describe("§P6a origin guard on the auth surface (finding 32)", () => {
  it("denies a foreign browser Origin on /authorize (403), before the provider routes it", async () => {
    const res = await SELF.fetch("http://localhost/authorize?response_type=code&client_id=x", {
      headers: { Origin: "https://evil.example.com" },
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "origin_not_allowed" });
  });

  it("denies a foreign Origin on /oauth/register and /oauth/token too", async () => {
    for (const path of ["/oauth/register", "/oauth/token"]) {
      const res = await SELF.fetch(`http://localhost${path}`, {
        method: "POST",
        headers: { Origin: "https://evil.example.com", "content-type": "application/json" },
        body: "{}",
      });
      expect(res.status).toBe(403);
    }
  });

  it("denies a localhost Origin on the auth surface when localhost is NOT env-gated on (finding 20)", async () => {
    // ALLOW_LOCALHOST unset => allowLocalhost defaults to false (prod) => localhost is denied.
    const res = await SELF.fetch("http://localhost/authorize?response_type=code&client_id=x", {
      headers: { Origin: "http://localhost:5173" },
    });
    expect(res.status).toBe(403);
  });

  it("does NOT origin-guard public paths: /health passes through even with a foreign Origin", async () => {
    const res = await SELF.fetch("http://localhost/health", { headers: { Origin: "https://evil.example.com" } });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, service: "servicenow-codemode-mcp" });
  });

  it("an absent Origin (non-browser client) is allowed on the auth surface", async () => {
    // No Origin header => not a browser cross-origin call => the wrapper lets it reach the
    // provider. The OAuth metadata endpoint is the cleanest no-side-effect proof it routed.
    const res = await SELF.fetch("http://localhost/.well-known/oauth-authorization-server");
    expect(res.status).toBe(200);
  });

  it("serves path-scoped OAuth authorization metadata for /mcp clients", async () => {
    const root = await SELF.fetch("http://localhost/.well-known/oauth-authorization-server");
    const scoped = await SELF.fetch("http://localhost/.well-known/oauth-authorization-server/mcp");
    expect(scoped.status).toBe(200);
    expect(await scoped.json()).toEqual(await root.json());
  });

  it("rate-limits dynamic client registration per source IP before the provider consumes the body", async () => {
    const ip = "203.0.113.188";
    for (let i = 0; i < 30; i++) {
      const res = await SELF.fetch("http://localhost/oauth/register", {
        method: "POST",
        headers: { "CF-Connecting-IP": ip, "content-type": "application/json" },
        body: "{}",
      });
      expect(res.status).not.toBe(429);
    }
    const denied = await SELF.fetch("http://localhost/oauth/register", {
      method: "POST",
      headers: { "CF-Connecting-IP": ip, "content-type": "application/json" },
      body: "{\"client_name\":\"still unread by limiter\"}",
    });
    expect(denied.status).toBe(429);
    expect(await denied.json()).toEqual({ error: "rate_limited" });
  });

  it("a SAME-origin POST /authorize is allowed (not 403) under default config (finding 34)", async () => {
    // The worker's OWN browser consent POST has Origin === the worker's host. Same-origin is
    // not the cross-origin threat DNS-rebinding/CSRF defends against, so it must pass the guard
    // even with empty ALLOWED_ORIGINS and allowLocalhost defaulting to FALSE. (Request host is
    // `localhost`; same-origin uses the matching `http://localhost`, distinct from the
    // localhost-with-port case above which is treated cross-origin and denied.)
    const res = await SELF.fetch("http://localhost/authorize", {
      method: "POST",
      headers: { Origin: "http://localhost", "content-type": "application/x-www-form-urlencoded" },
      body: "consent=x&operator_secret=y",
    });
    expect(res.status).not.toBe(403);
  });
});

describe("authenticated /mcp identity", () => {
  it("requires a non-empty string userId before building handler identity", () => {
    expect(authenticatedUserId({ userId: "u1" })).toBe("u1");
    expect(authenticatedUserId({})).toBeUndefined();
    expect(authenticatedUserId({ userId: "" })).toBeUndefined();
    expect(authenticatedUserId({ userId: "   " })).toBeUndefined();
    expect(authenticatedUserId({ userId: 123 })).toBeUndefined();
  });
});

// ─── §P6a signed/stored consent state (finding 22) ────────────────────────────
// The consent POST binds the granted scope to SERVER-SIDE state (OAUTH_KV under a
// server-minted nonce), never re-parsing a client-controlled hidden field. A tampered
// hidden field claiming a wider scope cannot widen the grant.

interface OAuthKvEnv {
  OAUTH_KV: KVNamespace;
}
const KV = (env as unknown as OAuthKvEnv).OAUTH_KV;

/** A fake OAuthProvider helper that records what scope completeAuthorization was given. */
function fakeProvider(authRequest: {
  clientId: string;
  scope: string[];
  codeChallenge?: string | null;
  codeChallengeMethod?: string | null;
}) {
  const seen: { userId?: string; scope?: string[]; props?: unknown } = {};
  const helper = {
    parseAuthRequest: async () => {
      const codeChallenge = authRequest.codeChallenge === null ? undefined : authRequest.codeChallenge ?? "cc";
      const codeChallengeMethod = authRequest.codeChallengeMethod === null ? undefined : authRequest.codeChallengeMethod ?? "S256";
      return {
        responseType: "code",
        clientId: authRequest.clientId,
        redirectUri: "https://client.example/cb",
        scope: authRequest.scope,
        state: "st-1",
        ...(codeChallenge !== undefined ? { codeChallenge } : {}),
        ...(codeChallengeMethod !== undefined ? { codeChallengeMethod } : {}),
      };
    },
    lookupClient: async () => ({ clientName: "Test Client" }),
    completeAuthorization: async (opts: { userId: string; scope: string[]; props: unknown }) => {
      seen.userId = opts.userId;
      seen.scope = opts.scope;
      seen.props = opts.props;
      return { redirectTo: "https://client.example/cb?code=abc" };
    },
  };
  return { helper, seen };
}

const SECRET = "operator-secret-value";
const OPERATOR_USER_ID = "test-operator";

// Operator-secret /authorize env. `provider` varies per test; overrides tweak one field (a
// specific CONSENT_RATE_DO, operator metadata, or `CONSENT_RATE_DO: undefined` to omit it).
type ConsentEnv = Parameters<typeof serviceNowAuthHandler.fetch>[1];
function consentEnv(provider: ReturnType<typeof fakeProvider>, overrides: Partial<ConsentEnv> = {}): ConsentEnv {
  return { OAUTH_PROVIDER: provider.helper as never, MCP_OPERATOR_SECRET: SECRET, OAUTH_KV: KV, CONSENT_RATE_DO: fakeRateDo([]).ns, ...overrides };
}

async function getConsent(provider: ReturnType<typeof fakeProvider>): Promise<{ nonce: string; status: number }> {
  const res = await serviceNowAuthHandler.fetch(
    new Request("http://localhost/authorize?response_type=code&client_id=c1"),
    consentEnv(provider),
  );
  const html = await res.text();
  const m = /name="consent" value="([^"]+)"/.exec(html);
  return { nonce: m![1]!, status: res.status };
}

function postConsent(fields: Record<string, string>, provider: ReturnType<typeof fakeProvider>): Promise<Response> {
  const form = new URLSearchParams(fields);
  return serviceNowAuthHandler.fetch(
    new Request("http://localhost/authorize", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    }),
    consentEnv(provider, { MCP_OPERATOR_USER_ID: OPERATOR_USER_ID }),
  );
}

/** Fake CONSENT_RATE_DO namespace whose stub.allow() returns a scripted sequence. */
function fakeRateDo(allowResults: boolean[]) {
  const calls: string[] = [];
  let i = 0;
  const ns = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: unknown) => ({
      allow: async (key: string, _now: number) => {
        calls.push(key);
        return allowResults[i++] ?? true;
      },
    }),
  };
  return { calls, ns: ns as never };
}

function fakeAuthDo(seed?: Iterable<[string, OidcCorrelationRecord]>) {
  const records = new Map(seed);
  const consentRecords = new Map<string, OidcConsentRecord>();
  const ns = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: unknown) => ({
      createOidcRecord: async (state: string, record: OidcCorrelationRecord) => {
        records.set(state, record);
      },
      consumeOidcRecord: async (state: string) => {
        const record = records.get(state) ?? null;
        records.delete(state);
        return record;
      },
      createOidcConsentRecord: async (nonce: string, record: OidcConsentRecord) => {
        consentRecords.set(nonce, record);
      },
      consumeOidcConsentRecord: async (nonce: string) => {
        const record = consentRecords.get(nonce) ?? null;
        consentRecords.delete(nonce);
        return record;
      },
    }),
  };
  return { records, consentRecords, ns: ns as never };
}

describe("finding 4 — consent-write admission cap on GET /authorize", () => {
  it("429s (and does NOT mint a consent nonce) when the limiter denies", async () => {
    const provider = fakeProvider({ clientId: "flooder", scope: ["servicenow:read"] });
    const rate = fakeRateDo([false]);
    const res = await serviceNowAuthHandler.fetch(
      new Request("http://localhost/authorize?response_type=code&client_id=flooder", {
        headers: { "CF-Connecting-IP": "203.0.113.7" },
      }),
      consentEnv(provider, { CONSENT_RATE_DO: rate.ns }),
    );
    expect(res.status).toBe(429);
    expect(await res.text()).not.toContain('name="consent"'); // no consent page minted
    expect(rate.calls).toEqual(["203.0.113.7"]); // keyed by SOURCE IP only (not client_id)
  });

  it("passes through (200 + consent nonce) when the limiter allows", async () => {
    const provider = fakeProvider({ clientId: "c1", scope: ["servicenow:read"] });
    const rate = fakeRateDo([true]);
    const res = await serviceNowAuthHandler.fetch(
      new Request("http://localhost/authorize?response_type=code&client_id=c1"),
      consentEnv(provider, { CONSENT_RATE_DO: rate.ns }),
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toContain('name="consent"');
  });

  it("fails closed when the consent limiter binding is missing", async () => {
    const provider = fakeProvider({ clientId: "c1", scope: ["servicenow:read"] });
    const res = await serviceNowAuthHandler.fetch(
      new Request("http://localhost/authorize?response_type=code&client_id=c1"),
      consentEnv(provider, { CONSENT_RATE_DO: undefined }),
    );
    expect(res.status).toBe(429);
    expect(await res.text()).not.toContain('name="consent"');
  });

  it("rejects an unknown OAuth client with 400 BEFORE consulting the limiter", async () => {
    const provider = fakeProvider({ clientId: "ghost", scope: ["servicenow:read"] });
    provider.helper.lookupClient = (async () => null) as never; // unknown client
    const rate = fakeRateDo([true]);
    const res = await serviceNowAuthHandler.fetch(
      new Request("http://localhost/authorize?response_type=code&client_id=ghost"),
      consentEnv(provider, { CONSENT_RATE_DO: rate.ns }),
    );
    expect(res.status).toBe(400);
    expect(rate.calls).toEqual([]); // limiter never consulted for an unknown client
  });
});

describe("AUTH-002 — MCP OAuth authorization requires PKCE S256", () => {
  it("rejects operator-secret authorization when S256 is declared without a code_challenge", async () => {
    const provider = fakeProvider({ clientId: "c1", scope: ["servicenow:read"], codeChallenge: null, codeChallengeMethod: "S256" });
    const res = await serviceNowAuthHandler.fetch(
      new Request("http://localhost/authorize?response_type=code&client_id=c1"),
      consentEnv(provider),
    );
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("PKCE S256");
    expect(provider.seen.scope).toBeUndefined();
  });

  it("rejects operator-secret authorization using a non-S256 PKCE method", async () => {
    const provider = fakeProvider({ clientId: "c1", scope: ["servicenow:read"], codeChallenge: "cc", codeChallengeMethod: "plain" });
    const res = await serviceNowAuthHandler.fetch(
      new Request("http://localhost/authorize?response_type=code&client_id=c1"),
      consentEnv(provider),
    );
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("PKCE S256");
  });

  it("rejects OIDC authorization without a code_challenge before creating IdP state", async () => {
    const provider = fakeProvider({ clientId: "oidc-client", scope: ["servicenow:read"], codeChallenge: null, codeChallengeMethod: "S256" });
    const authDo = fakeAuthDo();
    const res = await serviceNowAuthHandler.fetch(
      new Request("http://localhost/authorize?response_type=code&client_id=oidc-client"),
      {
        OAUTH_PROVIDER: provider.helper as never,
        AUTH_MODE: "oidc",
        AUTH_DO: authDo.ns,
        CONSENT_RATE_DO: fakeRateDo([]).ns,
        WORKER_PUBLIC_ORIGIN: "https://worker.example.com",
        OIDC_ISSUER,
        OIDC_CLIENT_ID,
        OIDC_CLIENT_SECRET,
        fetchImpl: fakeOidcFetch(),
      },
    );
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("PKCE S256");
    expect(authDo.records.size).toBe(0);
  });
});

describe("Phase 3 OIDC authorization surface", () => {
  it("redirects /authorize to the IdP and stores the original MCP auth request server-side", async () => {
    const provider = fakeProvider({ clientId: "oidc-client", scope: ["servicenow:read", "email"] });
    const authDo = fakeAuthDo();
    const res = await serviceNowAuthHandler.fetch(
      new Request("http://localhost/authorize?response_type=code&client_id=oidc-client"),
      {
        OAUTH_PROVIDER: provider.helper as never,
        AUTH_MODE: "oidc",
        AUTH_DO: authDo.ns,
        CONSENT_RATE_DO: fakeRateDo([]).ns,
        WORKER_PUBLIC_ORIGIN: "https://worker.example.com",
        OIDC_ISSUER,
        OIDC_CLIENT_ID,
        OIDC_CLIENT_SECRET,
        fetchImpl: fakeOidcFetch(),
      },
    );
    expect(res.status).toBe(302);
    const redirect = new URL(res.headers.get("location")!);
    expect(redirect.origin).toBe(OIDC_ISSUER);
    expect(redirect.searchParams.get("scope")).toBe("openid profile email offline_access");
    const state = redirect.searchParams.get("state")!;
    expect(authDo.records.get(state)).toMatchObject({
      grantedScopes: ["servicenow:read"],
      authRequest: { clientId: "oidc-client" },
    });
    expect(authDo.records.get(state)?.nonce).toBe(redirect.searchParams.get("nonce"));
  });

  it("does not accept operator-secret POST consent when AUTH_MODE=oidc", async () => {
    const provider = fakeProvider({ clientId: "oidc-client", scope: ["servicenow:read"] });
    const res = await serviceNowAuthHandler.fetch(
      new Request("http://localhost/authorize", { method: "POST" }),
      { OAUTH_PROVIDER: provider.helper as never, AUTH_MODE: "oidc" },
    );
    expect(res.status).toBe(405);
  });

  it("requires local consent after /oidc/callback before completing authorization", async () => {
    const keys = await oidcSigner();
    const subject = "acct:u-oidc@example.com";
    const idToken = await oidcIdToken(keys.privateKey, { sub: subject, email: "u-oidc@example.com", groups: ["admins"], nonce: "nonce-1" });
    const provider = fakeProvider({ clientId: "oidc-client", scope: ["servicenow:admin_script"] });
    const record: OidcCorrelationRecord = {
      authRequest: await provider.helper.parseAuthRequest(new Request("http://localhost/authorize")),
      grantedScopes: ["servicenow:admin_script"],
      nonce: "nonce-1",
      pkceVerifier: "verifier-1",
      expiresAt: Date.now() + 60_000,
    };
    const authDo = fakeAuthDo([["state-1", record]]);
    const hEnv = {
      OAUTH_PROVIDER: provider.helper as never,
      AUTH_MODE: "oidc",
      AUTH_DO: authDo.ns,
      OAUTH_PROVIDER_SECRET: SECRET,
      WORKER_PUBLIC_ORIGIN: "https://worker.example.com",
      OIDC_ISSUER,
      OIDC_CLIENT_ID,
      OIDC_CLIENT_SECRET,
      OIDC_GROUP_POLICY_MAP: JSON.stringify({ admins: { maxMode: "admin_script", policy: "admin" } }),
      fetchImpl: fakeOidcFetch(keys.jwks, () => ({ id_token: idToken, refresh_token: "RT-oidc" })),
    };
    const res = await serviceNowAuthHandler.fetch(
      new Request("http://localhost/oidc/callback?code=code-1&state=state-1"),
      hEnv,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("content-security-policy")).toBe("frame-ancestors 'none'");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    const html = await res.text();
    const consentNonce = /name="oidc_consent" value="([^"]+)"/.exec(html)?.[1];
    expect(consentNonce).toBeTruthy();
    expect(provider.seen.scope).toBeUndefined();
    expect(authDo.records.has("state-1")).toBe(false);
    const storedConsent = authDo.consentRecords.get(consentNonce!)!;
    expect(storedConsent).toMatchObject({
      userId: expect.any(String),
      grantedScopes: ["servicenow:admin_script"],
      clientName: "Test Client",
    });
    expect(storedConsent.grantProps).not.toHaveProperty("oidcRefreshToken");
    expect(storedConsent.sealedOidcRefreshToken).toMatchObject({
      alg: "AES-256-GCM",
      ciphertext: expect.any(String),
    });
    expect(JSON.stringify(storedConsent)).not.toContain("RT-oidc");

    const post = await serviceNowAuthHandler.fetch(
      new Request("http://localhost/oidc/consent", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ oidc_consent: consentNonce! }).toString(),
      }),
      hEnv,
    );
    expect(post.status).toBe(302);
    expect(provider.seen.userId).not.toContain(":");
    expect(provider.seen.scope).toEqual(["servicenow:admin_script"]);
    expect(provider.seen.props).toMatchObject({
      userId: provider.seen.userId,
      oidcSubject: subject,
      maxMode: "admin_script",
      actorPolicyName: "admin",
      oidcRefreshToken: "RT-oidc",
    });

    const replay = await serviceNowAuthHandler.fetch(
      new Request("http://localhost/oidc/consent", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ oidc_consent: consentNonce! }).toString(),
      }),
      hEnv,
    );
    expect(replay.status).toBe(400);
  });
});

describe("§P6a signed/stored consent state (finding 22)", () => {
  it("GET stores the auth-request server-side and returns a nonce (no round-tripped oauth JSON)", async () => {
    const provider = fakeProvider({ clientId: "c1", scope: ["servicenow:read"] });
    const res = await serviceNowAuthHandler.fetch(
      new Request("http://localhost/authorize?response_type=code&client_id=c1"),
      consentEnv(provider),
    );
    expect(res.headers.get("content-security-policy")).toBe("frame-ancestors 'none'");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    const html = await res.text();
    expect(html).toContain('name="consent"');
    expect(html).not.toContain('name="oauth"'); // the client-controlled field is gone
  });

  it("denies consent when the auth request has no scopes instead of defaulting to read", async () => {
    const provider = fakeProvider({ clientId: "c1", scope: [] });
    const res = await serviceNowAuthHandler.fetch(
      new Request("http://localhost/authorize?response_type=code&client_id=c1"),
      consentEnv(provider),
    );
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("No supported ServiceNow OAuth scopes requested.");
    expect(provider.seen.scope).toBeUndefined();
  });

  it("denies consent when every requested scope is unsupported", async () => {
    const provider = fakeProvider({ clientId: "c1", scope: ["profile", "email"] });
    const res = await serviceNowAuthHandler.fetch(
      new Request("http://localhost/authorize?response_type=code&client_id=c1"),
      consentEnv(provider),
    );
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("No supported ServiceNow OAuth scopes requested.");
    expect(provider.seen.scope).toBeUndefined();
  });

  it("grants the GET-time scope from server state, IGNORING a tampered hidden field", async () => {
    // GET-time scope is read_only; a tampered POST tries to escalate to admin_script.
    const provider = fakeProvider({ clientId: "c1", scope: ["servicenow:read"] });
    const { nonce } = await getConsent(provider);
    const res = await postConsent(
      {
        consent: nonce,
        operator_secret: SECRET,
        // A would-be attacker re-adds the old field with a wider scope — it must be ignored.
        oauth: JSON.stringify({ clientId: "c1", scope: ["servicenow:admin_script"] }),
      },
      provider,
    );
    expect(res.status).toBe(302);
    expect(provider.seen.scope).toEqual(["servicenow:read"]); // server-state scope, not the tampered one
    expect((provider.seen.props as { maxMode?: string }).maxMode).toBe("read_only");
  });

  it("fails CLOSED on a missing/forged consent nonce (never trusts a client auth-request)", async () => {
    const provider = fakeProvider({ clientId: "c1", scope: ["servicenow:read"] });
    const res = await postConsent({ consent: "not-a-real-nonce", operator_secret: SECRET }, provider);
    expect(res.status).toBe(400);
    expect(provider.seen.scope).toBeUndefined(); // completeAuthorization never called
  });

  it("fails CLOSED when MCP_OPERATOR_USER_ID is not configured", async () => {
    const provider = fakeProvider({ clientId: "c1", scope: ["servicenow:read"] });
    const { nonce } = await getConsent(provider);
    const res = await serviceNowAuthHandler.fetch(
      new Request("http://localhost/authorize", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ consent: nonce, operator_secret: SECRET }).toString(),
      }),
      consentEnv(provider),
    );
    expect(res.status).toBe(500);
    expect(provider.seen.scope).toBeUndefined();
  });

  it("rate-limits operator-secret POST attempts after a consent nonce is minted", async () => {
    const provider = fakeProvider({ clientId: "c1", scope: ["servicenow:read"] });
    const { nonce } = await getConsent(provider);
    const rate = fakeRateDo([false]);
    const denied = await serviceNowAuthHandler.fetch(
      new Request("http://localhost/authorize", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", "CF-Connecting-IP": "203.0.113.9" },
        body: new URLSearchParams({ consent: nonce, operator_secret: "wrong" }).toString(),
      }),
      consentEnv(provider, { MCP_OPERATOR_USER_ID: OPERATOR_USER_ID, CONSENT_RATE_DO: rate.ns }),
    );
    expect(denied.status).toBe(429);
    expect(rate.calls).toEqual(["203.0.113.9"]);
    expect(provider.seen.scope).toBeUndefined();
  });

  it("a wrong operator secret re-renders with the SAME nonce (retry stays valid) and does not grant", async () => {
    const provider = fakeProvider({ clientId: "c1", scope: ["servicenow:read"] });
    const { nonce } = await getConsent(provider);
    const bad = await postConsent({ consent: nonce, operator_secret: "wrong" }, provider);
    expect(bad.status).toBe(401);
    expect(provider.seen.scope).toBeUndefined();
    // The nonce is NOT burned on failure: a correct retry still succeeds.
    const ok = await postConsent({ consent: nonce, operator_secret: SECRET }, provider);
    expect(ok.status).toBe(302);
    expect(provider.seen.scope).toEqual(["servicenow:read"]);
  });

  it("burns the consent nonce on success (single-use; replay denied)", async () => {
    const provider = fakeProvider({ clientId: "c1", scope: ["servicenow:read"] });
    const { nonce } = await getConsent(provider);
    expect((await postConsent({ consent: nonce, operator_secret: SECRET }, provider)).status).toBe(302);
    // Replaying the same nonce now fails closed (the KV entry was deleted).
    const replay = await postConsent({ consent: nonce, operator_secret: SECRET }, provider);
    expect(replay.status).toBe(400);
  });

  it("uses configured operator subject metadata without persisting authorization groups into the OAuth grant", async () => {
    const provider = fakeProvider({ clientId: "c1", scope: ["servicenow:admin_script"] });
    const get = await serviceNowAuthHandler.fetch(
      new Request("http://localhost/authorize?response_type=code&client_id=c1"),
      consentEnv(provider, {
        MCP_OPERATOR_USER_ID: "ada-operator",
        MCP_OPERATOR_EMAIL: "ada@example.com",
        MCP_OPERATOR_ACCESS_GROUPS: "mcp-admins, change-approvers",
      }),
    );
    const nonce = /name="consent" value="([^"]+)"/.exec(await get.text())![1]!;
    const form = new URLSearchParams({ consent: nonce, operator_secret: SECRET });
    const post = await serviceNowAuthHandler.fetch(
      new Request("http://localhost/authorize", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: form.toString(),
      }),
      consentEnv(provider, {
        MCP_OPERATOR_USER_ID: "ada-operator",
        MCP_OPERATOR_EMAIL: "ada@example.com",
        MCP_OPERATOR_ACCESS_GROUPS: "mcp-admins, change-approvers",
      }),
    );
    expect(post.status).toBe(302);
    expect(provider.seen.userId).toBe("ada-operator");
    expect(provider.seen.props).toMatchObject({
      userId: "ada-operator",
      email: "ada@example.com",
      maxMode: "admin_script",
    });
    expect((provider.seen.props as { accessGroups?: unknown }).accessGroups).toBeUndefined();
  });

  it("fails CLOSED (throws) when OAUTH_KV is unbound", async () => {
    const provider = fakeProvider({ clientId: "c1", scope: ["servicenow:read"] });
    await expect(
      serviceNowAuthHandler.fetch(
        new Request("http://localhost/authorize?response_type=code&client_id=c1"),
        { OAUTH_PROVIDER: provider.helper as never, MCP_OPERATOR_SECRET: SECRET }, // no OAUTH_KV
      ),
    ).rejects.toThrow(MissingOAuthKvError);
  });
});
