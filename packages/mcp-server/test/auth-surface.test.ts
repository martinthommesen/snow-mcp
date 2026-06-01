import { SELF, env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { serviceNowAuthHandler } from "../src/auth/servicenow-auth-handler.js";
import { MissingOAuthKvError } from "../src/auth/oauth-kv.js";
import { authenticatedUserId } from "../src/index.js";

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
function fakeProvider(authRequest: { clientId: string; scope: string[] }) {
  const seen: { userId?: string; scope?: string[]; props?: unknown } = {};
  const helper = {
    parseAuthRequest: async () => ({
      responseType: "code",
      clientId: authRequest.clientId,
      redirectUri: "https://client.example/cb",
      scope: authRequest.scope,
      state: "st-1",
      codeChallenge: "cc",
      codeChallengeMethod: "S256",
    }),
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

async function getConsent(provider: ReturnType<typeof fakeProvider>): Promise<{ nonce: string; status: number }> {
  const res = await serviceNowAuthHandler.fetch(
    new Request("http://localhost/authorize?response_type=code&client_id=c1"),
    { OAUTH_PROVIDER: provider.helper as never, MCP_OPERATOR_SECRET: SECRET, OAUTH_KV: KV },
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
    { OAUTH_PROVIDER: provider.helper as never, MCP_OPERATOR_SECRET: SECRET, OAUTH_KV: KV, MCP_OPERATOR_USER_ID: OPERATOR_USER_ID },
  );
}

describe("§P6a signed/stored consent state (finding 22)", () => {
  it("GET stores the auth-request server-side and returns a nonce (no round-tripped oauth JSON)", async () => {
    const provider = fakeProvider({ clientId: "c1", scope: ["servicenow:read"] });
    const res = await serviceNowAuthHandler.fetch(
      new Request("http://localhost/authorize?response_type=code&client_id=c1"),
      { OAUTH_PROVIDER: provider.helper as never, MCP_OPERATOR_SECRET: SECRET, OAUTH_KV: KV },
    );
    const html = await res.text();
    expect(html).toContain('name="consent"');
    expect(html).not.toContain('name="oauth"'); // the client-controlled field is gone
  });

  it("denies consent when the auth request has no scopes instead of defaulting to read", async () => {
    const provider = fakeProvider({ clientId: "c1", scope: [] });
    const res = await serviceNowAuthHandler.fetch(
      new Request("http://localhost/authorize?response_type=code&client_id=c1"),
      { OAUTH_PROVIDER: provider.helper as never, MCP_OPERATOR_SECRET: SECRET, OAUTH_KV: KV },
    );
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("No supported ServiceNow OAuth scopes requested.");
    expect(provider.seen.scope).toBeUndefined();
  });

  it("denies consent when every requested scope is unsupported", async () => {
    const provider = fakeProvider({ clientId: "c1", scope: ["profile", "email"] });
    const res = await serviceNowAuthHandler.fetch(
      new Request("http://localhost/authorize?response_type=code&client_id=c1"),
      { OAUTH_PROVIDER: provider.helper as never, MCP_OPERATOR_SECRET: SECRET, OAUTH_KV: KV },
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
      { OAUTH_PROVIDER: provider.helper as never, MCP_OPERATOR_SECRET: SECRET, OAUTH_KV: KV },
    );
    expect(res.status).toBe(500);
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
      {
        OAUTH_PROVIDER: provider.helper as never,
        MCP_OPERATOR_SECRET: SECRET,
        OAUTH_KV: KV,
        MCP_OPERATOR_USER_ID: "ada-operator",
        MCP_OPERATOR_EMAIL: "ada@example.com",
        MCP_OPERATOR_ACCESS_GROUPS: "mcp-admins, change-approvers",
      },
    );
    const nonce = /name="consent" value="([^"]+)"/.exec(await get.text())![1]!;
    const form = new URLSearchParams({ consent: nonce, operator_secret: SECRET });
    const post = await serviceNowAuthHandler.fetch(
      new Request("http://localhost/authorize", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: form.toString(),
      }),
      {
        OAUTH_PROVIDER: provider.helper as never,
        MCP_OPERATOR_SECRET: SECRET,
        OAUTH_KV: KV,
        MCP_OPERATOR_USER_ID: "ada-operator",
        MCP_OPERATOR_EMAIL: "ada@example.com",
        MCP_OPERATOR_ACCESS_GROUPS: "mcp-admins, change-approvers",
      },
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
