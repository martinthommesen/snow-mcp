import { describe, expect, it } from "vitest";
import { SignJWT } from "jose";
import {
  discoverOidc,
  oidcAccessTokenProps,
  oidcAuthorizationCodeTokenResult,
  oidcPropsFromClaims,
  oidcPropsFromCode,
  refreshOidcGrantProps,
  type OidcEnv,
} from "../src/auth/oidc.js";
import {
  OIDC_ISSUER as ISSUER,
  OIDC_CLIENT_ID as CLIENT_ID,
  OIDC_CLIENT_SECRET as CLIENT_SECRET,
  oidcSigner as signer,
  oidcIdToken as idToken,
  fakeOidcFetch as fakeFetch,
} from "./oidc-fixtures.js";

const GROUP_MAP = JSON.stringify({
  admins: { maxMode: "admin_script", policy: "admin" },
  writers: { maxMode: "write", policy: "writer" },
  readers: { maxMode: "read_only", policy: "reader" },
});

function envWithFetch(fetchImpl: typeof fetch): OidcEnv {
  return {
    AUTH_MODE: "oidc",
    WORKER_PUBLIC_ORIGIN: "https://worker.example.com",
    OIDC_ISSUER: ISSUER,
    OIDC_CLIENT_ID: CLIENT_ID,
    OIDC_CLIENT_SECRET: CLIENT_SECRET,
    OIDC_GROUP_POLICY_MAP: GROUP_MAP,
    fetchImpl,
  };
}

describe("Phase 3 OIDC identity projection", () => {
  it("rejects cleartext OIDC issuers before discovery", async () => {
    let called = false;
    await expect(
      discoverOidc({
        ...envWithFetch(async () => {
          called = true;
          return Response.json({});
        }),
        OIDC_ISSUER: "http://idp.example.com",
      }),
    ).rejects.toThrow(/https/i);
    expect(called).toBe(false);
  });

  it("rejects discovery metadata with cleartext endpoints", async () => {
    await expect(
      discoverOidc(envWithFetch(async () => Response.json({
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: "http://idp.example.com/token",
        jwks_uri: `${ISSUER}/jwks`,
      }))),
    ).rejects.toThrow(/https/i);
  });

  it("times out a hung OIDC discovery request", async () => {
    await expect(
      discoverOidc({
        ...envWithFetch((async (_input: RequestInfo | URL, init?: RequestInit) =>
          new Promise<Response>((_resolve, reject) => {
            init?.signal?.addEventListener("abort", () => reject(new Error("aborted by timeout")));
          })) as typeof fetch),
        OIDC_HTTP_TIMEOUT_MS: "1",
      }),
    ).rejects.toThrow(/aborted|timeout/i);
  });

  it("caches discovery and JWKS metadata within one OIDC env", async () => {
    const keys = await signer();
    const token = await idToken(keys.privateKey, { sub: "u-cache", groups: ["admins"], nonce: "nonce-1" });
    let discoveryCalls = 0;
    let jwksCalls = 0;
    const upstream = fakeFetch(keys.jwks, () => ({ id_token: token, refresh_token: "RT-cache" }));
    const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === `${ISSUER}/.well-known/openid-configuration`) discoveryCalls++;
      if (url === `${ISSUER}/jwks`) jwksCalls++;
      return upstream(input, init);
    }) as typeof fetch;

    const env = envWithFetch(fetchImpl);
    await oidcPropsFromCode(env, "code-1", "verifier-1", "nonce-1", ["servicenow:admin_script"]);
    expect(discoveryCalls).toBe(1);
    expect(jwksCalls).toBe(1);
  });

  it("evicts failed discovery cache entries so the next login can retry", async () => {
    let discoveryCalls = 0;
    const env = envWithFetch((async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === `${ISSUER}/.well-known/openid-configuration`) {
        discoveryCalls++;
        if (discoveryCalls === 1) return new Response("temporary outage", { status: 503 });
      }
      return fakeFetch()(input);
    }) as typeof fetch);

    await expect(discoverOidc(env)).rejects.toThrow(/503/);
    await expect(discoverOidc(env)).resolves.toMatchObject({ issuer: ISSUER });
    expect(discoveryCalls).toBe(2);
  });

  it("rejects token endpoint redirects without reposting the OIDC client secret", async () => {
    let tokenPostInit: RequestInit | undefined;
    const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === `${ISSUER}/.well-known/openid-configuration`) {
        return Response.json({
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          jwks_uri: `${ISSUER}/jwks`,
        });
      }
      if (url === `${ISSUER}/token`) {
        tokenPostInit = init;
        return new Response(null, {
          status: 307,
          headers: { location: "https://evil.example.com/token" },
        });
      }
      return new Response("unexpected url", { status: 404 });
    }) as typeof fetch;

    await expect(
      oidcPropsFromCode(envWithFetch(fetchImpl), "code-1", "verifier-1", "nonce-1", ["servicenow:read"]),
    ).rejects.toThrow(/307|token endpoint/i);
    expect(tokenPostInit?.redirect).toBe("manual");
    expect(String(tokenPostInit?.body)).toContain("client_secret=client-secret");
  });

  it("mins MCP scope with group policy and selects the named ActorPolicy", () => {
    const { grantProps, accessTokenProps } = oidcPropsFromClaims(
      envWithFetch(fetch),
      { sub: "u1", email: "ada@example.com", email_verified: true, groups: ["admins"] },
      ["servicenow:write"],
      "RT1",
    );
    expect(grantProps).toMatchObject({
      userId: "oidc-u1",
      oidcSubject: "u1",
      email: "ada@example.com",
      maxMode: "write",
      actorPolicyName: "admin",
      authMode: "oidc",
      oidcRefreshToken: "RT1",
    });
    expect(accessTokenProps).not.toHaveProperty("oidcRefreshToken");
  });

  it("omits unverified OIDC email claims from grant props", () => {
    const { grantProps, accessTokenProps } = oidcPropsFromClaims(
      envWithFetch(fetch),
      { sub: "u-unverified", email: "spoofable@example.com", email_verified: false, groups: ["writers"] },
      ["servicenow:write"],
      "RT1",
    );
    expect(grantProps).not.toHaveProperty("email");
    expect(accessTokenProps).not.toHaveProperty("email");
  });

  it("normalizes OIDC group policy names the same way production posture does", () => {
    const env = {
      ...envWithFetch(fetch),
      OIDC_DEFAULT_POLICY_NAME: " backup ",
      OIDC_GROUP_POLICY_MAP: JSON.stringify({
        admins: { maxMode: "write", policy: " admin " },
        readers: { maxMode: "read_only", policy: 123 },
        writers: "write",
      }),
    };
    expect(oidcPropsFromClaims(env, { sub: "u-admin", groups: ["admins"] }, ["servicenow:write"]).grantProps.actorPolicyName).toBe("admin");
    expect(oidcPropsFromClaims(env, { sub: "u-reader", groups: ["readers"] }, ["servicenow:read"]).grantProps.actorPolicyName).toBe("backup");
    expect(oidcPropsFromClaims(env, { sub: "u-writer", groups: ["writers"] }, ["servicenow:write"]).grantProps.actorPolicyName).toBe("backup");
  });

  it("rejects equally privileged groups that select different ActorPolicies", () => {
    const env = {
      ...envWithFetch(fetch),
      OIDC_GROUP_POLICY_MAP: JSON.stringify({
        teamA: { maxMode: "write", policy: "writer-a" },
        teamB: { maxMode: "write", policy: "writer-b" },
      }),
    };
    expect(() => oidcPropsFromClaims(env, { sub: "u-ambiguous", groups: ["teamA", "teamB"] }, ["servicenow:write"])).toThrow(
      /ambiguous/i,
    );
  });

  it("does not let prototype-named IdP groups inherit a wider policy", () => {
    const { grantProps } = oidcPropsFromClaims(
      { ...envWithFetch(fetch), OIDC_GROUP_POLICY_MAP: undefined },
      { sub: "u-proto", groups: ["hasOwnProperty", "__proto__", "constructor"] },
      ["servicenow:admin_script"],
      "RT1",
    );
    expect(grantProps.maxMode).toBe("read_only");
    expect(grantProps.actorPolicyName).toBe("default");
  });

  it("downscopes OIDC access-token props without narrowing the refresh grant", () => {
    const { grantProps } = oidcPropsFromClaims(
      envWithFetch(fetch),
      { sub: "u1", groups: ["admins"] },
      ["servicenow:admin_script"],
      "RT1",
    );
    const accessTokenProps = oidcAccessTokenProps(grantProps, ["servicenow:read"]);
    expect(grantProps.maxMode).toBe("admin_script");
    expect(accessTokenProps).toMatchObject({
      scopes: ["servicenow:read"],
      maxMode: "read_only",
    });
    expect(accessTokenProps).not.toHaveProperty("oidcRefreshToken");
  });

  it("disables provider refresh tokens when the upstream IdP issued no refresh token", () => {
    const withRefresh = oidcAuthorizationCodeTokenResult(
      { authMode: "oidc", userId: "oidc-u1", oidcSubject: "u1", maxMode: "write", oidcRefreshToken: "RT1" },
      ["servicenow:read"],
    );
    expect(withRefresh.refreshTokenTTL).toBeUndefined();

    const withoutRefresh = oidcAuthorizationCodeTokenResult(
      { authMode: "oidc", userId: "oidc-u1", oidcSubject: "u1", maxMode: "write" },
      ["servicenow:read"],
    );
    expect(withoutRefresh.refreshTokenTTL).toBe(0);
    expect(withoutRefresh.accessTokenProps.maxMode).toBe("read_only");
  });

  it("validates the signed ID token and nonce during authorization-code exchange", async () => {
    const keys = await signer();
    const token = await idToken(keys.privateKey, { sub: "u2", groups: ["admins"], nonce: "nonce-1" });
    const out = await oidcPropsFromCode(
      envWithFetch(fakeFetch(keys.jwks, () => ({ id_token: token, refresh_token: "RT2" }))),
      "code-1",
      "verifier-1",
      "nonce-1",
      ["servicenow:admin_script"],
    );
    expect(out.grantProps).toMatchObject({ userId: "oidc-u2", oidcSubject: "u2", maxMode: "admin_script", actorPolicyName: "admin" });
  });

  it("rejects an ID token whose nonce does not match the stored OIDC state", async () => {
    const keys = await signer();
    const token = await idToken(keys.privateKey, { sub: "u2", groups: ["admins"], nonce: "wrong" });
    await expect(
      oidcPropsFromCode(
        envWithFetch(fakeFetch(keys.jwks, () => ({ id_token: token, refresh_token: "RT2" }))),
        "code-1",
        "verifier-1",
        "nonce-1",
        ["servicenow:admin_script"],
      ),
    ).rejects.toThrow(/nonce/i);
  });

  it("refresh-time group changes downgrade maxMode and policy selection", async () => {
    const keys = await signer();
    const token = await idToken(keys.privateKey, { sub: "u3", groups: ["readers"] });
    const refreshed = await refreshOidcGrantProps(
      envWithFetch(fakeFetch(keys.jwks, () => ({ id_token: token, refresh_token: "RT3b" }))),
      { authMode: "oidc", userId: "oidc-u3", oidcSubject: "u3", oidcRefreshToken: "RT3a" },
      ["servicenow:admin_script"],
    );
    expect(refreshed?.grantProps).toMatchObject({
      userId: "oidc-u3",
      oidcSubject: "u3",
      maxMode: "read_only",
      actorPolicyName: "reader",
      oidcRefreshToken: "RT3b",
    });
    expect(refreshed?.accessTokenProps).not.toHaveProperty("oidcRefreshToken");
  });

  it("rejects refresh responses without a signed ID token instead of trusting userinfo groups", async () => {
    const keys = await signer();
    let userinfoCalls = 0;
    const upstream = fakeFetch(keys.jwks, () => ({ access_token: "AT-only", refresh_token: "RT4b" }));
    const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === `${ISSUER}/userinfo`) userinfoCalls++;
      return upstream(input, init);
    }) as typeof fetch;
    await expect(
      refreshOidcGrantProps(
        envWithFetch(fetchImpl),
        { authMode: "oidc", userId: "oidc-u4", oidcSubject: "u4", oidcRefreshToken: "RT4a" },
        ["servicenow:admin_script"],
      ),
    ).rejects.toThrow(/signed id_token/i);
    expect(userinfoCalls).toBe(0);
  });
});

describe("Phase 3 OIDC ID-token validation hardening (negative cases)", () => {
  // Mint a structurally-valid RS256 id_token, overriding exactly the one claim/field under test.
  // kid "k1" matches the fixture JWKS and nonce "n1" matches the exchange below, so the FIRST
  // failure is always the field being tested (jwtVerify checks iss/aud/exp/sig/alg before nonce).
  async function rs256Token(
    signingKey: CryptoKey,
    o: { sub?: string; iss?: string; aud?: string; expFromNow?: string } = {},
  ): Promise<string> {
    return new SignJWT({ sub: o.sub ?? "u-neg", groups: ["admins"], nonce: "n1" })
      .setProtectedHeader({ alg: "RS256", kid: "k1" })
      .setIssuer(o.iss ?? ISSUER)
      .setAudience(o.aud ?? CLIENT_ID)
      .setIssuedAt()
      .setExpirationTime(o.expFromNow ?? "5m")
      .sign(signingKey);
  }

  // Drive the real authorization-code path: exchangeOidcCode -> validateIdToken (jose.jwtVerify).
  function exchange(idTokenJwt: string, jwks: unknown): Promise<unknown> {
    return oidcPropsFromCode(
      envWithFetch(fakeFetch(jwks, () => ({ id_token: idTokenJwt, refresh_token: "RT" }))),
      "code-neg",
      "verifier-neg",
      "n1",
      ["servicenow:read"],
    );
  }

  it("rejects an ID token from the wrong issuer", async () => {
    const keys = await signer();
    const token = await rs256Token(keys.privateKey, { iss: "https://evil-idp.example.com" });
    await expect(exchange(token, keys.jwks)).rejects.toThrow();
  });

  it("rejects an ID token minted for a different audience", async () => {
    const keys = await signer();
    const token = await rs256Token(keys.privateKey, { aud: "some-other-client" });
    await expect(exchange(token, keys.jwks)).rejects.toThrow();
  });

  it("rejects an expired ID token beyond the clock-tolerance window", async () => {
    const keys = await signer();
    const token = await rs256Token(keys.privateKey, { expFromNow: "-5m" });
    await expect(exchange(token, keys.jwks)).rejects.toThrow();
  });

  it("rejects an ID token signed by a key absent from the IdP JWKS", async () => {
    const served = await signer();
    const attacker = await signer();
    // Signed by the attacker's key, but kid "k1" resolves to the genuine served JWKS key -> mismatch.
    const token = await rs256Token(attacker.privateKey);
    await expect(exchange(token, served.jwks)).rejects.toThrow();
  });

  it("rejects an unsigned (alg:none) ID token", async () => {
    const keys = await signer();
    const b64u = (obj: unknown) => btoa(JSON.stringify(obj)).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    const exp = Math.floor(Date.now() / 1000) + 300;
    const noneToken = `${b64u({ alg: "none", typ: "JWT" })}.${b64u({ iss: ISSUER, aud: CLIENT_ID, sub: "u", nonce: "n1", exp })}.`;
    await expect(exchange(noneToken, keys.jwks)).rejects.toThrow();
  });

  it("rejects an HS256 (algorithm-confusion) ID token", async () => {
    const keys = await signer();
    const hsToken = await new SignJWT({ sub: "u", nonce: "n1", groups: ["admins"] })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer(ISSUER)
      .setAudience(CLIENT_ID)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(new TextEncoder().encode("symmetric-confusion-secret-32-bytes-min!!"));
    await expect(exchange(hsToken, keys.jwks)).rejects.toThrow();
  });

  it("rejects an OIDC refresh whose id_token subject differs from the bound subject", async () => {
    const keys = await signer();
    const token = await idToken(keys.privateKey, { sub: "someone-else", groups: ["admins"] });
    await expect(
      refreshOidcGrantProps(
        envWithFetch(fakeFetch(keys.jwks, () => ({ id_token: token, refresh_token: "RT-new" }))),
        { authMode: "oidc", userId: "oidc-u-orig", oidcSubject: "u-orig", oidcRefreshToken: "RT-old" },
        ["servicenow:read"],
      ),
    ).rejects.toThrow(/subject changed/i);
  });

  it("falls back to read_only/default for an unmapped IdP group (least privilege)", () => {
    const { grantProps } = oidcPropsFromClaims(
      envWithFetch(fetch),
      { sub: "u-unmapped", groups: ["some-unmapped-team"] },
      ["servicenow:admin_script"],
    );
    expect(grantProps.maxMode).toBe("read_only");
    expect(grantProps.actorPolicyName).toBe("default");
  });
});
