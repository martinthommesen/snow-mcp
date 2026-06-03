// Shared mock OpenID-Connect IdP for the OIDC tests (oidc.test.ts, auth-surface.test.ts).
// A single source for the signer, ID-token minter, and discovery/JWKS/token fetch stub so the
// mock IdP contract is defined once. The discovery doc includes `userinfo_endpoint`; flows that
// never call userinfo simply ignore it.

import { exportJWK, generateKeyPair, SignJWT } from "jose";

export const OIDC_ISSUER = "https://idp.example.com";
export const OIDC_CLIENT_ID = "mcp-client";
export const OIDC_CLIENT_SECRET = "client-secret";

export async function oidcSigner() {
  const { publicKey, privateKey } = await generateKeyPair("RS256", { extractable: true });
  const jwk = await exportJWK(publicKey);
  return {
    privateKey,
    jwks: { keys: [{ ...jwk, kid: "k1", alg: "RS256", use: "sig" }] },
  };
}

export async function oidcIdToken(privateKey: CryptoKey, claims: Record<string, unknown>) {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: "k1" })
    .setIssuer(OIDC_ISSUER)
    .setAudience(OIDC_CLIENT_ID)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);
}

export function fakeOidcFetch(jwks: unknown = { keys: [] }, tokenResponse: () => unknown = () => ({})): typeof fetch {
  return (async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url === `${OIDC_ISSUER}/.well-known/openid-configuration`) {
      return Response.json({
        issuer: OIDC_ISSUER,
        authorization_endpoint: `${OIDC_ISSUER}/authorize`,
        token_endpoint: `${OIDC_ISSUER}/token`,
        jwks_uri: `${OIDC_ISSUER}/jwks`,
        userinfo_endpoint: `${OIDC_ISSUER}/userinfo`,
      });
    }
    if (url === `${OIDC_ISSUER}/jwks`) return Response.json(jwks);
    if (url === `${OIDC_ISSUER}/token`) return Response.json(tokenResponse());
    return new Response("unexpected url", { status: 404 });
  }) as typeof fetch;
}
