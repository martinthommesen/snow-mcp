// MCP-client OAuth consent handler (plan §2.4, §1.1). The OAuthProvider routes all
// non-/mcp requests here. We implement /authorize as a single-operator consent: the
// operator proves identity with a pre-shared secret (MCP_OPERATOR_SECRET), and the
// granted OAuth scopes (servicenow:read|write|admin_script) become props.maxMode, which
// the authorization cap (§2.0.1) enforces. /health is served here too.
//
// This secures the endpoint (no valid token -> the provider returns 401 on /mcp) and is
// scriptable for verification (the consent is a form POST, not a mandatory browser UI).

import type { Mode } from "@servicenow-codemode/shared";
import { requireOAuthKv } from "./oauth-kv.js";

interface AuthRequestInfo {
  responseType: string;
  clientId: string;
  redirectUri: string;
  scope: string[];
  state: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  resource?: string | string[];
}

interface OAuthHelpersLike {
  parseAuthRequest(request: Request): Promise<AuthRequestInfo>;
  lookupClient(clientId: string): Promise<{ clientName?: string } | null>;
  completeAuthorization(opts: {
    request: AuthRequestInfo;
    userId: string;
    metadata: unknown;
    scope: string[];
    props: unknown;
  }): Promise<{ redirectTo: string }>;
}

interface HandlerEnv {
  OAUTH_PROVIDER: OAuthHelpersLike;
  MCP_OPERATOR_SECRET?: string;
  MCP_OPERATOR_USER_ID?: string;
  MCP_OPERATOR_EMAIL?: string;
  MCP_OPERATOR_ACCESS_GROUPS?: string;
  OAUTH_KV?: KVNamespace;
}

const SUPPORTED_SCOPES = ["servicenow:read", "servicenow:write", "servicenow:admin_script"] as const;

/** Server-side consent state lives in OAUTH_KV under this prefix, keyed by a server-minted
 *  nonce. Short TTL: a consent flow that isn't completed promptly is abandoned (plan §P6a). */
const CONSENT_KEY_PREFIX = "consent:";
const CONSENT_TTL_SECONDS = 600; // 10 minutes to complete the operator-secret consent.

function maxModeFromScopes(scopes: string[]): Mode {
  if (scopes.includes("servicenow:admin_script")) return "admin_script";
  if (scopes.includes("servicenow:write")) return "write";
  return "read_only";
}

/** Granted scopes = requested ∩ supported; empty intersections are denied. */
function grantScopes(requested: string[]): string[] {
  return requested.filter((s) => (SUPPORTED_SCOPES as readonly string[]).includes(s));
}

function unsupportedScopesResponse(): Response {
  return new Response("No supported ServiceNow OAuth scopes requested.", { status: 400 });
}

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

/** Render the consent page. The hidden field carries ONLY the server-minted `nonce` — the
 *  authoritative auth-request (scope/redirect/state) lives in OAUTH_KV under that nonce and
 *  is never round-tripped through the client (plan §P6a, finding 22). `oauth` is read from
 *  server state purely to DISPLAY the scopes being granted. */
function consentPage(oauth: AuthRequestInfo, clientName: string, nonce: string, error?: string): Response {
  const scopes = grantScopes(oauth.scope);
  const html = `<!doctype html><meta charset="utf-8"><title>Authorize MCP client</title>
<style>body{font:15px system-ui;max-width:34rem;margin:3rem auto;padding:0 1rem}
.s{background:#f4f4f5;border-radius:6px;padding:.5rem .75rem;margin:.25rem 0;font-family:monospace}
button{font:inherit;padding:.6rem 1rem;border:0;border-radius:6px;background:#2563eb;color:#fff;cursor:pointer}
.err{color:#b91c1c}</style>
<h2>Authorize MCP client</h2>
<p><b>${esc(clientName || oauth.clientId)}</b> is requesting access to the ServiceNow Code Mode MCP server.</p>
<p>Scopes to grant:</p>
${scopes.map((s) => `<div class="s">${esc(s)}</div>`).join("")}
${error ? `<p class="err">${esc(error)}</p>` : ""}
<form method="POST" action="/authorize">
  <input type="hidden" name="consent" value="${esc(nonce)}">
  <p><label>Operator secret<br><input type="password" name="operator_secret" autocomplete="off" style="width:100%;padding:.5rem"></label></p>
  <button type="submit">Approve</button>
</form>`;
  return new Response(html, { status: error ? 401 : 200, headers: { "content-type": "text/html; charset=utf-8" } });
}

export const serviceNowAuthHandler = {
  async fetch(request: Request, env: HandlerEnv): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return Response.json({ ok: true, service: "servicenow-codemode-mcp" });
    }

    if (url.pathname === "/authorize") {
      // OAUTH_KV holds the server-side consent state; a missing binding fails CLOSED here
      // (plan §P6a) rather than silently re-parsing a client-controlled field.
      const kv = requireOAuthKv(env);

      if (request.method === "GET") {
        const oauth = await env.OAUTH_PROVIDER.parseAuthRequest(request);
        if (grantScopes(oauth.scope).length === 0) return unsupportedScopesResponse();
        const client = await env.OAUTH_PROVIDER.lookupClient(oauth.clientId);
        // Bind the authoritative auth-request to server-side state under a server-minted nonce;
        // only the nonce is ever sent to the client. Scope can no longer be tampered between
        // GET (display/validate) and POST (grant) — the POST reads the stored object wholesale.
        const nonce = crypto.randomUUID();
        await kv.put(CONSENT_KEY_PREFIX + nonce, JSON.stringify(oauth), { expirationTtl: CONSENT_TTL_SECONDS });
        return consentPage(oauth, client?.clientName ?? "", nonce);
      }
      if (request.method === "POST") {
        const form = await request.formData();
        const nonce = String(form.get("consent") ?? "");
        // Look up the server-side state; a missing/expired/forged nonce fails CLOSED (never
        // trust a client-supplied auth-request). The stored object is the sole authority.
        const stored = nonce ? await kv.get(CONSENT_KEY_PREFIX + nonce) : null;
        if (!stored) return new Response("Invalid or expired consent request.", { status: 400 });
        const oauth = JSON.parse(stored) as AuthRequestInfo;
        const scope = grantScopes(oauth.scope);
        if (scope.length === 0) return unsupportedScopesResponse();

        const secret = String(form.get("operator_secret") ?? "");
        const expected = env.MCP_OPERATOR_SECRET ?? "";
        // Fail closed: no configured secret => never authorize. On a wrong secret, re-render
        // with the SAME nonce (do NOT delete the entry — its TTL keeps the retry valid).
        if (!expected || secret.length !== expected.length || !timingSafeEqual(secret, expected)) {
          return consentPage(oauth, "", nonce, "Invalid operator secret.");
        }
        // Single-use on success: burn the consent nonce so the grant can't be replayed.
        await kv.delete(CONSENT_KEY_PREFIX + nonce);
        const operatorUserId = env.MCP_OPERATOR_USER_ID?.trim();
        if (!operatorUserId) {
          return new Response("MCP_OPERATOR_USER_ID is required.", { status: 500 });
        }
        const operatorEmail = env.MCP_OPERATOR_EMAIL?.trim();
        const props = {
          userId: operatorUserId,
          scopes: scope,
          maxMode: maxModeFromScopes(scope),
          ...(operatorEmail ? { email: operatorEmail } : {}),
        };
        const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
          request: oauth,
          userId: operatorUserId,
          metadata: { via: "operator-secret" },
          scope,
          props,
        });
        return Response.redirect(redirectTo, 302);
      }
    }

    return new Response("Not found", { status: 404 });
  },
};

function timingSafeEqual(a: string, b: string): boolean {
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
