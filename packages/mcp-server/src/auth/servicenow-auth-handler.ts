// MCP-client OAuth consent handler (plan §2.4, §1.1). The OAuthProvider routes all
// non-/mcp requests here. We implement /authorize as a single-operator consent: the
// operator proves identity with a pre-shared secret (MCP_OPERATOR_SECRET), and the
// granted OAuth scopes (servicenow:read|write|admin_script) become props.maxMode, which
// the authorization cap (§2.0.1) enforces. /health is served here too.
//
// This secures the endpoint (no valid token -> the provider returns 401 on /mcp) and is
// scriptable for verification (the consent is a form POST, not a mandatory browser UI).

import type { Mode } from "@servicenow-codemode/shared";

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
}

const SUPPORTED_SCOPES = ["servicenow:read", "servicenow:write", "servicenow:admin_script"] as const;

function maxModeFromScopes(scopes: string[]): Mode {
  if (scopes.includes("servicenow:admin_script")) return "admin_script";
  if (scopes.includes("servicenow:write")) return "write";
  return "read_only";
}

/** Granted scopes = requested ∩ supported, defaulting to read when none requested. */
function grantScopes(requested: string[]): string[] {
  const g = requested.filter((s) => (SUPPORTED_SCOPES as readonly string[]).includes(s));
  return g.length > 0 ? g : ["servicenow:read"];
}

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

function consentPage(oauth: AuthRequestInfo, clientName: string, error?: string): Response {
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
  <input type="hidden" name="oauth" value='${esc(JSON.stringify(oauth))}'>
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
      if (request.method === "GET") {
        const oauth = await env.OAUTH_PROVIDER.parseAuthRequest(request);
        const client = await env.OAUTH_PROVIDER.lookupClient(oauth.clientId);
        return consentPage(oauth, client?.clientName ?? "", undefined);
      }
      if (request.method === "POST") {
        const form = await request.formData();
        const oauth = JSON.parse(String(form.get("oauth") ?? "{}")) as AuthRequestInfo;
        const secret = String(form.get("operator_secret") ?? "");
        const expected = env.MCP_OPERATOR_SECRET ?? "";
        // Fail closed: no configured secret => never authorize.
        if (!expected || secret.length !== expected.length || !timingSafeEqual(secret, expected)) {
          return consentPage(oauth, "", "Invalid operator secret.");
        }
        const scope = grantScopes(oauth.scope);
        const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
          request: oauth,
          userId: "operator",
          metadata: { via: "operator-secret" },
          scope,
          props: { userId: "operator", scopes: scope, maxMode: maxModeFromScopes(scope) },
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
