// End-to-end test of the DEPLOYED, OAuth-SECURED Worker via a real MCP client.
// Proves: (a) unauthenticated /mcp -> 401; (b) full OAuth dance (DCR + PKCE + operator
// consent) yields a token; (c) authenticated run_code -> Worker Loader sandbox ->
// ServiceNowRPC -> LIVE ServiceNow; (d) sandbox network isolation (S1).
import { readFileSync } from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const BASE = process.argv[2] ?? "https://servicenow-mcp.lammesen.workers.dev";

function devVar(key) {
  for (const raw of readFileSync(".dev.vars", "utf8").split("\n")) {
    const l = raw.trim();
    if (l.startsWith(`${key}=`)) { let v = l.slice(key.length + 1).trim(); return v.startsWith('"') ? v.slice(1, -1) : v; }
  }
  return undefined;
}
const OPERATOR_SECRET = devVar("MCP_OPERATOR_SECRET");

const b64url = (buf) => Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
async function pkce() {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
  return { verifier, challenge };
}

// P6a: GET /authorize with the standard snake_case OAuth query params, then scrape the
// server-minted nonce from the hidden field `name="consent" value="…"` in the returned HTML.
// `scope` is space-joined per the OAuth metadata convention.
async function getConsentNonce({ clientId, redirectUri, scope, state, challenge }) {
  const q = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: scope.join(" "),
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  const res = await fetch(`${BASE}/authorize?${q}`);
  const html = await res.text();
  const m = /name="consent" value="([^"]+)"/.exec(html);
  if (!m) throw new Error(`no consent nonce from GET /authorize (status ${res.status})`);
  return m[1];
}

let pass = 0, fail = 0;
const check = (n, c) => { if (c) { pass++; console.log("  PASS", n); } else { fail++; console.log("  FAIL", n); } };

// (a) unauthenticated /mcp -> 401
{
  const r = await fetch(`${BASE}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) });
  check("unauthenticated /mcp returns 401 (endpoint secured)", r.status === 401);
}

// (b) OAuth dance: register client (DCR) -> authorize (operator consent) -> token
async function getToken(scopes) {
  const redirectUri = "http://localhost/callback";
  const reg = await fetch(`${BASE}/oauth/register`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ redirect_uris: [redirectUri], token_endpoint_auth_method: "none", client_name: "e2e" }),
  });
  const client = await reg.json();
  const clientId = client.client_id;
  const { verifier, challenge } = await pkce();
  const state = b64url(crypto.getRandomValues(new Uint8Array(8)));

  // P6a consent is two steps: GET /authorize mints a server-side nonce rendered as a hidden
  // field name="consent"; POST sends { consent: <nonce>, operator_secret }. The GET uses the
  // STANDARD snake_case OAuth query params (parsed by OAuthProvider.parseAuthRequest), then we
  // scrape the nonce from the HTML and POST it (mirrors getConsent/postConsent in the tests).
  const nonce = await getConsentNonce({ clientId, redirectUri, scope: scopes, state, challenge });
  const form = new URLSearchParams({ consent: nonce, operator_secret: OPERATOR_SECRET ?? "" });
  const consent = await fetch(`${BASE}/authorize`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form, redirect: "manual" });
  const loc = consent.headers.get("location");
  if (!loc) throw new Error(`no redirect from /authorize (status ${consent.status})`);
  const code = new URL(loc).searchParams.get("code");

  const tok = await fetch(`${BASE}/oauth/token`, {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: clientId, code_verifier: verifier }),
  });
  const tj = await tok.json();
  return tj.access_token;
}

const token = await getToken(["servicenow:read"]);
check("OAuth dance (DCR + PKCE + operator consent) issues a token", typeof token === "string" && token.length > 0);

// (c)/(d) authenticated MCP client
const transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`), { requestInit: { headers: { authorization: `Bearer ${token}` } } });
const mcp = new Client({ name: "deployed-e2e", version: "0.1.0" });
await mcp.connect(transport);

const { tools } = await mcp.listTools();
check("3 tools present (authenticated)", tools.map((t) => t.name).sort().join(",") === "describe_table,list_tables,run_code");

const lt = await mcp.callTool({ name: "list_tables", arguments: { filter: "incident" } });
check("list_tables finds incident (live)", /"name":"incident"/.test(lt.content?.[0]?.text ?? ""));

const rc = await mcp.callTool({ name: "run_code", arguments: { code: `async () => { const r = await servicenow.tableQuery({ table: "incident", limit: 1, fields: ["number"] }); return r.rows[0]?.number ?? null; }` } });
console.log("  run_code result:", rc.content?.[0]?.text, "(isError:", rc.isError, ")");
check("run_code sandbox -> live ServiceNow returns an INC number", /INC\d+/.test(rc.content?.[0]?.text ?? "") && !rc.isError);

const iso = await mcp.callTool({ name: "run_code", arguments: { code: `async () => { let b=false; try { await fetch("https://example.com/"); } catch { b=true; } return b; }` } });
check("S1 sandbox network isolation holds on deployed Worker", (iso.content?.[0]?.text ?? "") === "true");

// read_only scope cannot escalate to write (B4 at the wire level)
const esc = await mcp.callTool({ name: "run_code", arguments: { code: `async () => 1`, mode: "write" } });
check("B4 read_only-scoped client cannot request write (mode_not_permitted)", esc.isError === true && (esc.structuredContent?.code === "mode_not_permitted"));

// THE FULL CHAIN: admin_script run_code -> sandbox -> runServerScript -> SIGNED actor
// -> x_mcp executor (verifies + executes) -> result, all through the deployed Worker.
{
  const adminToken = await getToken(["servicenow:admin_script"]);
  const at = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`), { requestInit: { headers: { authorization: `Bearer ${adminToken}` } } });
  const admin = new Client({ name: "e2e-admin", version: "0.1.0" });
  await admin.connect(at);
  const rs = await admin.callTool({
    name: "run_code",
    arguments: {
      code: `async () => { const r = await servicenow.runServerScript({ script: "return gs.getUserName();", reason: "e2e", idempotencyKey: "k" + Date.now() }); return r; }`,
      mode: "admin_script", reason: "e2e admin_script executor proof",
    },
  });
  const text = rs.content?.[0]?.text ?? "";
  console.log("  admin_script runServerScript result:", text.slice(0, 120), "(isError:", rs.isError, ")");
  check("FULL CHAIN: admin_script -> runServerScript -> x_mcp executor returns a value", !rs.isError && /admin/.test(text));
  await admin.close();
}

await mcp.close();

// S13 (live, subset) — OAuth-negative properties on the deployed provider.
async function registerClient() {
  const r = await fetch(`${BASE}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: ["http://localhost/callback"], token_endpoint_auth_method: "none" }) });
  return (await r.json()).client_id;
}
async function authorize(clientId, challenge, secret) {
  // Two-step P6a consent: GET to mint+scrape the nonce, then POST { consent, operator_secret }.
  const nonce = await getConsentNonce({ clientId, redirectUri: "http://localhost/callback", scope: ["servicenow:read"], state: "s", challenge });
  return fetch(`${BASE}/authorize`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ consent: nonce, operator_secret: secret }), redirect: "manual" });
}
{
  const cid = await registerClient();
  const { challenge } = await pkce();
  const bad = await authorize(cid, challenge, "WRONG-SECRET");
  check("S13 — wrong operator secret yields no authorization code", bad.status !== 302 && !bad.headers.get("location"));
}
{
  const cid = await registerClient();
  const { challenge } = await pkce();
  const ok = await authorize(cid, challenge, OPERATOR_SECRET ?? "");
  const code = new URL(ok.headers.get("location")).searchParams.get("code");
  const tok = await fetch(`${BASE}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: "http://localhost/callback", client_id: cid, code_verifier: "wrong-verifier-deliberately-mismatched-xxxxxxxxx" }) });
  check("S13 — O4 wrong PKCE verifier rejected at token endpoint", tok.status >= 400);
}

console.log(`\n${fail === 0 ? "DEPLOYED E2E: ALL PASS" : "DEPLOYED E2E: FAILURES"} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
