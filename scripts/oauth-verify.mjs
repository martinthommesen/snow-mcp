// Register a test OAuth client on the instance (Table API, admin Basic Auth), then
// verify the REAL OAuth token flow (B9, §2.8): ROPC grant -> Bearer query -> refresh.
// Prints status only — never client_secret or tokens. Persists the generated
// client_id/secret to .dev.vars for reuse.
//
//   node scripts/oauth-verify.mjs
import { readFileSync, writeFileSync } from "node:fs";
import { canonicalServiceNowHost } from "./servicenow-host-guard.mjs";

const PATH = ".dev.vars";
function parse() {
  const out = {};
  for (const raw of readFileSync(PATH, "utf8").split("\n")) {
    const l = raw.trim();
    if (!l || l.startsWith("#")) continue;
    const i = l.indexOf("=");
    if (i < 0) continue;
    let v = l.slice(i + 1).trim();
    if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
    out[l.slice(0, i).trim()] = v;
  }
  return out;
}
function setVar(key, val) {
  const lines = readFileSync(PATH, "utf8").split("\n");
  let found = false;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].startsWith(`${key}=`)) { lines[i] = `${key}="${val}"`; found = true; break; }
  }
  if (!found) lines.push(`${key}="${val}"`);
  writeFileSync(PATH, lines.join("\n"));
}

const env = parse();
const host = canonicalServiceNowHost(env.SNOW_INSTANCE_HOST);
const user = env.SNOW_DEV_ROPC_USERNAME;
const pass = env.SNOW_DEV_ROPC_PASSWORD;
const basic = "Basic " + Buffer.from(`${user}:${pass}`).toString("base64");
const CLIENT_NAME = "mcp-codemode-test";

async function fetchJsonNoRedirect(url, init) {
  const res = await fetch(url, { ...init, redirect: "manual" });
  if (res.status >= 300 && res.status < 400) {
    throw new Error(`Refusing redirect from ${new URL(url).origin}`);
  }
  return { status: res.status, json: await res.json().catch(() => null), res };
}

async function table(method, path, body) {
  const { status, json } = await fetchJsonNoRedirect(`https://${host}${path}`, {
    method,
    headers: { authorization: basic, accept: "application/json", ...(body ? { "content-type": "application/json" } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  return { status, json };
}

console.log(`OAuth verify against ${host}\n`);

// 1) Find or create the test OAuth client.
let entity = (await table("GET", `/api/now/table/oauth_entity?sysparm_query=name=${CLIENT_NAME}&sysparm_limit=1&sysparm_fields=sys_id,client_id`)).json?.result?.[0];
if (!entity) {
  const created = await table("POST", "/api/now/table/oauth_entity", {
    name: CLIENT_NAME,
    type: "client",
    active: "true",
    access_token_lifespan: "1800",
    refresh_token_lifespan: "8640000",
  });
  console.log(`create oauth_entity -> HTTP ${created.status}`);
  entity = created.json?.result;
}
const sysId = entity?.sys_id;
const clientId = entity?.client_id ?? (await table("GET", `/api/now/table/oauth_entity?sysparm_query=name=${CLIENT_NAME}&sysparm_limit=1&sysparm_fields=client_id`)).json?.result?.[0]?.client_id;
if (!sysId || !clientId) { console.log("FAILED: no sys_id/client_id"); process.exit(1); }

// The Table API returns the ENCRYPTED-at-rest client_secret (a password2 field), which
// the token endpoint rejects. Set a KNOWN plaintext secret: ServiceNow encrypts it at
// rest and validates OAuth against the plaintext we now hold.
const clientSecret = "mcp_" + Buffer.from(crypto.getRandomValues(new Uint8Array(18))).toString("base64").replace(/[^a-zA-Z0-9]/g, "");
const patched = await table("PATCH", `/api/now/table/oauth_entity/${sysId}`, { client_secret: clientSecret });
console.log(`set known client_secret -> HTTP ${patched.status} (client_id length ${clientId.length})`);
if (patched.status >= 300) { console.log("FAILED: could not set client_secret"); process.exit(1); }

// Persist for reuse (gitignored .dev.vars).
setVar("SNOW_OAUTH_CLIENT_ID", clientId);
setVar("SNOW_OAUTH_CLIENT_SECRET", clientSecret);
console.log("saved SNOW_OAUTH_CLIENT_ID / SNOW_OAUTH_CLIENT_SECRET to .dev.vars");

// 2) ROPC grant (grant_type=password) — MFA-exempt dev path (§2.8).
async function tokenReq(params) {
  const { status, json } = await fetchJsonNoRedirect(`https://${host}/oauth_token.do`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams(params).toString(),
  });
  return { status, json };
}

const grant = await tokenReq({ grant_type: "password", client_id: clientId, client_secret: clientSecret, username: user, password: pass });
console.log(`\nROPC token grant -> HTTP ${grant.status}`);
const accessToken = grant.json?.access_token;
const refreshToken = grant.json?.refresh_token;
console.log(`  access_token returned: ${Boolean(accessToken)}`);
console.log(`  refresh_token returned (B9): ${Boolean(refreshToken)}`);
console.log(`  token_type: ${grant.json?.token_type}, expires_in: ${grant.json?.expires_in}`);
if (!accessToken) { console.log("FAILED: no access_token"); process.exit(1); }

// 3) Use the Bearer token against the Table API (proves the OAuth path end-to-end).
const { status: qStatus, json: qj } = await fetchJsonNoRedirect(`https://${host}/api/now/table/incident?sysparm_limit=1&sysparm_fields=number`, {
  headers: { authorization: `Bearer ${accessToken}`, accept: "application/json" },
});
console.log(`\nBearer query incident -> HTTP ${qStatus}; rows: ${qj?.result?.length ?? 0}; sample starts INC: ${String(qj?.result?.[0]?.number ?? "").startsWith("INC")}`);

// 4) Refresh-token rotation (B9).
if (refreshToken) {
  const refreshed = await tokenReq({ grant_type: "refresh_token", client_id: clientId, client_secret: clientSecret, refresh_token: refreshToken });
  console.log(`\nrefresh_token grant -> HTTP ${refreshed.status}`);
  console.log(`  new access_token: ${Boolean(refreshed.json?.access_token)}`);
  const newRefresh = refreshed.json?.refresh_token;
  console.log(`  refresh rotated: ${Boolean(newRefresh) && newRefresh !== refreshToken}`);
}

const ok = qStatus === 200 && Boolean(accessToken);
console.log(`\n${ok ? "OAUTH VERIFY: OK — confidential-client token flow works end-to-end." : "OAUTH VERIFY: FAILED"}`);
process.exit(ok ? 0 : 1);
