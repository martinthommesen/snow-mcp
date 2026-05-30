// B1 / Phase 0.13a proof: does ServiceNow's in-scope HMAC (GlideCertificateEncryption
// .generateMac) match the host signer (actor.ts) over the identical ASCII-canonical
// payload + key? Creates a minimal Scripted REST endpoint that returns the SN-side MAC,
// then compares. Read-ish: creates one config record set (user-approved instance writes).
import { readFileSync } from "node:fs";
import { canonicalize, hmacSha256Base64, sha256Base64 } from "../packages/mcp-server/dist/auth/actor.js";

function dv(k) {
  for (const l of readFileSync(".dev.vars", "utf8").split("\n")) {
    const t = l.trim();
    if (t.startsWith(`${k}=`)) { let v = t.slice(k.length + 1).trim(); return v.startsWith('"') ? v.slice(1, -1) : v; }
  }
}
const host = dv("SNOW_INSTANCE_HOST");
const basic = "Basic " + Buffer.from(`${dv("SNOW_DEV_ROPC_USERNAME")}:${dv("SNOW_DEV_ROPC_PASSWORD")}`).toString("base64");
const keyB64 = dv("X_MCP_EXECUTOR_HMAC_KEY");

async function api(method, path, body) {
  const r = await fetch(`https://${host}${path}`, {
    method, headers: { authorization: basic, accept: "application/json", ...(body ? { "content-type": "application/json" } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  return { status: r.status, json: await r.json().catch(() => null) };
}

// 1) Host side
const keyBytes = Uint8Array.from(atob(keyB64), (c) => c.charCodeAt(0));
const payload = { mcp_actor_user_id: "u1", mcp_actor_email: "André@x.com", snow_effective_user_sys_id: "sys1", instance: host, request_id: "req1", script_sha256: await sha256Base64("return 1;"), issued_at: 1700000000000, nonce: "n1" };
const canon = canonicalize(payload);
const hostHmac = await hmacSha256Base64(canon, keyBytes);
const hostSha = await sha256Base64("return 1;");

// 2) Set the in-scope key property (no value printed)
await api("POST", "/api/now/table/sys_properties", { name: "x_mcp.executor.hmac_secret", value: keyB64, type: "password2", description: "MCP executor actor-signing HMAC key (B1 proof)" })
  .then((r) => console.log(`set hmac_secret property -> HTTP ${r.status}`));

// 3) Create the Scripted REST API + resource (find-or-create)
let def = (await api("GET", "/api/now/table/sys_ws_definition?sysparm_query=service_id=x_mcp_b1&sysparm_limit=1&sysparm_fields=sys_id")).json?.result?.[0];
if (!def) {
  const created = await api("POST", "/api/now/table/sys_ws_definition", { name: "x_mcp_b1", service_id: "x_mcp_b1", short_description: "MCP B1 HMAC proof" });
  console.log(`create sys_ws_definition -> HTTP ${created.status}`);
  def = created.json?.result;
}
if (!def?.sys_id) { console.log("FAILED: no sys_ws_definition"); process.exit(1); }

const opScript = [
  "(function process(request, response) {",
  "  var key = gs.getProperty('x_mcp.executor.hmac_secret');",
  "  var data = request.body.data.canonical;",
  "  var script = request.body.data.script || '';",
  "  var mac = new GlideCertificateEncryption().generateMac(key, 'HmacSHA256', data);",
  "  var sha = new GlideDigest().getSHA256Base64(script);",
  "  response.setBody({ mac: mac, sha256: sha });",
  "})(request, response);",
].join("\n");

let op = (await api("GET", `/api/now/table/sys_ws_operation?sysparm_query=web_service_definition=${def.sys_id}^relative_path=/mac&sysparm_limit=1&sysparm_fields=sys_id`)).json?.result?.[0];
if (!op) {
  const created = await api("POST", "/api/now/table/sys_ws_operation", {
    web_service_definition: def.sys_id, name: "mac", http_method: "POST", relative_path: "/mac",
    operation_script: opScript, active: "true", requires_authentication: "true", requires_acl_authorization: "false",
  });
  console.log(`create sys_ws_operation -> HTTP ${created.status}`);
  op = created.json?.result;
}
if (!op?.sys_id) { console.log("FAILED: no sys_ws_operation"); process.exit(1); }

// 4) Call the endpoint and compare
await new Promise((r) => setTimeout(r, 1500)); // let the endpoint register
const call = await fetch(`https://${host}/api/x_mcp_b1/mac`, {
  method: "POST", headers: { authorization: basic, accept: "application/json", "content-type": "application/json" },
  body: JSON.stringify({ canonical: canon, script: "return 1;" }),
});
const cj = await call.json().catch(() => null);
console.log(`\nendpoint call -> HTTP ${call.status}`);
const snMac = cj?.result?.mac ?? cj?.mac;
const snSha = cj?.result?.sha256 ?? cj?.sha256;
console.log("  host HMAC:", hostHmac);
console.log("  SN   HMAC:", snMac);
console.log("  host SHA :", hostSha);
console.log("  SN   SHA :", snSha);

const macMatch = snMac === hostHmac;
const shaMatch = snSha === hostSha;
console.log(`\n  B1 HMAC match (cross-engine): ${macMatch}`);
console.log(`  script_sha256 match (UTF-8 digest): ${shaMatch}`);
console.log(`\n${macMatch && shaMatch ? "B1 PROOF: PASS — in-scope HMAC + SHA match the host signer." : "B1 PROOF: MISMATCH — investigate key/data encoding."}`);
process.exit(macMatch && shaMatch ? 0 : 1);
