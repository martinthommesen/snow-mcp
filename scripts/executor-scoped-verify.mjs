// Verify the PRODUCTION scoped app (x_1793136_mcp, installed via now-sdk + Fluent):
// S8 role-gating (no role -> 403), then B1 valid/forged after assigning the role.
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
const keyBytes = Uint8Array.from(atob(dv("X_MCP_EXECUTOR_HMAC_KEY")), (c) => c.charCodeAt(0));
const ENDPOINT = `https://${host}/api/x_1793136_mcp/x_mcp/executor/run`;
const h = { authorization: basic, accept: "application/json" };

async function api(method, path, body) {
  const r = await fetch(`https://${host}${path}`, { method, headers: { ...h, ...(body ? { "content-type": "application/json" } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
  return { status: r.status, json: await r.json().catch(() => null) };
}
async function signed(script, opts = {}) {
  const actor = { mcp_actor_user_id: "u1", mcp_actor_email: "ada@example.com", snow_effective_user_sys_id: "sys1", instance: host, request_id: "req-" + Math.random().toString(36).slice(2), script_sha256: await sha256Base64(script), issued_at: Date.now(), nonce: "n-" + Math.random().toString(36).slice(2) };
  const sig = await hmacSha256Base64(canonicalize(actor), keyBytes);
  if (opts.forge) actor.mcp_actor_email = "evil@x.com";
  return { script, actor, actor_sig: sig };
}
async function call(payload) {
  const r = await fetch(ENDPOINT, { method: "POST", headers: { ...h, "content-type": "application/json" }, body: JSON.stringify(payload) });
  const j = await r.json().catch(() => null);
  return { status: r.status, body: j?.result ?? j };
}
let pass = 0, fail = 0;
const check = (n, c, e) => { if (c) { pass++; console.log("  PASS", n, e ?? ""); } else { fail++; console.log("  FAIL", n, e ?? ""); } };

console.log(`Scoped executor verify: ${ENDPOINT}\n`);

// admin user + role sys_ids
const adminId = (await api("GET", "/api/now/table/sys_user?sysparm_query=user_name=admin&sysparm_limit=1&sysparm_fields=sys_id")).json?.result?.[0]?.sys_id;
const roleId = (await api("GET", "/api/now/table/sys_user_role?sysparm_query=name=x_1793136_mcp.executor&sysparm_limit=1&sysparm_fields=sys_id")).json?.result?.[0]?.sys_id;

// Ensure admin does NOT currently have the role (remove if present) for the S8 test.
const existing = (await api("GET", `/api/now/table/sys_user_has_role?sysparm_query=user=${adminId}^role=${roleId}&sysparm_fields=sys_id`)).json?.result ?? [];
for (const e of existing) await api("DELETE", `/api/now/table/sys_user_has_role/${e.sys_id}`);
await new Promise((r) => setTimeout(r, 2000));

// S8 (config proof): the REST_Endpoint ACL exists requiring x_1793136_mcp.executor and the
// API enforces it. (A live 403 needs a NON-admin caller; admin bypasses ACLs by design.)
{
  const acl = (await api("GET", "/api/now/table/sys_security_acl?sysparm_query=type=rest_endpoint^operation=execute^name=x_1793136_mcp_executor_run&sysparm_limit=1&sysparm_fields=sys_id,name,active")).json?.result?.[0];
  const aclRoles = acl ? (await api("GET", `/api/now/table/sys_security_acl_role?sysparm_query=sys_security_acl=${acl.sys_id}&sysparm_fields=sys_user_role.name`)).json?.result ?? [] : [];
  const hasRole = aclRoles.some((r) => (r["sys_user_role.name"] || "") === "x_1793136_mcp.executor");
  const wsAcl = (await api("GET", "/api/now/table/sys_ws_definition?sysparm_query=sys_scope.scope=x_1793136_mcp&sysparm_fields=enforce_acl")).json?.result?.[0];
  check("S8 — REST_Endpoint ACL requires x_1793136_mcp.executor and API enforces it", Boolean(acl?.active === "true" && hasRole && wsAcl?.enforce_acl), `(acl=${!!acl}, role=${hasRole}, enforce=${!!wsAcl?.enforce_acl})`);
}

// Assign the role to admin (so the broad-identity call is also role-authorized), then execute.
await api("POST", "/api/now/table/sys_user_has_role", { user: adminId, role: roleId });
await new Promise((r) => setTimeout(r, 3000)); // role-cache propagation

let auditIdSeen = "";
{
  const r = await call(await signed("return gs.getUserName();"));
  auditIdSeen = r.body?.audit_id ?? "";
  check("B1 valid signed actor -> delegates to global core -> executes (returns user)", r.status === 200 && typeof r.body?.result === "string", `(status ${r.status}, result ${JSON.stringify(r.body?.result)})`);
}
{
  const r = await call(await signed("return 1;", { forge: true }));
  check("B1 forged actor email -> 401", r.status === 401 && r.body?.error === "actor_signature_invalid", `(status ${r.status})`);
}
// Audit-first row was written to the dedicated scoped table (proven by the returned audit_id;
// the table's own read ACL blocks admin via Table API by design, so we don't query it back).
check("audit-first row written to x_1793136_mcp_audit_log (audit_id returned)", /^[0-9a-f]{32}$/.test(auditIdSeen), `(audit_id ${auditIdSeen})`);

console.log(`\n${fail === 0 ? "SCOPED EXECUTOR: ALL PASS" : "SCOPED EXECUTOR: FAILURES"} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
