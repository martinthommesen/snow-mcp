// Install + verify the x_mcp executor on the live instance (Phase 5; user-authorized).
// Global-scope adaptation of sn-executor-app/ (a proper scoped app ships via Studio).
//
// DEFAULT INSTALL (plan §P7 nonce-store fix): the GLOBAL x_mcp_verify HELPER + properties ONLY.
// NO TABLES are created here — ServiceNow blocks creating tables/indexes via the inbound Table API
// even for admin (sys_db_object/sys_dictionary/sys_index POST -> 403). The nonce store + its UNIQUE
// index + the purge job are OWNED BY THE SCOPED FLUENT APP (x_1793136_mcp_nonce), which now-sdk
// install deploys correctly (app-deploy creates tables+indexes the right way, bypassing the 403).
// The audit table is likewise the scoped x_1793136_mcp_audit_log (written by the scoped wrapper);
// no global code writes a global x_mcp_audit_log. The canonical request endpoint is the SCOPED
// Fluent role-ACL-gated REST (x_1793136_mcp), which does verify -> consume-nonce -> execute.
// HMAC key material is injected into the admin-installed global helper at install time so the
// executor role never needs read access to x_1793136_mcp.executor.hmac_secret.
//
// M-4 (2026-05-31): the previously opt-in global-REST endpoint (HMAC-only, NO role ACL) + its live
// self-test have been REMOVED from this installer. That surface reproduced the exact shape of the
// production incident (an un-ACL'd global executor endpoint) and is not the canonical path. This
// script now installs ONLY the global x_mcp_verify core + properties; the request endpoint is the
// scoped Fluent app (sn-executor-app/fluent), which ships the role-ACL-gated REST + nonce/audit
// tables. Verify the live executor with scripts/executor-scoped-verify.mjs.
//
//   node scripts/executor-install.mjs   # installs the global verify() core + properties only
import { existsSync, readFileSync } from "node:fs";
import { canonicalizeInstanceHost } from "../packages/mcp-server/dist/sn/url-allowlist.js";
import { readDevVarFromText } from "./deployed-e2e-origin.mjs";

const verifyScriptTemplate = readFileSync(new URL("../sn-executor-app/script-include/x_mcp_verify.js", import.meta.url), "utf8");
let cachedDevVarsText;

function dv(k) {
  if (process.env[k]) return process.env[k];
  if (cachedDevVarsText === undefined) {
    cachedDevVarsText = existsSync(".dev.vars") ? readFileSync(".dev.vars", "utf8") : "";
  }
  return readDevVarFromText(cachedDevVarsText, k);
}
// SSRF guard (S15 / finding 2): canonicalize the configured host against the ServiceNow
// allowlist BEFORE any credentialed fetch, so a tampered SNOW_INSTANCE_HOST (userinfo,
// private IP, off-allowlist domain) can't exfiltrate the admin Basic credential. Throws on a
// bad host before the first request below.
const host = canonicalizeInstanceHost(dv("SNOW_INSTANCE_HOST"), { allowedHostSuffixes: ["service-now.com"] });
// Table/index DDL (sys_db_object/sys_dictionary/sys_index) requires admin rights the ROPC
// service account usually lacks (it 403s on table creation). Allow an admin-credential
// OVERRIDE via env for the install run ONLY — not persisted to .dev.vars:
//   SNOW_ADMIN_USER=admin SNOW_ADMIN_PASS='...' node scripts/executor-install.mjs
const installUser = process.env.SNOW_ADMIN_USER || dv("SNOW_DEV_ROPC_USERNAME");
const installPass = process.env.SNOW_ADMIN_PASS || dv("SNOW_DEV_ROPC_PASSWORD");
const basic = "Basic " + Buffer.from(`${installUser}:${installPass}`).toString("base64");
const keyB64 = dv("X_MCP_EXECUTOR_HMAC_KEY");
const keyPrevB64 = dv("X_MCP_EXECUTOR_HMAC_KEY_PREV") || "";
const ADMIN_ROLE_NAME = "x_1793136_mcp.admin";

if (!keyB64) {
  throw new Error("X_MCP_EXECUTOR_HMAC_KEY is required so x_mcp_verify can be installed with isolated signing material.");
}

function renderVerifierScript() {
  const rendered = verifyScriptTemplate
    .replace("\"__X_MCP_EXECUTOR_HMAC_KEY__\"", JSON.stringify(keyB64))
    .replace("\"__X_MCP_EXECUTOR_HMAC_KEY_PREV__\"", JSON.stringify(keyPrevB64));
  if (
    rendered.includes("\"__X_MCP_EXECUTOR_HMAC_KEY__\"") ||
    rendered.includes("\"__X_MCP_EXECUTOR_HMAC_KEY_PREV__\"")
  ) {
    throw new Error("x_mcp_verify HMAC placeholders were not fully replaced.");
  }
  return rendered;
}

async function api(method, path, body) {
  const r = await fetch(`https://${host}${path}`, {
    method, headers: { authorization: basic, accept: "application/json", ...(body ? { "content-type": "application/json" } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const j = await r.json().catch(() => null);
  return { status: r.status, json: j, result: j?.result };
}
async function apiOk(method, path, body) {
  const res = await api(method, path, body);
  if (res.status < 200 || res.status >= 300) {
    throw new Error(`${method} ${path} failed with HTTP ${res.status}`);
  }
  return res;
}
const log = (...a) => console.log(" ", ...a);

async function setProperty(name, value, type = "string") {
  const ex = (await api("GET", `/api/now/table/sys_properties?sysparm_query=name=${name}&sysparm_limit=1&sysparm_fields=sys_id`)).result?.[0];
  if (ex) { await api("PATCH", `/api/now/table/sys_properties/${ex.sys_id}`, { value }); return "updated"; }
  await api("POST", "/api/now/table/sys_properties", { name, value, type }); return "created";
}
function fieldText(row, name) {
  const value = row?.[name];
  if (value && typeof value === "object") return String(value.value ?? value.display_value ?? "");
  return String(value ?? "");
}
function hasTruthyField(row, names) {
  return names.some((name) => ["true", "1", "yes"].includes(fieldText(row, name).toLowerCase()));
}
function roleFieldIsAdminOnly(row, field, adminRoleId) {
  const roles = fieldText(row, field).split(/[,\s]+/).map((token) => token.trim()).filter(Boolean);
  if (roles.length === 0) return false;
  return roles.every((role) => role === adminRoleId || role === ADMIN_ROLE_NAME);
}
async function adminRoleId() {
  const query = encodeURIComponent(`name=${ADMIN_ROLE_NAME}`);
  const role = (await apiOk("GET", `/api/now/table/sys_user_role?sysparm_query=${query}&sysparm_limit=1&sysparm_fields=sys_id,name`)).result?.[0];
  if (!role?.sys_id) throw new Error(`Required role ${ADMIN_ROLE_NAME} is missing; install the scoped Fluent app before running executor-install.mjs.`);
  return String(role.sys_id);
}
async function requiredScopedHmacProperty(name, adminRoleSysId) {
  const query = encodeURIComponent(`name=${name}`);
  const row = (await apiOk(
    "GET",
    `/api/now/table/sys_properties?sysparm_query=${query}&sysparm_limit=1&sysparm_fields=sys_id,name,type,is_private,private,read_roles,write_roles`,
  )).result?.[0];
  if (!row?.sys_id) {
    throw new Error(`Required scoped HMAC property ${name} is missing; install the scoped Fluent app before running executor-install.mjs.`);
  }
  const typeOk = fieldText(row, "type") === "password2";
  const privateOk = hasTruthyField(row, ["is_private", "private"]);
  const readOk = roleFieldIsAdminOnly(row, "read_roles", adminRoleSysId);
  const writeOk = roleFieldIsAdminOnly(row, "write_roles", adminRoleSysId);
  if (!typeOk || !privateOk || !readOk || !writeOk) {
    throw new Error(`Refusing to update ${name}: expected password2, private, admin-only read/write metadata.`);
  }
  return row.sys_id;
}
async function updateRequiredHmacProperty(name, value, adminRoleSysId) {
  const sysId = await requiredScopedHmacProperty(name, adminRoleSysId);
  await apiOk("PATCH", `/api/now/table/sys_properties/${sysId}`, { value });
  return "updated";
}
// NOTE: ensureTable/ensureColumn/ensureUniqueIndex are intentionally GONE — the SCOPED Fluent app
// owns the nonce table + its UNIQUE index + the purge job (now-sdk deploys them; the Table API
// 403s on DDL even for admin). This installer creates NO tables.
async function ensureScriptInclude(name, script) {
  const ex = (await api("GET", `/api/now/table/sys_script_include?sysparm_query=name=${name}&sysparm_limit=1&sysparm_fields=sys_id`)).result?.[0];
  const body = { name, api_name: `global.${name}`, script, active: "true", access: "public", client_callable: "false" };
  if (ex) { await api("PATCH", `/api/now/table/sys_script_include/${ex.sys_id}`, body); return "updated"; }
  await api("POST", "/api/now/table/sys_script_include", body); return "created";
}

console.log(`Installing x_mcp executor on ${host}\n`);
const hmacAdminRoleId = await adminRoleId();

// 1) Properties (scoped-aligned namespace x_1793136_mcp.executor.*, plan §P7 item 5)
log("hmac_secret:", await updateRequiredHmacProperty("x_1793136_mcp.executor.hmac_secret", keyB64, hmacAdminRoleId));
log("hmac_secret_prev:", await updateRequiredHmacProperty("x_1793136_mcp.executor.hmac_secret_prev", keyPrevB64, hmacAdminRoleId));
// Break-glass toggles RE-ARM OFF on every (re)install/upgrade run (force-set, not keep-if-exists):
// a kill-switch must not persist "on" across a deploy. An operator re-enables it deliberately after
// install; executor-scoped-verify.mjs enables + restores only within its own verify window.
log("enabled:", await setProperty("x_1793136_mcp.executor.enabled", "false", "true|false"));
log("run_server_script_enabled:", await setProperty("x_1793136_mcp.executor.run_server_script_enabled", "false", "true|false"));
log("max_bytes:", await setProperty("x_1793136_mcp.executor.max_bytes", "32768", "integer"));
log("max_output_bytes:", await setProperty("x_1793136_mcp.executor.max_output_bytes", "65536", "integer"));

// 2) NO TABLES. The Table API 403s on DDL (sys_db_object/sys_dictionary/sys_index POST) even for
// admin, so we create NO tables here. The nonce store (x_1793136_mcp_nonce) + its UNIQUE index +
// the purge job, and the audit log (x_1793136_mcp_audit_log), are OWNED BY THE SCOPED FLUENT APP
// (now-sdk install deploys them — see sn-executor-app/fluent/src/fluent/x_mcp.now.ts). The scoped
// wrapper consumes the nonce in-scope; this global core only reads scoped audit/nonce rows to prove
// the wrapper path ran before eval.

// 3) Script Include (the global verify()/execute() core for scoped delegation). The installed
// script contains the current/previous HMAC key literals; rotate by rerunning this installer.
log("x_mcp_verify script include:", await ensureScriptInclude("x_mcp_verify", renderVerifierScript()));

console.log(
  "\nHelper install complete (x_mcp_verify core + properties; NO tables, NO global REST endpoint — " +
    "the scoped Fluent app owns the nonce+audit tables AND the role-ACL-gated REST endpoint). " +
    "Request endpoint is the scoped Fluent REST; verify it with scripts/executor-scoped-verify.mjs.",
);
process.exit(0);
