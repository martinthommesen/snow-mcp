// Install + verify the x_mcp executor on the live instance (Phase 5; user-authorized).
// Global-scope adaptation of sn-executor-app/ (a proper scoped app ships via Studio).
// Creates: properties, x_mcp_audit_log + x_mcp_nonce tables, x_mcp_verify Script Include,
// and the executor Scripted REST endpoint. Then proves B1/S8/S9/B6 end-to-end.
//
//   node scripts/executor-install.mjs
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
  const j = await r.json().catch(() => null);
  return { status: r.status, json: j, result: j?.result };
}
const log = (...a) => console.log(" ", ...a);

async function setProperty(name, value, type = "string") {
  const ex = (await api("GET", `/api/now/table/sys_properties?sysparm_query=name=${name}&sysparm_limit=1&sysparm_fields=sys_id`)).result?.[0];
  if (ex) { await api("PATCH", `/api/now/table/sys_properties/${ex.sys_id}`, { value }); return "updated"; }
  await api("POST", "/api/now/table/sys_properties", { name, value, type }); return "created";
}
async function ensureTable(name, label) {
  const ex = (await api("GET", `/api/now/table/sys_db_object?sysparm_query=name=${name}&sysparm_limit=1&sysparm_fields=sys_id`)).result?.[0];
  if (ex) return "exists";
  const r = await api("POST", "/api/now/table/sys_db_object", { name, label });
  return `created(${r.status})`;
}
async function ensureColumn(table, element, internal_type, column_label, max_length) {
  const ex = (await api("GET", `/api/now/table/sys_dictionary?sysparm_query=name=${table}^element=${element}&sysparm_limit=1&sysparm_fields=sys_id`)).result?.[0];
  if (ex) return;
  await api("POST", "/api/now/table/sys_dictionary", { name: table, element, internal_type, column_label, max_length: String(max_length ?? 255) });
}
async function ensureScriptInclude(name, script) {
  const ex = (await api("GET", `/api/now/table/sys_script_include?sysparm_query=name=${name}&sysparm_limit=1&sysparm_fields=sys_id`)).result?.[0];
  const body = { name, api_name: `global.${name}`, script, active: "true", access: "public", client_callable: "false" };
  if (ex) { await api("PATCH", `/api/now/table/sys_script_include/${ex.sys_id}`, body); return "updated"; }
  await api("POST", "/api/now/table/sys_script_include", body); return "created";
}

// --- Script Include: x_mcp_verify (global scope) ---
const verifyScript = `var x_mcp_verify = Class.create();
x_mcp_verify.prototype = {
  FRESHNESS_MS: 120000,
  initialize: function() {},
  _asciiJsonString: function(s) {
    var out = '"';
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i);
      if (c === 0x22) out += '\\\\"';
      else if (c === 0x5c) out += '\\\\\\\\';
      else if (c < 0x20 || c >= 0x7f) { var h = c.toString(16); while (h.length < 4) h = '0' + h; out += '\\\\u' + h; }
      else out += s.charAt(i);
    }
    return out + '"';
  },
  _canonical: function(a) {
    var keys = ['mcp_actor_user_id','mcp_actor_email','snow_effective_user_sys_id','instance','request_id','script_sha256','issued_at','nonce'];
    var parts = [];
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i], v = a[k];
      var vs = (k === 'issued_at') ? String(v) : this._asciiJsonString(String(v == null ? '' : v));
      parts.push(this._asciiJsonString(k) + ':' + vs);
    }
    return '{' + parts.join(',') + '}';
  },
  _eq: function(a, b) { if (a.length !== b.length) return false; var d = 0; for (var i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; },
  verify: function(script, actor, sig) {
    if (!sig) return false;
    var expHash = new GlideDigest().getSHA256Base64(String(script || ''));
    if (expHash !== String(actor.script_sha256 || '')) return false;
    var now = new GlideDateTime().getNumericValue();
    var issued = parseInt(actor.issued_at, 10);
    if (isNaN(issued) || Math.abs(now - issued) > this.FRESHNESS_MS) return false;
    var canon = this._canonical(actor);
    var keyCur = gs.getProperty('x_mcp.executor.hmac_secret', '');
    var keyPrev = gs.getProperty('x_mcp.executor.hmac_secret_prev', '');
    var enc = new GlideCertificateEncryption();
    var ok = keyCur && this._eq(enc.generateMac(keyCur, 'HmacSHA256', canon), sig);
    if (!ok && keyPrev) ok = this._eq(enc.generateMac(keyPrev, 'HmacSHA256', canon), sig);
    if (!ok) return false;
    return this._consumeNonce(String(actor.nonce || ''));
  },
  _consumeNonce: function(nonce) {
    if (!nonce) return false;
    var ex = new GlideRecord('sys_user_preference'); ex.addQuery('name', 'x_mcp.nonce.' + nonce); ex.setLimit(1); ex.query();
    if (ex.next()) return false;
    var row = new GlideRecord('sys_user_preference'); row.initialize(); row.name = 'x_mcp.nonce.' + nonce; row.value = '1'; row.system = 'true'; return !!row.insert();
  },
  // GLOBAL core for scoped delegation (plan §0.13a): scoped apps cannot use new Function
  // or GlideCertificateEncryption, so the scoped executor calls global.x_mcp_verify.run().
  // Returns { verified, ok, error, serialized }. The scoped wrapper owns audit/kill-switch.
  run: function(code, actor, sig) {
    if (!this.verify(code, actor, sig)) return { verified: false };
    var result, err = null;
    try { var fn = new Function('gs','GlideRecord','GlideRecordSecure','GlideAggregate','"use strict";\\n' + code); result = fn(gs, GlideRecord, GlideRecordSecure, GlideAggregate); }
    catch (e) { err = String(e); }
    var serialized = null;
    try { serialized = JSON.stringify(result === undefined ? null : result); }
    catch (se) { err = err || ('unserializable: ' + String(se)); serialized = null; }
    return { verified: true, ok: !err, error: err, serialized: serialized };
  },
  type: 'x_mcp_verify'
};`;

// --- Executor Scripted REST operation script (global scope, §10) ---
// Audit -> syslog (JSON message). Production scoped app (update set) uses the dedicated
// x_mcp_audit_log + x_mcp_nonce tables; custom tables can't be created via Table API.
const execScript = `function utf8Len(s){var n=0;for(var i=0;i<s.length;i++){var c=s.charCodeAt(i);if(c<0x80)n+=1;else if(c<0x800)n+=2;else if(c>=0xD800&&c<=0xDBFF){n+=4;i++;}else n+=3;}return n;}
(function process(request, response) {
  var body = request.body.data || {};
  var code = String(body.script || '');
  var actor = body.actor || {};
  var sig = String(body.actor_sig || '');
  var start = new GlideDateTime();
  var ad = { snow_user: gs.getUserID(), snow_user_name: gs.getUserName(), mcp_actor_user_id: String(actor.mcp_actor_user_id || ''), mcp_actor_email: String(actor.mcp_actor_email || ''), request_id: String(actor.request_id || ''), actor_verified: false, code_hash: new GlideDigest().getSHA256Base64(code), code_size: utf8Len(code), status: 'running' };
  var audit = new GlideRecord('syslog'); audit.initialize(); audit.source = 'x_mcp.executor'; audit.level = 0; audit.message = JSON.stringify(ad);
  var auditId = audit.insert();
  if (!auditId) { response.setStatus(500); response.setBody({ error: 'audit_unavailable' }); return; }
  function close(st, extra){ ad.status = st; if (extra) for (var k in extra) ad[k] = extra[k]; ad.duration = (new GlideDateTime()).getNumericValue() - start.getNumericValue(); audit.message = JSON.stringify(ad); audit.update(); }
  if (!new x_mcp_verify().verify(code, actor, sig)) {
    close('rejected', { error_class: 'actor_signature_invalid' });
    response.setStatus(401); response.setBody({ error: 'actor_signature_invalid', audit_id: auditId + '' }); return;
  }
  ad.actor_verified = true;
  if (gs.getProperty('x_mcp.executor.enabled', 'true') !== 'true') { close('killed'); response.setStatus(503); response.setBody({ error: 'executor_disabled', audit_id: auditId + '' }); return; }
  if (gs.getProperty('x_mcp.executor.run_server_script_enabled', 'true') !== 'true') { close('killed', { error_class: 'egress_disabled' }); response.setStatus(503); response.setBody({ error: 'run_server_script_disabled', audit_id: auditId + '' }); return; }
  var maxB = parseInt(gs.getProperty('x_mcp.executor.max_bytes', '32768'), 10);
  var bytes = utf8Len(code);
  if (bytes === 0 || bytes > maxB) { close('error', { error_class: 'code_size' }); response.setStatus(413); response.setBody({ error: 'code_size', audit_id: auditId + '' }); return; }
  var result, err = null, status = 'ok';
  try { var fn = new Function('gs','GlideRecord','GlideRecordSecure','GlideAggregate','"use strict";\\n' + code); result = fn(gs, GlideRecord, GlideRecordSecure, GlideAggregate); }
  catch (e) { err = String(e); status = 'error'; }
  var serialized = null;
  try { serialized = JSON.stringify(result === undefined ? null : result); }
  catch (se) { err = err || ('unserializable: ' + String(se)); status = 'error'; serialized = null; }
  var maxOut = parseInt(gs.getProperty('x_mcp.executor.max_output_bytes', '65536'), 10);
  if (serialized && utf8Len(serialized) > maxOut) { if (status === 'ok') status = 'truncated'; close(status, { output_size: utf8Len(serialized), error_class: err ? err.split(':')[0] : '' }); response.setStatus(200); response.setBody({ ok: !err, result: null, result_sample: serialized.slice(0, maxOut), truncated: true, error: err, audit_id: auditId + '' }); return; }
  close(status, { output_size: serialized ? utf8Len(serialized) : 0, error_class: err ? err.split(':')[0] : '' });
  response.setStatus(err ? 500 : 200); response.setBody({ ok: !err, result: (err || serialized == null) ? null : JSON.parse(serialized), truncated: false, error: err, audit_id: auditId + '' });
})(request, response);`;

console.log(`Installing x_mcp executor on ${host}\n`);

// 1) Properties
log("hmac_secret:", await setProperty("x_mcp.executor.hmac_secret", keyB64, "password2"));
log("enabled:", await setProperty("x_mcp.executor.enabled", "true", "true|false"));
log("run_server_script_enabled:", await setProperty("x_mcp.executor.run_server_script_enabled", "true", "true|false"));
log("max_bytes:", await setProperty("x_mcp.executor.max_bytes", "32768", "integer"));
log("max_output_bytes:", await setProperty("x_mcp.executor.max_output_bytes", "65536", "integer"));

// 2) Tables + columns
log("x_mcp_audit_log table:", await ensureTable("x_mcp_audit_log", "MCP Audit Log"));
for (const [el, ty, lbl, ml] of [
  ["snow_user", "string", "SN User", 64], ["snow_user_name", "string", "SN User Name", 128],
  ["mcp_actor_user_id", "string", "MCP Actor", 128], ["mcp_actor_email", "string", "MCP Actor Email", 255],
  ["request_id", "string", "Request ID", 128], ["actor_verified", "boolean", "Actor Verified", 40],
  ["code_hash", "string", "Code Hash", 64], ["code_size", "integer", "Code Size", 40],
  ["started_at", "glide_date_time", "Started", 40], ["duration", "integer", "Duration", 40],
  ["status", "string", "Status", 40], ["output_size", "integer", "Output Size", 40], ["error_class", "string", "Error Class", 128],
]) await ensureColumn("x_mcp_audit_log", el, ty, lbl, ml);
log("x_mcp_nonce table:", await ensureTable("x_mcp_nonce", "MCP Nonce"));
await ensureColumn("x_mcp_nonce", "value", "string", "Value", 128);
await ensureColumn("x_mcp_nonce", "created", "glide_date_time", "Created", 40);

// 3) Script Include
log("x_mcp_verify script include:", await ensureScriptInclude("x_mcp_verify", verifyScript));

// 4) Scripted REST API + operation
let def = (await api("GET", "/api/now/table/sys_ws_definition?sysparm_query=service_id=x_mcp&sysparm_limit=1&sysparm_fields=sys_id")).result?.[0];
if (!def) { const r = await api("POST", "/api/now/table/sys_ws_definition", { name: "x_mcp", service_id: "x_mcp", short_description: "MCP executor" }); def = r.result; log("sys_ws_definition:", r.status); }
else log("sys_ws_definition: exists");
let op = (await api("GET", `/api/now/table/sys_ws_operation?sysparm_query=web_service_definition=${def.sys_id}^relative_path=/executor/run&sysparm_limit=1&sysparm_fields=sys_id`)).result?.[0];
const opBody = { web_service_definition: def.sys_id, name: "run", http_method: "POST", relative_path: "/executor/run", operation_script: execScript, active: "true", requires_authentication: "true", requires_acl_authorization: "false" };
if (!op) { const r = await api("POST", "/api/now/table/sys_ws_operation", opBody); op = r.result; log("sys_ws_operation:", r.status); }
else { await api("PATCH", `/api/now/table/sys_ws_operation/${op.sys_id}`, opBody); log("sys_ws_operation: updated"); }

console.log("\nInstall complete. Verifying...\n");
await new Promise((r) => setTimeout(r, 2500));

// ---- VERIFY (B1 / S8 / S9 / B6) ----
// Global-scope Scripted REST APIs get an auto-generated numeric namespace; use base_uri.
const defFull = (await api("GET", "/api/now/table/sys_ws_definition?sysparm_query=service_id=x_mcp&sysparm_limit=1&sysparm_fields=base_uri")).result?.[0];
const ENDPOINT = `https://${host}${defFull?.base_uri ?? "/api/x_mcp"}/executor/run`;
log("endpoint:", `${defFull?.base_uri}/executor/run`);
const keyBytes = Uint8Array.from(atob(keyB64), (c) => c.charCodeAt(0));
async function signed(script, opts = {}) {
  const actor = {
    mcp_actor_user_id: "u1", mcp_actor_email: "ada@example.com", snow_effective_user_sys_id: "sys1",
    instance: host, request_id: "req-" + Math.random().toString(36).slice(2),
    script_sha256: await sha256Base64(script), issued_at: Date.now(), nonce: opts.nonce ?? "n-" + Math.random().toString(36).slice(2),
  };
  let sig = await hmacSha256Base64(canonicalize(actor), keyBytes);
  if (opts.forgeEmail) actor.mcp_actor_email = "evil@x.com"; // tamper AFTER signing
  return { script, actor, actor_sig: opts.badSig ? "AAAA" : sig };
}
async function call(payload) {
  const r = await fetch(ENDPOINT, { method: "POST", headers: { authorization: basic, accept: "application/json", "content-type": "application/json" }, body: JSON.stringify(payload) });
  const j = await r.json().catch(() => null);
  // ServiceNow Scripted REST wraps setBody(obj) as { result: obj }.
  return { status: r.status, body: j?.result ?? j };
}

let pass = 0, fail = 0;
const check = (n, c, extra) => { if (c) { pass++; console.log("  PASS", n, extra ?? ""); } else { fail++; console.log("  FAIL", n, extra ?? ""); } };

// B1: valid signature -> executes, returns value
{
  const r = await call(await signed("return gs.getUserName();"));
  const v = r.body?.result;
  check("B1 valid signed actor -> executes server-side script", r.status === 200 && typeof v === "string" && v.length > 0, `(returned user "${v}", audit_id ${r.body?.audit_id})`);
}
// runServerScript reaches global table (cross-scope reach, S16-ish)
{
  const r = await call(await signed("var g=new GlideAggregate('incident');g.addAggregate('COUNT');g.query();g.next();return parseInt(g.getAggregate('COUNT'),10);"));
  check("cross-scope reach: GlideAggregate count on global incident", r.status === 200 && Number.isFinite(r.body?.result), `(count ${r.body?.result})`);
}
// B1 negative: forged email -> 401 rejected
{
  const r = await call(await signed("return 1;", { forgeEmail: true }));
  check("B1 forged actor email -> 401 actor_signature_invalid", r.status === 401 && r.body?.error === "actor_signature_invalid", `(status ${r.status})`);
}
// B1 negative: bad signature -> 401
{
  const r = await call(await signed("return 1;", { badSig: true }));
  check("B1 bad signature -> 401", r.status === 401);
}
// replay: same nonce twice -> second rejected (T8)
{
  const nonce = "replay-" + Math.random().toString(36).slice(2);
  const first = await call(await signed("return 1;", { nonce }));
  const second = await call(await signed("return 1;", { nonce }));
  check("nonce replay rejected (first ok, second 401)", first.status === 200 && second.status === 401, `(first ${first.status}, second ${second.status})`);
}
// B6: over-cap output -> valid truncated envelope (never a thrown JSON.parse)
{
  const r = await call(await signed("return new Array(100000).join('x');"));
  const ok = r.status === 200 && r.body?.truncated === true && r.body?.result === null && typeof r.body?.result_sample === "string" && r.body.result_sample.length > 0;
  check("B6 over-cap output -> { result:null, result_sample, truncated:true }", ok, `(truncated ${r.body?.truncated}, sample ${r.body?.result_sample?.length}b)`);
}
// S9: kill switch -> 503, then re-enable
{
  await setProperty("x_mcp.executor.enabled", "false");
  await new Promise((r) => setTimeout(r, 1500));
  const off = await call(await signed("return 1;"));
  await setProperty("x_mcp.executor.enabled", "true");
  await new Promise((r) => setTimeout(r, 1500));
  const on = await call(await signed("return 1;"));
  check("S9 kill switch: disabled -> 503, re-enabled -> 200", off.status === 503 && on.status === 200, `(off ${off.status}, on ${on.status})`);
}

console.log(`\n${fail === 0 ? "EXECUTOR: ALL PASS" : "EXECUTOR: FAILURES"} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
