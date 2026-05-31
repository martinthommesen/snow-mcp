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
//
// M-4 (2026-05-31): the previously opt-in global-REST endpoint (HMAC-only, NO role ACL) + its live
// self-test have been REMOVED from this installer. That surface reproduced the exact shape of the
// production incident (an un-ACL'd global executor endpoint) and is not the canonical path. This
// script now installs ONLY the global x_mcp_verify core + properties; the request endpoint is the
// scoped Fluent app (sn-executor-app/fluent), which ships the role-ACL-gated REST + nonce/audit
// tables. Verify the live executor with scripts/executor-scoped-verify.mjs.
//
//   node scripts/executor-install.mjs   # installs the global verify() core + properties only
import { readFileSync } from "node:fs";

function dv(k) {
  for (const l of readFileSync(".dev.vars", "utf8").split("\n")) {
    const t = l.trim();
    if (t.startsWith(`${k}=`)) { let v = t.slice(k.length + 1).trim(); return v.startsWith('"') ? v.slice(1, -1) : v; }
  }
}
const host = dv("SNOW_INSTANCE_HOST");
// Table/index DDL (sys_db_object/sys_dictionary/sys_index) requires admin rights the ROPC
// service account usually lacks (it 403s on table creation). Allow an admin-credential
// OVERRIDE via env for the install run ONLY — not persisted to .dev.vars:
//   SNOW_ADMIN_USER=admin SNOW_ADMIN_PASS='...' node scripts/executor-install.mjs
const installUser = process.env.SNOW_ADMIN_USER || dv("SNOW_DEV_ROPC_USERNAME");
const installPass = process.env.SNOW_ADMIN_PASS || dv("SNOW_DEV_ROPC_PASSWORD");
const basic = "Basic " + Buffer.from(`${installUser}:${installPass}`).toString("base64");
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
// NOTE: ensureTable/ensureColumn/ensureUniqueIndex are intentionally GONE — the SCOPED Fluent app
// owns the nonce table + its UNIQUE index + the purge job (now-sdk deploys them; the Table API
// 403s on DDL even for admin). This installer creates NO tables.
async function ensureScriptInclude(name, script) {
  const ex = (await api("GET", `/api/now/table/sys_script_include?sysparm_query=name=${name}&sysparm_limit=1&sysparm_fields=sys_id`)).result?.[0];
  const body = { name, api_name: `global.${name}`, script, active: "true", access: "public", client_callable: "false" };
  if (ex) { await api("PATCH", `/api/now/table/sys_script_include/${ex.sys_id}`, body); return "updated"; }
  await api("POST", "/api/now/table/sys_script_include", body); return "created";
}

// --- Script Include: x_mcp_verify (GLOBAL scope) ---
// This IS the canonical global core (plan §P7) and the LIVE production verifier (D11). The class
// body MUST stay byte-consistent with sn-executor-app/script-include/x_mcp_verify.js: verify()
// (HMAC + script-bind + instance-claim + freshness; NO nonce, NO eval), execute() (new Function
// eval), run() (verify-then-execute back-compat). SINGLE-USE NONCE consumption is NOT here — the
// scoped wrapper owns it (INSERT-as-arbiter into the scoped x_1793136_mcp_nonce table). The nonce
// STAYS in the signed canonical (the HMAC still covers it); only its single-use INSERT moved.
// Properties are read from the scoped-aligned x_1793136_mcp.executor.* namespace (set below).
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
    var keys = ['mcp_actor_user_id','mcp_actor_email','snow_effective_user_sys_id','instance','request_id','script_sha256','issued_at','nonce','reason'];
    var parts = [];
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i], v = a[k];
      var vs = (k === 'issued_at') ? String(v) : this._asciiJsonString(String(v == null ? '' : v));
      parts.push(this._asciiJsonString(k) + ':' + vs);
    }
    return '{' + parts.join(',') + '}';
  },
  _hmacBase64: function(key, message) { var mac = new GlideCertificateEncryption(); return mac.generateMac(key, 'HmacSHA256', message); },
  _constantTimeEquals: function(a, b) { if (a == null || b == null) return false; if (a.length !== b.length) return false; var d = 0; for (var i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; },
  _thisInstance: function() { return gs.getProperty('instance_name', ''); },
  _instanceMatches: function(claimed) { var name = String(this._thisInstance() || ''); if (!name) return false; var c = String(claimed || ''); if (!c) return false; return c === name || c.indexOf(name + '.') === 0; },
  // verify(): HMAC + script-bind + instance-claim + freshness. NO nonce single-use, NO eval —
  // the caller consumes the nonce (INSERT-as-arbiter on the scoped x_1793136_mcp_nonce table)
  // between verify() and execute(). The nonce STAYS in the signed canonical (HMAC covers it).
  verify: function(script, actor, sig) {
    if (!sig) return { verified: false };
    var expHash = new GlideDigest().getSHA256Base64(String(script || ''));
    if (expHash !== String(actor.script_sha256 || '')) return { verified: false };
    if (!this._instanceMatches(actor.instance)) return { verified: false };
    var now = new GlideDateTime().getNumericValue();
    var issued = parseInt(actor.issued_at, 10);
    if (isNaN(issued) || Math.abs(now - issued) > this.FRESHNESS_MS) return { verified: false };
    var canon = this._canonical(actor);
    var keyCur = gs.getProperty('x_1793136_mcp.executor.hmac_secret', '');
    var keyPrev = gs.getProperty('x_1793136_mcp.executor.hmac_secret_prev', '');
    var ok = keyCur && this._constantTimeEquals(this._hmacBase64(keyCur, canon), sig);
    if (!ok && keyPrev) ok = this._constantTimeEquals(this._hmacBase64(keyPrev, canon), sig);
    if (!ok) return { verified: false };
    return { verified: true };
  },
  // execute(): eval the verified script (new Function is global-only). Caller MUST verify +
  // consume the nonce first. Returns { serialized, error }; never throws (catches internally).
  execute: function(code) {
    var result, err = null;
    try { var fn = new Function('gs','GlideRecord','GlideRecordSecure','GlideAggregate','"use strict";\\n' + code); result = fn(gs, GlideRecord, GlideRecordSecure, GlideAggregate); }
    catch (e) { err = String(e); }
    var serialized = null;
    try { serialized = JSON.stringify(result === undefined ? null : result); }
    catch (se) { err = err || ('unserializable: ' + String(se)); serialized = null; }
    return { serialized: serialized, error: err };
  },
  // run(): verify-then-execute back-compat, NO nonce single-use. The scoped wrapper does NOT use
  // run() — it calls verify()/consume/execute() so the nonce INSERT lands between the two.
  run: function(code, actor, sig) {
    if (!this.verify(code, actor, sig).verified) return { verified: false };
    var out = this.execute(code);
    return { verified: true, ok: !out.error, error: out.error, serialized: out.serialized };
  },
  type: 'x_mcp_verify'
};`;

console.log(`Installing x_mcp executor on ${host}\n`);

// 1) Properties (scoped-aligned namespace x_1793136_mcp.executor.*, plan §P7 item 5)
log("hmac_secret:", await setProperty("x_1793136_mcp.executor.hmac_secret", keyB64, "password2"));
log("enabled:", await setProperty("x_1793136_mcp.executor.enabled", "true", "true|false"));
log("run_server_script_enabled:", await setProperty("x_1793136_mcp.executor.run_server_script_enabled", "true", "true|false"));
log("max_bytes:", await setProperty("x_1793136_mcp.executor.max_bytes", "32768", "integer"));
log("max_output_bytes:", await setProperty("x_1793136_mcp.executor.max_output_bytes", "65536", "integer"));

// 2) NO TABLES. The Table API 403s on DDL (sys_db_object/sys_dictionary/sys_index POST) even for
// admin, so we create NO tables here. The nonce store (x_1793136_mcp_nonce) + its UNIQUE index +
// the purge job, and the audit log (x_1793136_mcp_audit_log), are OWNED BY THE SCOPED FLUENT APP
// (now-sdk install deploys them — see sn-executor-app/fluent/src/fluent/x_mcp.now.ts). The scoped
// wrapper consumes the nonce in-scope; this global core no longer touches any nonce table.

// 3) Script Include (the global verify()/execute()/run() core for scoped delegation).
log("x_mcp_verify script include:", await ensureScriptInclude("x_mcp_verify", verifyScript));

console.log(
  "\nHelper install complete (x_mcp_verify core + properties; NO tables, NO global REST endpoint — " +
    "the scoped Fluent app owns the nonce+audit tables AND the role-ACL-gated REST endpoint). " +
    "Request endpoint is the scoped Fluent REST; verify it with scripts/executor-scoped-verify.mjs.",
);
process.exit(0);
