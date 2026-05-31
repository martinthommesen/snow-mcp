// x_mcp/executor/run  (Scripted REST resource, scoped app x_mcp, role-gated by REST_Endpoint ACL)
// Reference implementation from DEVELOPMENT_PLAN §10 (v4): SYNCHRONOUS; audit-FIRST +
// fail-closed; VERIFIES the signed actor; UTF-8 byte cap; SAFE serialize.
//
// ⚠️ DEPRECATED (plan §P7; DELTAS D10/D11). The PRODUCTION executor is the scoped Fluent
//    wrapper sn-executor-app/fluent/src/server/x_mcp_executor.js, which GATES audit ->
//    kill-switch -> egress -> size BEFORE delegating verify+eval to global x_mcp_verify.run()
//    (gate-before-delegate). This reference VERIFIES FIRST (line ~45), so an oversized but
//    validly-signed call BURNS its nonce before the 413 — the bug P7 fixes by keeping the
//    Fluent wrapper's ordering. Also: it calls the OLD `.verify()` API, which the unified
//    canonical core (script-include/x_mcp_verify.js) no longer exposes (only `.run()`). Kept
//    only as a non-SDK historical reference; do NOT install this. Eval + crypto are
//    global-only, so a self-contained scoped executor like this cannot actually run.
//
// ⚠️ UNVERIFIED IN THIS BUILD — requires a live PDI to install, run, and prove
//    (Phase 1.8 spike / Phase 5; gates S8/S9/S16/B1/B6). See docs/OPEN_QUESTIONS.md.

// Correct UTF-8 byte length (incl. surrogate pairs) — 'max_bytes' means bytes, not code units.
function utf8Len(s) {
  var n = 0;
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xD800 && c <= 0xDBFF) { n += 4; i++; }
    else n += 3;
  }
  return n;
}

(function process(req, res) {
  var body = req.body.data || {};
  var code = String(body.script || '');
  var actor = body.actor || {};        // CLAIMED until verified
  var sig = String(body.actor_sig || '');

  // 1) AUDIT-FIRST + FAIL-CLOSED. Record server-known facts + the *claimed* actor as unverified.
  var start = new GlideDateTime();
  var audit = new GlideRecord('x_mcp_audit_log');
  audit.initialize();
  audit.snow_user = gs.getUserID();
  audit.snow_user_name = gs.getUserName();
  audit.mcp_actor_user_id = String(actor.mcp_actor_user_id || '');
  audit.mcp_actor_email = String(actor.mcp_actor_email || '');
  audit.request_id = String(actor.request_id || '');
  audit.actor_verified = false;
  audit.code_hash = new GlideDigest().getSHA256Base64(code);
  audit.code_size = utf8Len(code);
  audit.started_at = start;
  audit.status = 'running';
  var auditId = audit.insert();
  if (!auditId) { res.setStatus(500); res.setBody({ error: 'audit_unavailable' }); return; } // fail closed

  // 2) VERIFY the signed actor BEFORE trusting any actor field (§2.0). Fail closed.
  // I-7 (2026-05-31): verify() returns an OBJECT { verified } — `!obj` is ALWAYS false, so the
  // original `if (!new ...verify(...))` reject branch was DEAD CODE (every forged/unsigned/replayed
  // request fell through to eval — the exact shape of the production incident). Check `.verified`.
  // This file is a DEPRECATED reference (do NOT install — use the Fluent wrapper); the guard is
  // corrected so the landmine pattern cannot be copy-pasted from here.
  var __verify = new x_mcp.x_mcp_verify().verify(code, actor, sig);
  if (!__verify || !__verify.verified) {
    audit.status = 'rejected'; audit.error_class = 'actor_signature_invalid'; audit.update();
    res.setStatus(401); res.setBody({ error: 'actor_signature_invalid', audit_id: auditId + '' }); return;
  }
  audit.actor_verified = true; audit.update();

  // 3) Kill switch, then tenant EGRESS toggle (runServerScript can reach SN outbound; §11).
  if (gs.getProperty('x_mcp.executor.enabled', 'true') !== 'true') {
    audit.status = 'killed'; audit.update();
    res.setStatus(503); res.setBody({ error: 'executor_disabled', audit_id: auditId + '' }); return;
  }
  if (gs.getProperty('x_mcp.executor.run_server_script_enabled', 'true') !== 'true') {
    audit.status = 'killed'; audit.error_class = 'egress_disabled'; audit.update();
    res.setStatus(503); res.setBody({ error: 'run_server_script_disabled', audit_id: auditId + '' }); return;
  }

  // 4) UTF-8 BYTE size guard (host enforces too; defense in depth).
  var maxB = parseInt(gs.getProperty('x_mcp.executor.max_bytes', '32768'), 10);
  var bytes = utf8Len(code);
  if (bytes === 0 || bytes > maxB) {
    audit.status = 'error'; audit.error_class = 'code_size'; audit.update();
    res.setStatus(413); res.setBody({ error: 'code_size', audit_id: auditId + '' }); return;
  }

  // 5) SYNCHRONOUS execution. Plain GlideRecord bypasses ACLs server-side (the 'maximum
  //    reach'); role + ACL + audit + kill switch + verified actor are the boundary.
  var result, err = null, status = 'ok';
  try {
    var fn = new Function('gs', 'GlideRecord', 'GlideRecordSecure', 'GlideAggregate', '"use strict";\n' + code);
    result = fn(gs, GlideRecord, GlideRecordSecure, GlideAggregate);
  } catch (e) { err = String(e); status = 'error'; }

  // 6) SAFE serialize — catch JSON.stringify failures (circular / GlideRecord-like / too deep).
  var serialized = null;
  try { serialized = JSON.stringify(result === undefined ? null : result); }
  catch (se) { err = err || ('unserializable: ' + String(se)); status = 'error'; serialized = null; }

  var maxOut = parseInt(gs.getProperty('x_mcp.executor.max_output_bytes', '65536'), 10);
  function closeAudit(st, outBytes) {
    audit.status = st;
    audit.duration = (new GlideDateTime()).getNumericValue() - start.getNumericValue();
    audit.output_size = outBytes; audit.error_class = err ? err.split(':')[0] : ''; audit.update();
  }

  // 6a) Over-cap: return a SAMPLE STRING. NEVER JSON.parse a truncated string.
  if (serialized && utf8Len(serialized) > maxOut) {
    if (status === 'ok') status = 'truncated';
    closeAudit(status, utf8Len(serialized));
    res.setStatus(200);
    res.setBody({ ok: !err, result: null, result_sample: serialized.slice(0, maxOut),
                  truncated: true, error: err, audit_id: auditId + '' });
    return;
  }

  // 6b) Under cap: 'serialized' is a COMPLETE JSON string we just produced — safe to parse back.
  closeAudit(status, serialized ? utf8Len(serialized) : 0);
  res.setStatus(err ? 500 : 200);
  res.setBody({ ok: !err, result: (err || serialized == null) ? null : JSON.parse(serialized),
                truncated: false, error: err, audit_id: auditId + '' });
})(request, response);
