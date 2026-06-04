// Executor resource (scoped app x_1793136_mcp). Scoped apps CANNOT use new Function or
// GlideCertificateEncryption (global-only), so HMAC verification + script eval are DELEGATED to
// the GLOBAL x_mcp_verify (plan §0.13a) via its verify()/execute() split. The scoped app owns the
// role-gated REST endpoint (REST_Endpoint ACL = S8), the audit-first row (x_1793136_mcp_audit_log),
// the kill switch, the byte cap, the safe truncation envelope, AND single-use nonce consumption —
// the INSERT-as-arbiter into the scoped x_1793136_mcp_nonce table (the deployable unique-indexed
// store; plan §P7 nonce-store fix). Order: audit -> kill -> egress -> size/413 -> verify ->
// consume-nonce -> execute, so a forged request never burns a nonce and a replay never executes.
function utf8Len(s) {
    var n = 0
    for (var i = 0; i < s.length; i++) {
        var c = s.charCodeAt(i)
        if (c < 0x80) n += 1
        else if (c < 0x800) n += 2
        else if (c >= 0xd800 && c <= 0xdbff) {
            n += 4
            i++
        } else n += 3
    }
    return n
}

// UTF-8-byte-safe truncation in plain GlideScript (no TextEncoder on the SN engine, plan §P7
// item 4). Walk the string, accumulating each code point's UTF-8 byte width via the same
// model as utf8Len; stop at the LAST whole sequence that fits within maxBytes (never split a
// multi-byte char or a surrogate pair). Mirrors the host truncateUtf8 intent.
function utf8Slice(s, maxBytes) {
    var n = 0
    for (var i = 0; i < s.length; i++) {
        var c = s.charCodeAt(i)
        var w = c < 0x80 ? 1 : c < 0x800 ? 2 : c >= 0xd800 && c <= 0xdbff ? 4 : 3
        if (n + w > maxBytes) return s.slice(0, i)
        n += w
        if (w === 4) i++ // surrogate pair: skip the low surrogate too
    }
    return s
}

;(function process(request, response) {
    var body = request.body.data || {}
    var code = String(body.script || '')
    var codeBytes = utf8Len(code)
    var actor = body.actor || {}
    var sig = String(body.actor_sig || '')

    var start = new GlideDateTime()
    var audit = new GlideRecord('x_1793136_mcp_audit_log')
    audit.initialize()
    audit.snow_user = gs.getUserID()
    audit.snow_user_name = gs.getUserName()
    audit.mcp_actor_user_id = String(actor.mcp_actor_user_id || '')
    audit.mcp_actor_email = String(actor.mcp_actor_email || '')
    audit.request_id = String(actor.request_id || '')
    audit.actor_verified = false
    audit.code_hash = new GlideDigest().getSHA256Base64(code)
    audit.code_size = codeBytes
    audit.started_at = start
    audit.status = 'running'
    var auditId = audit.insert()
    if (!auditId) {
        response.setStatus(500)
        response.setBody({ error: 'audit_unavailable' })
        return
    }

    // Kill switch + egress toggle (scoped-allowed: gs.getProperty). Only the scoped app-owned
    // x_1793136_mcp.executor.* namespace is authoritative; fresh installs and upgrades default off.
    if (gs.getProperty('x_1793136_mcp.executor.enabled', 'false') !== 'true') {
        audit.status = 'killed'
        audit.update()
        response.setStatus(503)
        response.setBody({ error: 'executor_disabled', audit_id: auditId + '' })
        return
    }
    if (gs.getProperty('x_1793136_mcp.executor.run_server_script_enabled', 'false') !== 'true') {
        audit.status = 'killed'
        audit.error_class = 'egress_disabled'
        audit.update()
        response.setStatus(503)
        response.setBody({ error: 'run_server_script_disabled', audit_id: auditId + '' })
        return
    }

    var maxB = parseInt(gs.getProperty('x_1793136_mcp.executor.max_bytes', '32768'), 10)
    if (isNaN(maxB)) maxB = 32768 // NIT: a malformed property must not disable the cap (NaN compares false)
    if (codeBytes === 0 || codeBytes > maxB) {
        audit.status = 'error'
        audit.error_class = 'code_size'
        audit.update()
        response.setStatus(413)
        response.setBody({ error: 'code_size', audit_id: auditId + '' })
        return
    }

    // COOPERATIVE timeout (plan §P7 item 4): the budget property x_1793136_mcp.executor.timeout_ms
    // is read by future cooperative checks. NOTE: a PREEMPTIVE watchdog is NOT deliverable —
    // ServiceNow server-side JS is synchronous and single-threaded, so we cannot interrupt a
    // running new Function() from here. Hard enforcement relies on the platform TRANSACTION
    // QUOTA (maximum execution time), which kills the whole transaction. Do not represent
    // timeout_ms as an in-script kill.

    // VERIFY -> CONSUME NONCE -> EXECUTE (plan §P7 nonce-store fix). The global core does HMAC +
    // eval (new Function + GlideCertificateEncryption are global-only), but SINGLE-USE NONCE
    // consumption is owned HERE, in scope, against the scoped x_1793136_mcp_nonce table — the only
    // reliably-creatable unique-indexed nonce store (now-sdk deploys its table+UNIQUE index; the
    // global x_mcp_nonce table could not be created via the Table API). The interleave is:
    //   verify() (no nonce, no eval) -> INSERT-as-arbiter nonce -> execute().
    // The try/catch around verify() is defense-in-depth (finding 31): if verify ever throws, close
    // the audit row to 'rejected' + 401 instead of leaving it stuck 'running' with a 500.
    var core
    var v
    try {
        // eslint-disable-next-line no-unsupported-node-builtins
        core = new global.x_mcp_verify()
        v = core.verify(code, actor, sig)
    } catch (re) {
        audit.status = 'rejected'
        audit.error_class = 'verify_failed'
        audit.update()
        response.setStatus(401)
        response.setBody({ error: 'actor_signature_invalid', audit_id: auditId + '' })
        return
    }
    if (!v.verified) {
        audit.status = 'rejected'
        audit.error_class = 'actor_signature_invalid'
        audit.update()
        response.setStatus(401)
        response.setBody({ error: 'actor_signature_invalid', audit_id: auditId + '' })
        return
    }

    // SINGLE-USE NONCE (finding 24): INSERT-as-arbiter into the scoped x_1793136_mcp_nonce table.
    // The DB UNIQUE index on `value` is the concurrency arbiter — only one of two concurrent
    // identical signed requests can insert the nonce; the loser's insert() returns falsy (or
    // throws the constraint violation), which is a REPLAY -> 401, NO execute. Consuming AFTER
    // verify avoids burning a nonce on a forged request; BEFORE execute avoids double-execution
    // on replay. The 413/size gate above already ran, so an oversized call never burns its nonce.
    var nonceVal = String(actor.nonce || '')
    if (!nonceVal) {
        audit.status = 'rejected'
        audit.error_class = 'actor_signature_invalid'
        audit.update()
        response.setStatus(401)
        response.setBody({ error: 'actor_signature_invalid', audit_id: auditId + '' })
        return
    }
    var ng = new GlideRecord('x_1793136_mcp_nonce')
    ng.initialize()
    ng.value = nonceVal
    ng.created = new GlideDateTime()
    var nid
    try {
        nid = ng.insert()
    } catch (ne) {
        nid = null // unique-index collision thrown => replay
    }
    if (!nid) {
        audit.status = 'rejected'
        audit.error_class = 'nonce_replay'
        audit.update()
        response.setStatus(401)
        response.setBody({ error: 'actor_signature_invalid', audit_id: auditId + '' })
        return
    }

    audit.actor_verified = true
    // Persist the SIGNED, verified justification (plan §P7 item 1/4): actor.reason is integrity-
    // bound by the HMAC the core just checked, so it is now trusted attribution — not an unsigned
    // POST field. The host no longer sends a top-level body.reason.
    audit.reason = String(actor.reason || '')

    // MINT the execute() capability (finding 6): execute() now REQUIRES a secret-derived cap so
    // that instantiating global.x_mcp_verify and calling execute() directly cannot eval attacker
    // code. We mint it HERE — AFTER the single-use nonce INSERT succeeded — binding it to this
    // nonce + the exact code hash. Only a holder of the scoped secret can produce it; we read the
    // secret from our own scope and hand it to the global _hmacBase64 (which takes the key as an
    // argument, so it is not a minting oracle). A caller that skipped verify -> consume-nonce has
    // no secret and cannot forge a matching cap.
    var execSecret = gs.getProperty('x_1793136_mcp.executor.hmac_secret', '')
    var execCodeHash = new GlideDigest().getSHA256Base64(code)
    var execCap = core._hmacBase64(execSecret, 'x_mcp_exec_cap|' + nonceVal + '|' + execCodeHash)

    // EXECUTE the verified script (eval is global-only). execute() catches internally and never
    // throws, so the audit row always closes below — no 'running'-stuck row on the execute path.
    var out
    out = core.execute(code, nonceVal, execCap)
    var err = out.error
    var status = err ? 'error' : 'ok'
    var serialized = out.serialized
    var serializedBytes = serialized ? utf8Len(serialized) : 0
    var maxOut = parseInt(gs.getProperty('x_1793136_mcp.executor.max_output_bytes', '65536'), 10)
    if (isNaN(maxOut)) maxOut = 65536 // NIT: malformed property must not disable the output cap
    function closeAudit(st, ob) {
        audit.status = st
        audit.duration = new GlideDateTime().getNumericValue() - start.getNumericValue()
        audit.output_size = ob
        audit.error_class = err ? err.split(':')[0] : ''
        audit.update()
    }

    if (serialized && serializedBytes > maxOut) {
        if (status === 'ok') status = 'truncated'
        closeAudit(status, serializedBytes)
        response.setStatus(200)
        // Byte-safe truncation (plan §P7 item 4): never split a UTF-8 sequence on a byte cap.
        response.setBody({ ok: !err, result: null, result_sample: utf8Slice(serialized, maxOut), truncated: true, error: err, audit_id: auditId + '' })
        return
    }
    closeAudit(status, serializedBytes)
    response.setStatus(err ? 500 : 200)
    response.setBody({ ok: !err, result: err || serialized == null ? null : JSON.parse(serialized), truncated: false, error: err, audit_id: auditId + '' })
})(request, response)
