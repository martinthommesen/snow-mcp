// Executor resource (scoped app x_1793136_mcp). Scoped apps CANNOT use new Function or
// GlideCertificateEncryption (global-only), so verification + execution are DELEGATED to
// the GLOBAL x_mcp_verify.run() (plan §0.13a). The scoped app owns the role-gated REST
// endpoint (REST_Endpoint ACL = S8), the audit-first row (x_1793136_mcp_audit_log), the
// kill switch, the byte cap, and the safe truncation envelope.
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
    audit.code_size = utf8Len(code)
    audit.started_at = start
    audit.status = 'running'
    var auditId = audit.insert()
    if (!auditId) {
        response.setStatus(500)
        response.setBody({ error: 'audit_unavailable' })
        return
    }

    // Kill switch + egress toggle (scoped-allowed: gs.getProperty). Property namespace is the
    // scoped vendor prefix x_1793136_mcp.executor.* (plan §P7 item 5).
    if (gs.getProperty('x_1793136_mcp.executor.enabled', 'true') !== 'true') {
        audit.status = 'killed'
        audit.update()
        response.setStatus(503)
        response.setBody({ error: 'executor_disabled', audit_id: auditId + '' })
        return
    }
    if (gs.getProperty('x_1793136_mcp.executor.run_server_script_enabled', 'true') !== 'true') {
        audit.status = 'killed'
        audit.error_class = 'egress_disabled'
        audit.update()
        response.setStatus(503)
        response.setBody({ error: 'run_server_script_disabled', audit_id: auditId + '' })
        return
    }

    var maxB = parseInt(gs.getProperty('x_1793136_mcp.executor.max_bytes', '32768'), 10)
    var bytes = utf8Len(code)
    if (bytes === 0 || bytes > maxB) {
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

    // DELEGATE verify + eval to the global core (new Function + GlideCertificateEncryption).
    // The LIVE global core (scripts/executor-install.mjs) is what runs here; its _consumeNonce
    // ends in row.insert() against the UNIQUE index on the GLOBAL x_mcp_nonce.value table (NOT
    // the scoped x_1793136_mcp_nonce, which that core does not write — see x_mcp.now.ts). The
    // core catches a duplicate-key throw internally, but this try/catch stays as defense-in-
    // depth: if a future core lets the constraint violation escape run(), the throw would leave
    // the audit row stuck at 'running' with a 500 — reintroducing the finding-31 (audit never
    // closes) bug on the finding-24 (nonce race) path. A nonce collision IS a replay, so close
    // to 'rejected' + 401 either way (plan §P7 items 3b/4).
    var out
    try {
        // eslint-disable-next-line no-unsupported-node-builtins
        out = new global.x_mcp_verify().run(code, actor, sig)
    } catch (re) {
        audit.status = 'rejected'
        audit.error_class = 'nonce_consume_failed'
        audit.update()
        response.setStatus(401)
        response.setBody({ error: 'actor_signature_invalid', audit_id: auditId + '' })
        return
    }
    if (!out.verified) {
        audit.status = 'rejected'
        audit.error_class = 'actor_signature_invalid'
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

    var err = out.error
    var status = err ? 'error' : 'ok'
    var serialized = out.serialized
    var maxOut = parseInt(gs.getProperty('x_1793136_mcp.executor.max_output_bytes', '65536'), 10)
    function closeAudit(st, ob) {
        audit.status = st
        audit.duration = new GlideDateTime().getNumericValue() - start.getNumericValue()
        audit.output_size = ob
        audit.error_class = err ? err.split(':')[0] : ''
        audit.update()
    }

    if (serialized && utf8Len(serialized) > maxOut) {
        if (status === 'ok') status = 'truncated'
        closeAudit(status, utf8Len(serialized))
        response.setStatus(200)
        // Byte-safe truncation (plan §P7 item 4): never split a UTF-8 sequence on a byte cap.
        response.setBody({ ok: !err, result: null, result_sample: utf8Slice(serialized, maxOut), truncated: true, error: err, audit_id: auditId + '' })
        return
    }
    closeAudit(status, serialized ? utf8Len(serialized) : 0)
    response.setStatus(err ? 500 : 200)
    response.setBody({ ok: !err, result: err || serialized == null ? null : JSON.parse(serialized), truncated: false, error: err, audit_id: auditId + '' })
})(request, response)
