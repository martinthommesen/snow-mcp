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

    // Kill switch + egress toggle (scoped-allowed: gs.getProperty).
    if (gs.getProperty('x_mcp.executor.enabled', 'true') !== 'true') {
        audit.status = 'killed'
        audit.update()
        response.setStatus(503)
        response.setBody({ error: 'executor_disabled', audit_id: auditId + '' })
        return
    }
    if (gs.getProperty('x_mcp.executor.run_server_script_enabled', 'true') !== 'true') {
        audit.status = 'killed'
        audit.error_class = 'egress_disabled'
        audit.update()
        response.setStatus(503)
        response.setBody({ error: 'run_server_script_disabled', audit_id: auditId + '' })
        return
    }

    var maxB = parseInt(gs.getProperty('x_mcp.executor.max_bytes', '32768'), 10)
    var bytes = utf8Len(code)
    if (bytes === 0 || bytes > maxB) {
        audit.status = 'error'
        audit.error_class = 'code_size'
        audit.update()
        response.setStatus(413)
        response.setBody({ error: 'code_size', audit_id: auditId + '' })
        return
    }

    // DELEGATE verify + eval to the global core (new Function + GlideCertificateEncryption).
    // eslint-disable-next-line no-unsupported-node-builtins
    var out = new global.x_mcp_verify().run(code, actor, sig)
    if (!out.verified) {
        audit.status = 'rejected'
        audit.error_class = 'actor_signature_invalid'
        audit.update()
        response.setStatus(401)
        response.setBody({ error: 'actor_signature_invalid', audit_id: auditId + '' })
        return
    }
    audit.actor_verified = true

    var err = out.error
    var status = err ? 'error' : 'ok'
    var serialized = out.serialized
    var maxOut = parseInt(gs.getProperty('x_mcp.executor.max_output_bytes', '65536'), 10)
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
        response.setBody({ ok: !err, result: null, result_sample: serialized.slice(0, maxOut), truncated: true, error: err, audit_id: auditId + '' })
        return
    }
    closeAudit(status, serialized ? utf8Len(serialized) : 0)
    response.setStatus(err ? 500 : 200)
    response.setBody({ ok: !err, result: err || serialized == null ? null : JSON.parse(serialized), truncated: false, error: err, audit_id: auditId + '' })
})(request, response)
