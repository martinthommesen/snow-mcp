// Script Include: x_mcp_verify (scoped app x_1793136_mcp). Verifies the host-signed
// actor (plan §2.0, §10; B1). ASCII-only canonical encoding MUST match the host signer.
// HMAC via GlideCertificateEncryption. Nonce replay via x_1793136_mcp_nonce.
var x_mcp_verify = Class.create()
x_mcp_verify.prototype = {
    FRESHNESS_MS: 120000,
    initialize: function () {},
    _asciiJsonString: function (s) {
        var out = '"'
        for (var i = 0; i < s.length; i++) {
            var c = s.charCodeAt(i)
            if (c === 0x22) out += '\\"'
            else if (c === 0x5c) out += '\\\\'
            else if (c < 0x20 || c >= 0x7f) {
                var h = c.toString(16)
                while (h.length < 4) h = '0' + h
                out += '\\u' + h
            } else out += s.charAt(i)
        }
        return out + '"'
    },
    _canonical: function (a) {
        var keys = ['mcp_actor_user_id', 'mcp_actor_email', 'snow_effective_user_sys_id', 'instance', 'request_id', 'script_sha256', 'issued_at', 'nonce']
        var parts = []
        for (var i = 0; i < keys.length; i++) {
            var k = keys[i],
                v = a[k]
            var vs = k === 'issued_at' ? String(v) : this._asciiJsonString(String(v == null ? '' : v))
            parts.push(this._asciiJsonString(k) + ':' + vs)
        }
        return '{' + parts.join(',') + '}'
    },
    _eq: function (a, b) {
        if (a.length !== b.length) return false
        var d = 0
        for (var i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i)
        return d === 0
    },
    verify: function (script, actor, sig) {
        if (!sig) return false
        var expHash = new GlideDigest().getSHA256Base64(String(script || ''))
        if (expHash !== String(actor.script_sha256 || '')) return false
        var now = new GlideDateTime().getNumericValue()
        var issued = parseInt(actor.issued_at, 10)
        if (isNaN(issued) || Math.abs(now - issued) > this.FRESHNESS_MS) return false
        var canon = this._canonical(actor)
        var keyCur = gs.getProperty('x_mcp.executor.hmac_secret', '')
        var keyPrev = gs.getProperty('x_mcp.executor.hmac_secret_prev', '')
        var enc = new GlideCertificateEncryption()
        var ok = keyCur && this._eq(enc.generateMac(keyCur, 'HmacSHA256', canon), sig)
        if (!ok && keyPrev) ok = this._eq(enc.generateMac(keyPrev, 'HmacSHA256', canon), sig)
        if (!ok) return false
        return this._consumeNonce(String(actor.nonce || ''))
    },
    _consumeNonce: function (nonce) {
        if (!nonce) return false
        var ex = new GlideRecord('x_1793136_mcp_nonce')
        ex.addQuery('value', nonce)
        ex.setLimit(1)
        ex.query()
        if (ex.next()) return false
        var row = new GlideRecord('x_1793136_mcp_nonce')
        row.initialize()
        row.value = nonce
        row.created = new GlideDateTime()
        return !!row.insert()
    },
    type: 'x_mcp_verify',
}
