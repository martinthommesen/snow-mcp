// Script Include: x_mcp_verify (GLOBAL scope). COPY of the canonical core at
// sn-executor-app/script-include/x_mcp_verify.js — the class body below MUST stay
// byte-consistent with it (and with the executor-install.mjs blob). Do not hand-fork:
// a divergence in _canonical / the ASCII escaper silently breaks every signature (B1).
//
// PUBLIC API: run(code, actor, sig) = verify + eval. The scoped executor wrapper calls
// `new global.x_mcp_verify().run(...)` AFTER its audit/kill-switch/egress/size gates.
var x_mcp_verify = Class.create();
x_mcp_verify.prototype = {
  FRESHNESS_MS: 120 * 1000,

  initialize: function () {},

  _asciiJsonString: function (s) {
    var out = '"';
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i);
      if (c === 0x22) out += '\\"';
      else if (c === 0x5c) out += '\\\\';
      else if (c < 0x20 || c >= 0x7f) {
        var hex = c.toString(16);
        while (hex.length < 4) hex = '0' + hex;
        out += '\\u' + hex;
      } else out += s.charAt(i);
    }
    return out + '"';
  },

  _canonical: function (actor) {
    var keys = ['mcp_actor_user_id', 'mcp_actor_email', 'snow_effective_user_sys_id',
                'instance', 'request_id', 'script_sha256', 'issued_at', 'nonce', 'reason'];
    var parts = [];
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i];
      var v = actor[k];
      var valStr = (k === 'issued_at') ? String(v) : this._asciiJsonString(String(v == null ? '' : v));
      parts.push(this._asciiJsonString(k) + ':' + valStr);
    }
    return '{' + parts.join(',') + '}';
  },

  _hmacBase64: function (key, message) {
    var mac = new GlideCertificateEncryption();
    return mac.generateMac(key, 'HmacSHA256', message); // base64 (may be null on bad input)
  },

  _constantTimeEquals: function (a, b) {
    if (a == null || b == null) return false;
    if (a.length !== b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  },

  _thisInstance: function () {
    return gs.getProperty('instance_name', '');
  },

  _instanceMatches: function (claimed) {
    var name = String(this._thisInstance() || '');
    if (!name) return false;
    var c = String(claimed || '');
    if (!c) return false;
    return c === name || c.indexOf(name + '.') === 0;
  },

  _verify: function (script, actor, sig) {
    if (!sig) return false;
    var expectedHash = new GlideDigest().getSHA256Base64(String(script || ''));
    if (expectedHash !== String(actor.script_sha256 || '')) return false;
    if (!this._instanceMatches(actor.instance)) return false;
    var now = new GlideDateTime().getNumericValue();
    var issued = parseInt(actor.issued_at, 10);
    if (isNaN(issued) || Math.abs(now - issued) > this.FRESHNESS_MS) return false;
    var canonical = this._canonical(actor);
    var keyCur = gs.getProperty('x_1793136_mcp.executor.hmac_secret', '');
    var keyPrev = gs.getProperty('x_1793136_mcp.executor.hmac_secret_prev', '');
    var ok = keyCur && this._constantTimeEquals(this._hmacBase64(keyCur, canonical), sig);
    if (!ok && keyPrev) ok = this._constantTimeEquals(this._hmacBase64(keyPrev, canonical), sig);
    if (!ok) return false;
    return this._consumeNonce(String(actor.nonce || ''));
  },

  // ⚠️ REFERENCE-ONLY NONCE STORE — see the canonical note in
  // sn-executor-app/script-include/x_mcp_verify.js. This file is NOT deployed; the LIVE verifier
  // is the GLOBAL core in scripts/executor-install.mjs, whose _consumeNonce writes the GLOBAL
  // x_mcp_nonce table with INSERT-as-arbiter (a duplicate insert — falsy OR thrown unique-
  // constraint violation — is the replay; finding 24). The scoped x_1793136_mcp_nonce below is
  // reserved/unused by the live path.
  _consumeNonce: function (nonce) {
    if (!nonce) return false;
    var existing = new GlideRecord('x_1793136_mcp_nonce');
    existing.addQuery('value', nonce);
    existing.setLimit(1);
    existing.query();
    if (existing.next()) return false;
    var row = new GlideRecord('x_1793136_mcp_nonce');
    row.initialize();
    row.value = nonce;
    row.created = new GlideDateTime();
    return !!row.insert();
  },

  run: function (code, actor, sig) {
    if (!this._verify(code, actor, sig)) return { verified: false };
    var result, err = null;
    try {
      var fn = new Function('gs', 'GlideRecord', 'GlideRecordSecure', 'GlideAggregate', '"use strict";\n' + code);
      result = fn(gs, GlideRecord, GlideRecordSecure, GlideAggregate);
    } catch (e) {
      err = String(e);
    }
    var serialized = null;
    try {
      serialized = JSON.stringify(result === undefined ? null : result);
    } catch (se) {
      err = err || ('unserializable: ' + String(se));
      serialized = null;
    }
    return { verified: true, ok: !err, error: err, serialized: serialized };
  },

  type: 'x_mcp_verify',
};
