// Script Include: x_mcp_verify (GLOBAL scope). COPY of the canonical core at
// sn-executor-app/script-include/x_mcp_verify.js — the class body below MUST stay
// byte-consistent with it (and with the executor-install.mjs blob). Do not hand-fork:
// a divergence in _canonical / the ASCII escaper silently breaks every signature (B1).
//
// PUBLIC API (plan §P7 nonce-store fix): verify(code,actor,sig) -> {verified, error?} (HMAC +
// script-bind + instance-claim + freshness; NO nonce, NO eval); execute(code) -> {serialized,
// error} (new Function eval); run(code,actor,sig) -> verify-then-execute (NO nonce; back-compat).
// SINGLE-USE NONCE consumption is owned by the SCOPED wrapper (x_mcp_executor.js), which INSERTs
// into the scoped x_1793136_mcp_nonce table (DB UNIQUE index) between verify() and execute(). The
// nonce STAYS in the signed canonical — the HMAC still covers it.
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

  verify: function (script, actor, sig) {
    if (!sig) return { verified: false };
    var expectedHash = new GlideDigest().getSHA256Base64(String(script || ''));
    if (expectedHash !== String(actor.script_sha256 || '')) return { verified: false };
    if (!this._instanceMatches(actor.instance)) return { verified: false };
    var now = new GlideDateTime().getNumericValue();
    var issued = parseInt(actor.issued_at, 10);
    if (isNaN(issued) || Math.abs(now - issued) > this.FRESHNESS_MS) return { verified: false };
    var canonical = this._canonical(actor);
    var keyCur = gs.getProperty('x_1793136_mcp.executor.hmac_secret', '');
    var keyPrev = gs.getProperty('x_1793136_mcp.executor.hmac_secret_prev', '');
    var ok = keyCur && this._constantTimeEquals(this._hmacBase64(keyCur, canonical), sig);
    if (!ok && keyPrev) ok = this._constantTimeEquals(this._hmacBase64(keyPrev, canonical), sig);
    if (!ok) return { verified: false };
    // Nonce single-use is owned by the scoped wrapper (INSERT-as-arbiter on x_1793136_mcp_nonce).
    return { verified: true };
  },

  execute: function (code) {
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
    return { serialized: serialized, error: err };
  },

  // Back-compat verify-then-execute, NO nonce single-use. The scoped wrapper does NOT use run().
  run: function (code, actor, sig) {
    if (!this.verify(code, actor, sig).verified) return { verified: false };
    var out = this.execute(code);
    return { verified: true, ok: !out.error, error: out.error, serialized: out.serialized };
  },

  type: 'x_mcp_verify',
};
