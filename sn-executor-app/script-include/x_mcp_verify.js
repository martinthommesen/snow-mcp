// Script Include: x_mcp.x_mcp_verify  (scoped app x_mcp)
// Verifies the host-signed actor payload (plan §2.0, §10; gate B1).
//
// ⚠️ UNVERIFIED IN THIS BUILD — the in-scope HMAC mechanism is Phase 0.13a (open).
//    Candidates: GlideCertificateEncryption.generateMac / a global verify Script Include
//    / com.glide.tokenbased_auth. This implementation must be proven on the target
//    family before it ships. See docs/OPEN_QUESTIONS.md.
//
// CONTRACT (must byte-for-byte match the host signer in packages/mcp-server/src/auth/actor.ts):
//   canonical = JSON.stringify, with keys in THIS fixed order:
//     mcp_actor_user_id, mcp_actor_email, snow_effective_user_sys_id,
//     instance, request_id, script_sha256, issued_at, nonce
//   actor_sig = base64( HMAC-SHA256( key = x_mcp.executor.hmac_secret, canonical ) )
//   Verification is FAIL-CLOSED on: bad/missing sig; script_sha256 != SHA-256(script);
//   issued_at outside ±freshness; replayed nonce (seen in x_mcp_nonce within the window).

var x_mcp_verify = Class.create();
x_mcp_verify.prototype = {
  FRESHNESS_MS: 120 * 1000,

  initialize: function () {},

  // Engine-independent, ASCII-ONLY escaper. MUST match the host signer byte-for-byte
  // (packages/mcp-server/src/auth/actor.ts asciiJsonString). We do NOT use JSON.stringify
  // here, because V8 and ServiceNow's engine can escape non-ASCII differently — which
  // would silently break every signature carrying a non-ASCII actor field (B1).
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

  // Build the canonical string in the agreed key order, ASCII-only.
  _canonical: function (actor) {
    var keys = ['mcp_actor_user_id', 'mcp_actor_email', 'snow_effective_user_sys_id',
                'instance', 'request_id', 'script_sha256', 'issued_at', 'nonce'];
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
    // TODO(0.13a): confirm the exact in-scope HMAC API + key encoding on the target family.
    // GlideCertificateEncryption.generateMac(key, algorithm, data) returns base64; key is
    // typically base64-encoded. We mirror the host (raw-key HMAC-SHA256 -> base64).
    var mac = new GlideCertificateEncryption();
    return mac.generateMac(key, 'HmacSHA256', message); // base64
  },

  _constantTimeEquals: function (a, b) {
    if (a.length !== b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  },

  // Returns true only if the signature is valid, fresh, script-bound, and non-replayed.
  verify: function (script, actor, sig) {
    if (!sig) return false;

    // (a) script binding
    var expectedHash = new GlideDigest().getSHA256Base64(String(script || ''));
    if (expectedHash !== String(actor.script_sha256 || '')) return false;

    // (b) freshness
    var now = new GlideDateTime().getNumericValue();
    var issued = parseInt(actor.issued_at, 10);
    if (isNaN(issued) || Math.abs(now - issued) > this.FRESHNESS_MS) return false;

    // (c) signature (current key, then previous key during rotation)
    var canonical = this._canonical(actor);
    var keyCur = gs.getProperty('x_mcp.executor.hmac_secret', '');
    var keyPrev = gs.getProperty('x_mcp.executor.hmac_secret_prev', '');
    var ok = keyCur && this._constantTimeEquals(this._hmacBase64(keyCur, canonical), sig);
    if (!ok && keyPrev) ok = this._constantTimeEquals(this._hmacBase64(keyPrev, canonical), sig);
    if (!ok) return false;

    // (d) nonce replay defense — insert; duplicate insert => replay.
    return this._consumeNonce(String(actor.nonce || ''));
  },

  // Insert the nonce; if it already exists within the window, reject as a replay.
  _consumeNonce: function (nonce) {
    if (!nonce) return false;
    var existing = new GlideRecord('x_mcp_nonce');
    existing.addQuery('value', nonce);
    existing.setLimit(1);
    existing.query();
    if (existing.next()) return false; // replay

    var row = new GlideRecord('x_mcp_nonce');
    row.initialize();
    row.value = nonce;
    row.created = new GlideDateTime();
    return !!row.insert();
  },

  type: 'x_mcp_verify',
};
