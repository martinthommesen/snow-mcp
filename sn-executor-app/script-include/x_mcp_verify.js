// Script Include: x_mcp_verify (GLOBAL scope — the single canonical core, plan §P7).
//
// THIS FILE IS THE SOURCE OF TRUTH. The Fluent copy
// (sn-executor-app/fluent/src/server/x_mcp_verify.js) and the embedded blob in
// scripts/executor-install.mjs are GENERATED/COPIED from this one and MUST stay
// byte-consistent in the class body — do not hand-fork. A divergence in `_canonical`
// or the ASCII escaper silently breaks every signature (B1).
//
// ⚠️ UNVERIFIED IN THIS BUILD — the in-scope HMAC + SHA-256 mechanism is Phase 0.13a
//    (open). GlideCertificateEncryption.generateMac / GlideDigest.getSHA256Base64 must be
//    proven on the target family before it ships (P8). See docs/OPEN_QUESTIONS.md.
//
// CONTRACT (must byte-for-byte match the host signer in packages/mcp-server/src/auth/actor.ts):
//   canonical = the ASCII-only encoder below, keys in THIS fixed order:
//     mcp_actor_user_id, mcp_actor_email, snow_effective_user_sys_id,
//     instance, request_id, script_sha256, issued_at, nonce, reason
//   actor_sig = base64( HMAC-SHA256( key = x_1793136_mcp.executor.hmac_secret, canonical ) )
//   Verification is FAIL-CLOSED on: bad/missing sig; script_sha256 != SHA-256(script);
//   actor.instance != this instance (cross-instance replay); issued_at outside ±freshness;
//   replayed nonce (seen in the nonce table within the window).
//
// PUBLIC API: run(code, actor, sig) = verify + eval. Returns
//   { verified:false }                                  — verification failed (wrapper -> 401)
//   { verified:true, ok, error, serialized }            — verified; eval result/serialization
// (The legacy `.verify()`-only split is gone; the scoped wrapper calls `.run()`.)

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

  // Build the canonical string in the agreed key order, ASCII-only. `reason` is LAST
  // (mirrors host CANONICAL_KEYS, plan §P7 item 1).
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
    // TODO(0.13a): confirm the exact in-scope HMAC API + key encoding on the target family.
    // GlideCertificateEncryption.generateMac(key, algorithm, data) returns base64; key is
    // typically base64-encoded. We mirror the host (raw-key HMAC-SHA256 -> base64).
    var mac = new GlideCertificateEncryption();
    return mac.generateMac(key, 'HmacSHA256', message); // base64 (may be null on bad input)
  },

  // NULL-SAFE constant-time compare. _hmacBase64/generateMac can return null/undefined on
  // a bad key or input; guard so a null MAC yields a clean `false` (-> 401) instead of a
  // thrown TypeError on `.length` (plan §P7 item 3b).
  _constantTimeEquals: function (a, b) {
    if (a == null || b == null) return false;
    if (a.length !== b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  },

  // This instance's host name, used to reject cross-instance replay (plan §P7 item 3a).
  // `instance_name` is the PDI subdomain; the host signs the full FQDN, so compare on the
  // subdomain prefix. instance.uri / glide.servlet.uri are fallbacks if unset.
  _thisInstance: function () {
    return gs.getProperty('instance_name', '');
  },

  // True only if the signed actor.instance names THIS instance (subdomain match).
  _instanceMatches: function (claimed) {
    var name = String(this._thisInstance() || '');
    if (!name) return false; // fail closed if the instance name is unreadable
    var c = String(claimed || '');
    if (!c) return false;
    // Host signs e.g. "dev12345.service-now.com"; instance_name is "dev12345".
    return c === name || c.indexOf(name + '.') === 0;
  },

  // Returns true only if the signature is valid, fresh, script-bound, instance-bound, and
  // non-replayed. Internal — callers use run().
  _verify: function (script, actor, sig) {
    if (!sig) return false;

    // (a) script binding.
    // ⚠️ 0.13a seam: GlideDigest.getSHA256Base64(String) must hash the UTF-8 bytes of the
    // input to match the host's WebCrypto SHA-256 over `TextEncoder().encode(input)` (UTF-8).
    // If SN hashes UTF-16/Latin-1, non-ASCII scripts break signatures. Source-only here;
    // proven on a live PDI at P8 (see docs/OPEN_QUESTIONS.md). ASCII scripts are unaffected.
    var expectedHash = new GlideDigest().getSHA256Base64(String(script || ''));
    if (expectedHash !== String(actor.script_sha256 || '')) return false;

    // (b) instance claim — reject cross-instance replay (a payload signed for another PDI).
    if (!this._instanceMatches(actor.instance)) return false;

    // (c) freshness
    var now = new GlideDateTime().getNumericValue();
    var issued = parseInt(actor.issued_at, 10);
    if (isNaN(issued) || Math.abs(now - issued) > this.FRESHNESS_MS) return false;

    // (d) signature (current key, then previous key during rotation)
    var canonical = this._canonical(actor);
    var keyCur = gs.getProperty('x_1793136_mcp.executor.hmac_secret', '');
    var keyPrev = gs.getProperty('x_1793136_mcp.executor.hmac_secret_prev', '');
    var ok = keyCur && this._constantTimeEquals(this._hmacBase64(keyCur, canonical), sig);
    if (!ok && keyPrev) ok = this._constantTimeEquals(this._hmacBase64(keyPrev, canonical), sig);
    if (!ok) return false;

    // (e) nonce replay defense — insert; duplicate insert => replay.
    return this._consumeNonce(String(actor.nonce || ''));
  },

  // ⚠️ REFERENCE-ONLY NONCE STORE. This canonical source targets the SCOPED x_1793136_mcp_nonce
  // table, but this file is NOT deployed — the LIVE verifier is the GLOBAL core in
  // scripts/executor-install.mjs, whose _consumeNonce writes the GLOBAL x_mcp_nonce table and
  // treats a duplicate INSERT (falsy OR thrown unique-constraint violation) as a replay (that
  // INSERT-as-arbiter is the concurrency-safe form; finding 24). Keep this reference and the
  // live blob's _consumeNonce semantically aligned — both reject a replayed nonce — but the
  // live store + its DB unique constraint live in executor-install.mjs.
  _consumeNonce: function (nonce) {
    if (!nonce) return false;
    var existing = new GlideRecord('x_1793136_mcp_nonce');
    existing.addQuery('value', nonce);
    existing.setLimit(1);
    existing.query();
    if (existing.next()) return false; // replay

    var row = new GlideRecord('x_1793136_mcp_nonce');
    row.initialize();
    row.value = nonce;
    row.created = new GlideDateTime();
    return !!row.insert();
  },

  // PUBLIC: verify the signed actor, then eval the script (plan §P7 item 2). The scoped
  // wrapper owns audit/kill-switch/egress/size BEFORE calling this; this owns verify + eval.
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
