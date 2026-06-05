// Script Include: x_mcp_verify (GLOBAL scope). COPY of the canonical core at
// sn-executor-app/script-include/x_mcp_verify.js.
//
// The class body below MUST stay byte-consistent with the canonical file. Do not
// hand-fork: a divergence in `_canonical` or the ASCII escaper silently breaks
// every signature (B1). scripts/executor-install.mjs installs the canonical file
// directly, so this copy is for Fluent app source/deploy only.
//
// Live verification is release evidence, not a source comment. Run
// scripts/executor-scoped-verify.mjs on the target family/build and record the result in
// docs/PRODUCTION_READINESS.md before enabling production executor use.
//
// CONTRACT (must byte-for-byte match the host signer in packages/mcp-server/src/auth/actor.ts):
//   canonical = the ASCII-only encoder below, keys in THIS fixed order:
//     mcp_actor_user_id, mcp_actor_email, snow_effective_user_sys_id,
//     instance, request_id, script_sha256, issued_at, nonce, reason
//   actor_sig = base64( HMAC-SHA256( key = installer-injected HMAC secret, canonical ) )
//   Verification is FAIL-CLOSED on: bad/missing sig; script_sha256 != SHA-256(script);
//   actor.instance != this instance (cross-instance replay); issued_at outside ±freshness;
//   missing nonce. Replay is rejected by the scoped wrapper's DB-unique nonce INSERT.
//
// PUBLIC API (plan §P7 nonce-store fix):
//   verify(code, actor, sig) -> { verified:boolean, error? }   — HMAC + script-bind + instance-
//                                                                claim + freshness. NO nonce
//                                                                single-use, NO eval.
//   execute(code, actor, sig, auditId) -> { serialized, error } — re-verifies the HMAC-bound actor
//                                                                and the wrapper-created running
//                                                                audit row + consumed nonce before
//                                                                new Function eval + serialize.
// SINGLE-USE NONCE consumption is now owned by the SCOPED Fluent wrapper (it INSERTs into the
// scoped x_1793136_mcp_nonce table, which has a DB UNIQUE index — the live, deployable store).
// The core does not consume nonces, but execute() checks that the scoped nonce row already exists
// before eval. The nonce STAYS in the signed canonical — the HMAC still covers it.

var x_mcp_verify = Class.create();
(function () {
  var HMAC_SECRET_CURRENT = "__X_MCP_EXECUTOR_HMAC_KEY__";
  var HMAC_SECRET_PREV = "__X_MCP_EXECUTOR_HMAC_KEY_PREV__";

  // The installer replaces the placeholders above with JSON string literals. Untemplated source
  // fails closed, so the scoped executor role never needs read access to the HMAC properties.
  function secret(value) {
    var s = String(value || '');
    if (!s) return '';
    if (s.indexOf('__X_MCP_EXECUTOR_HMAC_KEY') === 0) return '';
    return s;
  }

  function currentSecret() {
    return secret(HMAC_SECRET_CURRENT);
  }

  function previousSecret() {
    return secret(HMAC_SECRET_PREV);
  }

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
    // GlideCertificateEncryption.generateMac(key, algorithm, data) returns base64. The target
    // family/build verifier gate proves this still matches the host signer before release.
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
  // subdomain prefix and fail closed if the property is unreadable.
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

  // PUBLIC: verify the signed actor (HMAC + script-bind + instance-claim + freshness + nonce
  // presence). NO nonce single-use and NO eval — the scoped wrapper interleaves verify ->
  // consume-nonce -> execute so the single-use INSERT lands on the deployable scoped
  // x_1793136_mcp_nonce table (plan §P7).
  // Returns { verified:true } or { verified:false }.
  verify: function (script, actor, sig) {
    if (!sig) return { verified: false };
    actor = actor || {};

    // (a) script binding.
    // GlideDigest.getSHA256Base64(String) must hash the UTF-8 bytes of the
    // input to match the host's WebCrypto SHA-256 over `TextEncoder().encode(input)` (UTF-8).
    // The target family/build verifier gate must cover this before release.
    var expectedHash = new GlideDigest().getSHA256Base64(String(script || ''));
    if (expectedHash !== String(actor.script_sha256 || '')) return { verified: false };

    // (b) instance claim — reject cross-instance replay (a payload signed for another PDI).
    if (!this._instanceMatches(actor.instance)) return { verified: false };

    // (c) freshness
    var now = new GlideDateTime().getNumericValue();
    var issued = parseInt(actor.issued_at, 10);
    if (isNaN(issued) || Math.abs(now - issued) > this.FRESHNESS_MS) return { verified: false };

    // (d) signed nonce presence. The scoped wrapper consumes it after verify() succeeds.
    if (!String(actor.nonce || '')) return { verified: false };

    // (e) signature (current key, then previous key during rotation). The key material is injected
    // into this admin-installed global Script Include; it is NOT read from executor-role-visible
    // scoped properties at request time.
    var canonical = this._canonical(actor);
    var keyCur = currentSecret();
    var keyPrev = previousSecret();
    var ok = keyCur && this._constantTimeEquals(this._hmacBase64(keyCur, canonical), sig);
    if (!ok && keyPrev) ok = this._constantTimeEquals(this._hmacBase64(keyPrev, canonical), sig);
    if (!ok) return { verified: false };

    // Nonce single-use is NOT checked here — the caller consumes it (INSERT-as-arbiter on the
    // scoped x_1793136_mcp_nonce table) AFTER this returns verified:true and BEFORE execute().
    return { verified: true };
  },

  _nonceConsumed: function (nonce) {
    var n = String(nonce || '');
    if (!n) return false;
    var gr = new GlideRecord('x_1793136_mcp_nonce');
    gr.addQuery('value', n);
    gr.setLimit(1);
    gr.query();
    return gr.next();
  },

  _auditCapabilityValid: function (auditId, code, actor) {
    var id = String(auditId || '');
    if (!/^[0-9a-f]{32}$/.test(id)) return false;
    var audit = new GlideRecord('x_1793136_mcp_audit_log');
    if (!audit.get(id)) return false;
    var codeHash = new GlideDigest().getSHA256Base64(String(code || ''));
    return String(audit.status || '') === 'running' &&
      String(audit.request_id || '') === String(actor.request_id || '') &&
      String(audit.code_hash || '') === codeHash;
  },

  // PUBLIC: eval the verified script (plan §P7 item 2 / finding 6). The scoped wrapper calls this
  // ONLY AFTER its audit row exists and its single-use nonce INSERT succeeds. Direct callers still
  // need a fresh host-signed actor, the unreturned running audit sys_id, and proof that the nonce
  // has already been consumed; otherwise execute() refuses eval.
  execute: function (code, actor, sig, auditId) {
    var v;
    try {
      v = this.verify(code, actor || {}, sig);
    } catch (ve) {
      v = { verified: false };
    }
    if (!v.verified) return { serialized: null, error: 'actor_signature_invalid' };
    if (!this._auditCapabilityValid(auditId, code, actor || {}) || !this._nonceConsumed((actor || {}).nonce)) {
      return { serialized: null, error: 'capability_required' };
    }
    return this._executeCode(code);
  },

  _executeCode: function (code) {
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

  type: 'x_mcp_verify',
};
})();
