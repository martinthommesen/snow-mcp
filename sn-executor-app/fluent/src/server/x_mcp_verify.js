// Script Include: x_mcp_verify (GLOBAL scope). COPY of the canonical core at
// sn-executor-app/script-include/x_mcp_verify.js.
//
// The class body below MUST stay byte-consistent with the canonical file. Do not
// hand-fork: a divergence in `_canonical` or the ASCII escaper silently breaks
// every signature (B1). scripts/executor-install.mjs installs the canonical file
// directly, so this copy is for Fluent app source/deploy only.
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
// PUBLIC API (plan §P7 nonce-store fix):
//   verify(code, actor, sig) -> { verified:boolean, error? }   — HMAC + script-bind + instance-
//                                                                claim + freshness. NO nonce
//                                                                single-use, NO eval.
//   execute(code, nonce, cap) -> { serialized, error }        — cap-gated new Function eval +
//                                                                serialize (finding 6). cap is
//                                                                minted by the scoped wrapper
//                                                                after the nonce INSERT.
// SINGLE-USE NONCE consumption is now owned by the SCOPED Fluent wrapper (it INSERTs into the
// scoped x_1793136_mcp_nonce table, which has a DB UNIQUE index — the live, deployable store).
// The core no longer touches any nonce table (the global x_mcp_nonce table could not be created
// via the Table API). The nonce STAYS in the signed canonical — the HMAC still covers it.

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

  // PUBLIC: verify the signed actor (HMAC + script-bind + instance-claim + freshness). NO nonce
  // single-use and NO eval — the scoped wrapper interleaves verify -> consume-nonce -> execute so
  // the single-use INSERT lands on the deployable scoped x_1793136_mcp_nonce table (plan §P7).
  // Returns { verified:true } or { verified:false }.
  verify: function (script, actor, sig) {
    if (!sig) return { verified: false };

    // (a) script binding.
    // ⚠️ 0.13a seam: GlideDigest.getSHA256Base64(String) must hash the UTF-8 bytes of the
    // input to match the host's WebCrypto SHA-256 over `TextEncoder().encode(input)` (UTF-8).
    // If SN hashes UTF-16/Latin-1, non-ASCII scripts break signatures. Source-only here;
    // proven on a live PDI at P8 (see docs/OPEN_QUESTIONS.md). ASCII scripts are unaffected.
    var expectedHash = new GlideDigest().getSHA256Base64(String(script || ''));
    if (expectedHash !== String(actor.script_sha256 || '')) return { verified: false };

    // (b) instance claim — reject cross-instance replay (a payload signed for another PDI).
    if (!this._instanceMatches(actor.instance)) return { verified: false };

    // (c) freshness
    var now = new GlideDateTime().getNumericValue();
    var issued = parseInt(actor.issued_at, 10);
    if (isNaN(issued) || Math.abs(now - issued) > this.FRESHNESS_MS) return { verified: false };

    // (d) signature (current key, then previous key during rotation)
    var canonical = this._canonical(actor);
    var keyCur = gs.getProperty('x_1793136_mcp.executor.hmac_secret', '');
    var keyPrev = gs.getProperty('x_1793136_mcp.executor.hmac_secret_prev', '');
    var ok = keyCur && this._constantTimeEquals(this._hmacBase64(keyCur, canonical), sig);
    if (!ok && keyPrev) ok = this._constantTimeEquals(this._hmacBase64(keyPrev, canonical), sig);
    if (!ok) return { verified: false };

    // Nonce single-use is NOT checked here — the caller consumes it (INSERT-as-arbiter on the
    // scoped x_1793136_mcp_nonce table) AFTER this returns verified:true and BEFORE execute().
    return { verified: true };
  },

  // PUBLIC: eval the verified script (plan §P7 item 2 / finding 6). REQUIRES a capability that
  // only a holder of the executor HMAC secret can mint:
  //   cap = base64(HMAC(hmac_secret, 'x_mcp_exec_cap|' + nonce + '|' + SHA256(code)))
  // The SCOPED wrapper mints it (it reads the scoped secret) ONLY AFTER the single-use nonce
  // INSERT succeeds, then passes (code, nonce, cap) here. A caller that instantiates this global
  // core and calls execute() DIRECTLY — bypassing verify -> consume-nonce — cannot produce a
  // valid cap (no secret), and re-running verify() alone does NOT mint one. _hmacBase64 takes the
  // key as a parameter, so it is not a minting oracle. FAIL-CLOSED: a missing secret or any cap
  // mismatch refuses eval. Closes the public-execute() HMAC/nonce-replay bypass.
  execute: function (code, nonce, cap) {
    var secret = gs.getProperty('x_1793136_mcp.executor.hmac_secret', '');
    var codeHash = new GlideDigest().getSHA256Base64(String(code || ''));
    var expected = this._hmacBase64(secret, 'x_mcp_exec_cap|' + String(nonce || '') + '|' + codeHash);
    if (!secret || !this._constantTimeEquals(cap, expected)) {
      return { serialized: null, error: 'capability_required' };
    }
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
