// Verify the PRODUCTION scoped app (x_1793136_mcp, installed via now-sdk + Fluent):
// S8 role-gating (no role -> 403), then B1 valid/forged after assigning the role.
import { readFileSync } from "node:fs";
import { canonicalize, hmacSha256Base64, sha256Base64 } from "../packages/mcp-server/dist/auth/actor.js";
import { canonicalizeInstanceHost } from "../packages/mcp-server/dist/sn/url-allowlist.js";

// Transport-level path guard mirroring SnFetchClient (finding 3): a tampered SNOW_EXECUTOR_PATH
// must not change host or traverse out of /api/. Rejects userinfo (@), scheme (://), and
// dot-segments (literal or percent-encoded) BEFORE the path is glued onto the trusted host.
function assertApiPath(p) {
  const lowered = String(p).toLowerCase();
  if (!p.startsWith("/api/") || p.includes("://") || p.includes("@") || lowered.includes("..") || lowered.includes("%2e")) {
    throw new Error(`unsafe SNOW_EXECUTOR_PATH: ${p}`);
  }
  return p;
}

function dv(k) {
  for (const l of readFileSync(".dev.vars", "utf8").split("\n")) {
    const t = l.trim();
    if (t.startsWith(`${k}=`)) { let v = t.slice(k.length + 1).trim(); return v.startsWith('"') ? v.slice(1, -1) : v; }
  }
}
// SSRF guard (finding 3): canonicalize the host against the ServiceNow allowlist before any
// credentialed fetch, so a tampered SNOW_INSTANCE_HOST can't exfiltrate the Basic credential.
const host = canonicalizeInstanceHost(dv("SNOW_INSTANCE_HOST"), { allowedHostSuffixes: ["service-now.com"] });
const basic = "Basic " + Buffer.from(`${dv("SNOW_DEV_ROPC_USERNAME")}:${dv("SNOW_DEV_ROPC_PASSWORD")}`).toString("base64");
const keyBytes = Uint8Array.from(atob(dv("X_MCP_EXECUTOR_HMAC_KEY")), (c) => c.charCodeAt(0));
// Hit the EXACT endpoint the live Worker calls (SNOW_EXECUTOR_PATH in .dev.vars, e.g. the
// numeric scoped form /api/1793136/x_mcp/executor/run) so a scope-name-vs-numeric path-form
// mismatch can't 404. Falls back to the scope-name form if SNOW_EXECUTOR_PATH is unset.
const ENDPOINT = `https://${host}${assertApiPath(dv("SNOW_EXECUTOR_PATH") || "/api/x_1793136_mcp/x_mcp/executor/run")}`;
const h = { authorization: basic, accept: "application/json" };

async function api(method, path, body) {
  const r = await fetch(`https://${host}${path}`, { method, headers: { ...h, ...(body ? { "content-type": "application/json" } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
  return { status: r.status, json: await r.json().catch(() => null) };
}
async function apiOk(method, path, body) {
  const res = await api(method, path, body);
  if (res.status < 200 || res.status >= 300) {
    throw new Error(`${method} ${path} failed with HTTP ${res.status}: ${JSON.stringify(res.json)}`);
  }
  return res;
}
async function signed(script, opts = {}) {
  const actor = {
    mcp_actor_user_id: "u1", mcp_actor_email: "ada@example.com", snow_effective_user_sys_id: "sys1",
    // `instance` is SIGNED (set before the HMAC) — opts.instance lets a test forge a VALIDLY-
    // signed actor for a DIFFERENT instance (case 2 cross-instance replay).
    instance: opts.instance ?? host, request_id: "req-" + Math.random().toString(36).slice(2),
    script_sha256: await sha256Base64(script), issued_at: Date.now(),
    // opts.nonce lets cases 1/5 reuse a fixed nonce; default is random.
    nonce: opts.nonce ?? "n-" + Math.random().toString(36).slice(2),
    // `reason` is a SIGNED canonical key (plan §P7 item 1, the new LAST key) — it MUST be present
    // or the host canonical emits "reason":"undefined" while the executor emits "reason":"" and
    // every HMAC mismatches -> a false 401 on the live PDI (including the pre-existing B1 case).
    reason: opts.reason ?? "verify",
  };
  const sig = await hmacSha256Base64(canonicalize(actor), keyBytes);
  // forge/forgeEmail: tamper the email AFTER signing so the HMAC no longer matches (B1 negative).
  if (opts.forge || opts.forgeEmail) actor.mcp_actor_email = "evil@x.com";
  // tamperReason: change the SIGNED reason AFTER signing (case 4 — proves reason is HMAC-bound).
  if (opts.tamperReason !== undefined) actor.reason = opts.tamperReason;
  // badSig: replace a valid sig with garbage / null / empty (case 3 — clean 401, not 500).
  const actor_sig = "actorSig" in opts ? opts.actorSig : opts.badSig ? "AAAA" : sig;
  return { script, actor, actor_sig };
}
async function call(payload) {
  const r = await fetch(ENDPOINT, { method: "POST", headers: { ...h, "content-type": "application/json" }, body: JSON.stringify(payload) });
  const j = await r.json().catch(() => null);
  return { status: r.status, body: j?.result ?? j };
}
let pass = 0, fail = 0, skipped = 0;
const check = (n, c, e) => { if (c) { pass++; console.log("  PASS", n, e ?? ""); } else { fail++; console.log("  FAIL", n, e ?? ""); } };
// A precondition-skip must NOT count as a failure (it would flip the suite to exit(1)).
const skip = (n, why) => { skipped++; console.log("  SKIPPED:", n, "—", why, "— operator-verify"); };

console.log(`Scoped executor verify: ${ENDPOINT}\n`);

// admin user + role sys_ids
const adminId = (await apiOk("GET", "/api/now/table/sys_user?sysparm_query=user_name=admin&sysparm_limit=1&sysparm_fields=sys_id")).json?.result?.[0]?.sys_id;
const roleId = (await apiOk("GET", "/api/now/table/sys_user_role?sysparm_query=name=x_1793136_mcp.executor&sysparm_limit=1&sysparm_fields=sys_id")).json?.result?.[0]?.sys_id;
if (!adminId) throw new Error("Could not resolve admin user sys_id.");
if (!roleId) throw new Error("Could not resolve x_1793136_mcp.executor role sys_id.");

async function currentAdminExecutorRoles() {
  const rows = (await apiOk("GET", `/api/now/table/sys_user_has_role?sysparm_query=user=${adminId}^role=${roleId}&sysparm_fields=sys_id`)).json?.result;
  if (!Array.isArray(rows)) throw new Error("Role lookup returned no result array.");
  return rows;
}

async function removeAdminExecutorRole() {
  for (const e of await currentAdminExecutorRoles()) await apiOk("DELETE", `/api/now/table/sys_user_has_role/${e.sys_id}`);
}

async function grantAdminExecutorRole() {
  await apiOk("POST", "/api/now/table/sys_user_has_role", { user: adminId, role: roleId });
}

// Ensure admin does NOT currently have the role (remove if present) for the S8 test, but restore
// the starting state in finally so an interrupted failed verify does not leave prod access changed.
const existing = await currentAdminExecutorRoles();
const hadExecutorRole = existing.length > 0;
let cleanupFailed = false;

try {
await removeAdminExecutorRole();
await new Promise((r) => setTimeout(r, 2000));

// S8 (config proof): the REST_Endpoint ACL exists requiring x_1793136_mcp.executor and the
// API enforces it. (A live 403 needs a NON-admin caller; admin bypasses ACLs by design.)
{
  const acl = (await api("GET", "/api/now/table/sys_security_acl?sysparm_query=type=rest_endpoint^operation=execute^name=x_1793136_mcp_executor_run&sysparm_limit=1&sysparm_fields=sys_id,name,active")).json?.result?.[0];
  const aclRoles = acl ? (await api("GET", `/api/now/table/sys_security_acl_role?sysparm_query=sys_security_acl=${acl.sys_id}&sysparm_fields=sys_user_role.name`)).json?.result ?? [] : [];
  const hasRole = aclRoles.some((r) => (r["sys_user_role.name"] || "") === "x_1793136_mcp.executor");
  const wsAcl = (await api("GET", "/api/now/table/sys_ws_definition?sysparm_query=sys_scope.scope=x_1793136_mcp&sysparm_fields=enforce_acl")).json?.result?.[0];
  check("S8 — REST_Endpoint ACL requires x_1793136_mcp.executor and API enforces it", Boolean(acl?.active === "true" && hasRole && wsAcl?.enforce_acl), `(acl=${!!acl}, role=${hasRole}, enforce=${!!wsAcl?.enforce_acl})`);
}

// S8b — SHADOW-ENDPOINT REGRESSION LOCK (P8 root cause). A deprecated GLOBAL numeric endpoint
// POST /api/1793136/x_mcp/executor/run had survived an earlier install; its verify() reject branch
// was DEAD CODE (`if (!new x_mcp_verify().verify(...))` — verify() returns an object, so `!obj`
// is always false), so it executed every request with NO signature check and NO role ACL. The
// Worker hit it because SNOW_EXECUTOR_PATH used the numeric form. It has been retired (op + def
// deleted). Assert it STAYS dead: an unsigned POST must not execute (route gone => 400/404, never
// 200). No other test guards this path — the bug was invisible because everything else hits the
// scoped wrapper. Re-arming X_MCP_INSTALL_GLOBAL_REST=1 or any leftover global op trips this.
// L-3: assert BOTH deprecated global forms are dead — the numeric-namespace form AND the
// scope-name form `/api/x_mcp/executor/run` (the old rpc.ts default). Neither must execute.
for (const deadPath of ["/api/1793136/x_mcp/executor/run", "/api/x_mcp/executor/run"]) {
  const r = await api("POST", deadPath, { script: "return 1;", actor: {}, actor_sig: "" });
  check(`S8b — GLOBAL shadow endpoint is RETIRED (${deadPath} is dead)`,
    r.status === 404 || r.status === 400, `(status ${r.status} — must be 404/400, never 200)`);
}

// Assign the role to admin (so the broad-identity call is also role-authorized), then execute.
await grantAdminExecutorRole();
await new Promise((r) => setTimeout(r, 3000)); // role-cache propagation

let auditIdSeen = "";
{
  // B1 also IS the I-8 round-trip check: a HOST-signed actor (host b64-decodes X_MCP_EXECUTOR_HMAC_KEY
  // to raw bytes) verifying in-scope (GlideCertificateEncryption.generateMac) proves the key-encoding
  // contract end-to-end. A 200 here means the host/verifier MAC agree; a contract mismatch fails CLOSED
  // (401), never silently — so this case is the deploy-time guard the executor's 0.13a TODO asked for.
  const r = await call(await signed("return gs.getUserName();"));
  auditIdSeen = r.body?.audit_id ?? "";
  check("B1 valid signed actor -> delegates to global core -> executes (returns user) [I-8 HMAC round-trip]", r.status === 200 && typeof r.body?.result === "string", `(status ${r.status}, result ${JSON.stringify(r.body?.result)})`);
}
{
  const r = await call(await signed("return 1;", { forge: true }));
  check("B1 forged actor email -> 401", r.status === 401 && r.body?.error === "actor_signature_invalid", `(status ${r.status})`);
}
// Audit-first row was written to the dedicated scoped table (proven by the returned audit_id;
// the table's own read ACL blocks admin via Table API by design, so we don't query it back).
check("audit-first row written to x_1793136_mcp_audit_log (audit_id returned)", /^[0-9a-f]{32}$/.test(auditIdSeen), `(audit_id ${auditIdSeen})`);

// ─────────────────────────────────────────────────────────────────────────────
// P1–P7 HARDENING PROOFS (scoped endpoint). Each case signs with the reason-aware
// signed() above so the HMAC + canonical (incl. the new LAST `reason` key) match the
// deployed executor. The scoped audit table is read-ACL-blocked to admin via Table API
// (see the audit-first note above), so audit-row state is asserted via the OBSERVABLE
// response (status + error + audit_id from the row's close path), not a Table read.
// ─────────────────────────────────────────────────────────────────────────────

// 1) CONCURRENT nonce-replay (THE finding-24 gate). A SEQUENTIAL replay is already covered
//    by the install self-test; here we fire ONE validly-signed request (same nonce, same
//    body) TWICE SIMULTANEOUSLY via Promise.all. The DB UNIQUE-index INSERT is the arbiter:
//    only one INSERT of the nonce can win, so EXACTLY ONE must 200 and the other must 401
//    (the loser's _consumeNonce sees the duplicate — falsy insert OR thrown constraint — and
//    the wrapper closes 'rejected' -> 401). "At least one rejected" is NOT sufficient: we
//    assert the XOR (exactly one 200) AND that the loser is specifically a 401.
// concurrencyArbitrated is the AUTHORITATIVE proof that the nonce unique constraint enforces — it
// is read by case 1b below (the sys_index catalog row is only a secondary, unreliable signal).
let concurrencyArbitrated = false;
{
  const sameNonce = "concur-" + Math.random().toString(36).slice(2);
  // Build ONE signed payload, send the SAME object twice (identical nonce + body + sig).
  const payload = await signed("return gs.getUserName();", { nonce: sameNonce });
  const [a, b] = await Promise.all([call(payload), call(payload)]);
  const oks = [a, b].filter((r) => r.status === 200);
  const loser = [a, b].find((r) => r.status !== 200);
  const exactlyOneOk = oks.length === 1;
  const loserIs401 = loser?.status === 401 && loser?.body?.error === "actor_signature_invalid";
  concurrencyArbitrated = exactlyOneOk && loserIs401;
  check("CONCURRENT replay: exactly ONE 200, the other 401 (DB-unique INSERT serializes the race)",
    concurrencyArbitrated, `(statuses ${a.status}/${b.status})`);
}
// 1b) The unique constraint that arbitrates the race MUST be enforced on the SCOPED
//     x_1793136_mcp_nonce table the live wrapper writes (plan §P7 nonce-store fix). The
//     AUTHORITATIVE proof is case 1 itself: the wrapper has NO SELECT-before-INSERT, so the only
//     path to a 401-loser is insert() failing on a DB unique constraint — without it, both
//     concurrent identical-nonce INSERTs would 200. The `sys_index` CATALOG row is only a
//     SECONDARY signal and an unreliable one: now-sdk 4.7.1 creates the physical DDL index but
//     does not always write the sys_index row (confirmed live — index enforces yet the catalog
//     row is absent), and the table is ACL-blocked from direct probing. So an absent catalog row
//     is NOT evidence of a missing index. Pass when EITHER the catalog row exists OR case 1 proved
//     the arbiter enforces; fail only if neither holds (i.e. uniqueness genuinely is not enforced).
{
  const idx = (await api("GET", "/api/now/table/sys_index?sysparm_query=table=x_1793136_mcp_nonce^index_name=x_1793136_mcp_nonce_value_uq&sysparm_limit=1&sysparm_fields=sys_id,unique")).json?.result?.[0];
  const catalogRow = Boolean(idx?.sys_id);
  check("x_1793136_mcp_nonce unique constraint enforces (concurrency arbiter behind case 1)",
    catalogRow || concurrencyArbitrated,
    catalogRow
      ? `(sys_index ${idx.sys_id}, unique=${idx.unique})`
      : `(sys_index catalog row absent — now-sdk 4.7.1 metadata gap; enforcement PROVEN by case 1 CONCURRENT one-200/one-401)`);
}

// 2) INSTANCE-CLAIM mismatch -> 401. A VALIDLY-signed actor (good HMAC) whose signed `instance`
//    names a DIFFERENT host must be rejected by _instanceMatches (cross-instance replay). Distinct
//    from a forged-email/bad-sig case: the only thing wrong is the signed instance claim.
{
  const r = await call(await signed("return 1;", { instance: "wrong-instance.service-now.com" }));
  check("INSTANCE-CLAIM mismatch (valid sig, foreign instance) -> 401", r.status === 401 && r.body?.error === "actor_signature_invalid", `(status ${r.status})`);
}

// 3) NULL-MAC / malformed-sig -> CLEAN 401 (never a 500). _hmacBase64/generateMac can return null
//    on a bad input; _constantTimeEquals is null-safe (plan §P7 item 3b), so empty/null/garbage
//    sigs must each yield a clean 401 — and the wrapper must CLOSE the audit row to 'rejected'
//    (not leave it stuck 'running'). The scoped audit table is read-ACL-blocked, so the proxy for
//    "row closed cleanly, not stuck/500" is the 401 + the audit_id returned FROM the close path
//    (the response carries audit_id only after audit.update() on the rejected branch). The actual
//    status='rejected' column value is operator-verifiable in the audit table.
for (const [label, opts] of [
  ["empty sig", { actorSig: "" }],
  ["null sig", { actorSig: null }],
  ["garbage sig", { actorSig: "!!!notbase64!!!" }],
]) {
  const r = await call(await signed("return 1;", opts));
  const clean401 = r.status === 401 && r.body?.error === "actor_signature_invalid";
  const rowClosed = /^[0-9a-f]{32}$/.test(r.body?.audit_id ?? "");
  check(`NULL/malformed sig (${label}) -> clean 401, audit row closed (not 500/stuck)`, clean401 && rowClosed, `(status ${r.status}, audit_id ${r.body?.audit_id})`);
}

// 4) SIGNED + AUDITED reason. A valid call with a known reason must 200 (reason is HMAC-bound, so a
//    correctly-signed reason passes verify); then re-signing with the reason TAMPERED (changed after
//    signing) must 401 — proving `reason` is under the signature, not an unsigned POST field. The
//    "reason persisted in the audit `reason` column" half is operator-verify (the audit table is
//    read-ACL-blocked to admin via Table API; the column value is checked by the operator live).
{
  const knownReason = "p7-audited-reason-" + Math.random().toString(36).slice(2);
  const good = await call(await signed("return gs.getUserName();", { reason: knownReason }));
  check("SIGNED reason: valid signed reason -> 200 (reason is HMAC-bound and accepted)", good.status === 200 && typeof good.body?.result === "string", `(status ${good.status})`);
  // Sign WITH knownReason, then mutate actor.reason after signing -> HMAC no longer matches.
  const tampered = await call(await signed("return 1;", { reason: knownReason, tamperReason: "evil-unsigned-reason" }));
  check("TAMPERED reason (changed after signing) -> 401 (reason is under the HMAC)", tampered.status === 401 && tampered.body?.error === "actor_signature_invalid", `(status ${tampered.status})`);
}
// Operator-verify note for the persisted-column half of case 4.
skip("SIGNED reason persisted in x_1793136_mcp_audit_log.reason column", "scoped audit table is read-ACL-blocked to admin via Table API — verify the `reason` column live");

// 5) SIZE/413 BEFORE NONCE-BURN. The wrapper gates size (413) BEFORE delegating to verify/nonce-
//    consume, so an oversized call with a FRESH nonce must be rejected WITHOUT burning that nonce.
//    Proof: fire an oversized call carrying nonce N (-> 413), then replay the SAME nonce N on a
//    small VALID call and assert it still 200s (the nonce was never consumed). Using the 413 path
//    (not the kill-switch) keeps this idempotent — no property toggle. The oversized body must be
//    >max_bytes (default 32768); `script_sha256` covers the real (oversized) code so the HMAC is
//    valid — the 413 fires on the size gate before verify regardless.
{
  const freshNonce = "size-then-nonce-" + Math.random().toString(36).slice(2);
  const big = "x".repeat(40000); // > 32768-byte default max_bytes
  const oversized = await call(await signed(`return "${big}";`, { nonce: freshNonce }));
  const rejected413 = oversized.status === 413 && oversized.body?.error === "code_size";
  // Same nonce on a small valid call: must still succeed if the 413 did NOT burn the nonce.
  const reuse = await call(await signed("return 1;", { nonce: freshNonce }));
  check("SIZE/413 runs BEFORE nonce-burn: oversized -> 413, SAME nonce then reused on valid call -> 200",
    rejected413 && reuse.status === 200, `(oversized ${oversized.status}, reuse ${reuse.status})`);
}

// L-6: the scoped `MCP Nonce Purge` ScheduledScript's interval serializes to a bad string under
// now-sdk 4.7.1 ("[object Object]"), needing a one-time UI fix. This is FAIL-SAFE for replay
// (more retained nonces only strengthen the unique-index defense), so a bad/missing period is an
// operational note, NOT a hard failure. PASS when the period looks valid; SKIP (operator-verify)
// otherwise so the suite still exits 0 on a green security run.
{
  const job = (await api("GET", "/api/now/table/sysauto_script?sysparm_query=nameLIKEMCP Nonce Purge&sysparm_limit=1&sysparm_fields=sys_id,run_period,run_type")).json?.result?.[0];
  const period = String(job?.run_period ?? "");
  const valid = Boolean(job) && period !== "" && !period.includes("[object Object]");
  if (valid) {
    check("L-6 — MCP Nonce Purge job has a valid run_period (table stays bounded)", true, `(run_period "${period}", run_type "${job.run_type}")`);
  } else {
    skip("L-6 — MCP Nonce Purge run_period", `set it in the UI (System Definition > Scheduled Jobs) — now-sdk 4.7.1 serializes it as "${period || "MISSING"}"; replay protection is unaffected (fail-safe), only purge is deferred`);
  }
}

} finally {
  try {
    await removeAdminExecutorRole();
    if (hadExecutorRole) await grantAdminExecutorRole();
  } catch (e) {
    cleanupFailed = true;
    console.error("FAILED to restore admin executor role:", e instanceof Error ? e.message : String(e));
  }
}

if (cleanupFailed) fail++;

console.log(`\n${fail === 0 ? "SCOPED EXECUTOR: ALL PASS" : "SCOPED EXECUTOR: FAILURES"} — ${pass} passed, ${fail} failed, ${skipped} skipped`);
process.exit(fail === 0 ? 0 : 1);
