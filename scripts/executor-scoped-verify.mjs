// Verify the PRODUCTION scoped app (x_1793136_mcp, installed via now-sdk + Fluent):
// S8 role-gating (no role -> 403), then B1 valid/forged after assigning the role.
import { existsSync, readFileSync } from "node:fs";
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
  if (process.env[k]) return process.env[k];
  if (!existsSync(".dev.vars")) return undefined;
  for (const l of readFileSync(".dev.vars", "utf8").split("\n")) {
    const t = l.trim();
    if (t.startsWith(`${k}=`)) { let v = t.slice(k.length + 1).trim(); return v.startsWith('"') ? v.slice(1, -1) : v; }
  }
}
// SSRF guard (finding 3): canonicalize the host against the ServiceNow allowlist before any
// credentialed fetch, so a tampered SNOW_INSTANCE_HOST can't exfiltrate the Basic credential.
const host = canonicalizeInstanceHost(dv("SNOW_INSTANCE_HOST"), { allowedHostSuffixes: ["service-now.com"] });
function basicAuth(username, password) {
  return "Basic " + Buffer.from(`${username}:${password}`).toString("base64");
}
const adminBasic = basicAuth(dv("SNOW_DEV_ROPC_USERNAME"), dv("SNOW_DEV_ROPC_PASSWORD"));
const keyBytes = Uint8Array.from(atob(dv("X_MCP_EXECUTOR_HMAC_KEY")), (c) => c.charCodeAt(0));
// Hit the EXACT endpoint the live Worker calls (SNOW_EXECUTOR_PATH in .dev.vars, e.g. the
// numeric scoped form /api/1793136/x_mcp/executor/run) so a scope-name-vs-numeric path-form
// mismatch can't 404. Falls back to the scope-name form if SNOW_EXECUTOR_PATH is unset.
const ENDPOINT = `https://${host}${assertApiPath(dv("SNOW_EXECUTOR_PATH") || "/api/x_1793136_mcp/x_mcp/executor/run")}`;
let endpointAuth = adminBasic;
const NONCE_PURGE_JOB_NAME = "MCP Nonce Purge";
const NONCE_PURGE_RUN_PERIOD = "1970-01-01 00:15:00";
const EXECUTOR_TOGGLE_NAMES = [
  "x_1793136_mcp.executor.enabled",
  "x_1793136_mcp.executor.run_server_script_enabled",
];
const HMAC_PROPERTY_NAMES = [
  "x_1793136_mcp.executor.hmac_secret",
  "x_1793136_mcp.executor.hmac_secret_prev",
];

async function api(method, path, body, authorization = adminBasic) {
  const r = await fetch(`https://${host}${path}`, {
    method,
    headers: { authorization, accept: "application/json", ...(body ? { "content-type": "application/json" } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  return { status: r.status, json: await r.json().catch(() => null) };
}
async function apiOk(method, path, body, authorization = adminBasic) {
  const res = await api(method, path, body, authorization);
  if (res.status < 200 || res.status >= 300) {
    throw new Error(`${method} ${path} failed with HTTP ${res.status}: ${JSON.stringify(res.json)}`);
  }
  return res;
}
async function getProperty(name) {
  const query = encodeURIComponent(`name=${name}`);
  const row = (await apiOk("GET", `/api/now/table/sys_properties?sysparm_query=${query}&sysparm_limit=1&sysparm_fields=sys_id,name,value`)).json?.result?.[0];
  if (!row?.sys_id) throw new Error(`Required executor property ${name} is missing; install the scoped app and run scripts/executor-install.mjs first.`);
  return { name, sys_id: row.sys_id, value: String(row.value ?? "") };
}
async function setPropertyValue(prop, value) {
  await apiOk("PATCH", `/api/now/table/sys_properties/${prop.sys_id}`, { value });
}
async function enableExecutorTogglesForVerify() {
  const props = [];
  for (const name of EXECUTOR_TOGGLE_NAMES) props.push(await getProperty(name));
  for (const prop of props) {
    if (prop.value !== "true") await setPropertyValue(prop, "true");
  }
  return props;
}
async function restoreExecutorToggles(props) {
  for (const prop of props) await setPropertyValue(prop, prop.value);
}
function randomPassword() {
  return `McpVerify-${crypto.randomUUID()}-${crypto.randomUUID()}`;
}
async function createExecutorOnlyPrincipal(roleId) {
  const configuredUser = dv("SNOW_EXECUTOR_TEST_USERNAME");
  const configuredPassword = dv("SNOW_EXECUTOR_TEST_PASSWORD");
  if (configuredUser || configuredPassword) {
    if (!configuredUser || !configuredPassword) {
      throw new Error("Set both SNOW_EXECUTOR_TEST_USERNAME and SNOW_EXECUTOR_TEST_PASSWORD, or set neither to create a temporary executor-only user.");
    }
    const query = encodeURIComponent(`user_name=${configuredUser}`);
    const user = (await apiOk("GET", `/api/now/table/sys_user?sysparm_query=${query}&sysparm_limit=1&sysparm_fields=sys_id,user_name`)).json?.result?.[0];
    if (!user?.sys_id) throw new Error("SNOW_EXECUTOR_TEST_USERNAME was not found in sys_user.");
    const roles = (await apiOk("GET", `/api/now/table/sys_user_has_role?sysparm_query=user=${user.sys_id}&sysparm_fields=role.name`)).json?.result ?? [];
    const roleNames = new Set(roles.map((r) => String(r["role.name"] ?? "")));
    check("executor test principal has executor role and is not admin",
      roleNames.has("x_1793136_mcp.executor") && !roleNames.has("admin"),
      `(executor=${roleNames.has("x_1793136_mcp.executor")}, admin=${roleNames.has("admin")})`);
    return {
      auth: basicAuth(configuredUser, configuredPassword),
      managed: false,
      userId: user.sys_id,
      roleId,
      roleGrantId: undefined,
      label: configuredUser,
    };
  }

  const randomSuffix = crypto.randomUUID().replaceAll("-", "").slice(0, 8);
  const username = `x_mcp_exec_verify_${Date.now()}_${randomSuffix}`;
  const password = randomPassword();
  let principal;
  try {
    const created = await apiOk("POST", "/api/now/table/sys_user", {
      user_name: username,
      first_name: "MCP",
      last_name: "Executor Verify",
      active: "true",
      locked_out: "false",
      password_needs_reset: "false",
      user_password: password,
    });
    const userId = created.json?.result?.sys_id;
    if (!userId) throw new Error("Temporary executor-only user creation did not return sys_id.");

    const auth = basicAuth(username, password);
    principal = { auth, managed: true, userId, roleId, roleGrantId: undefined, label: username };
    const noRole = await call(await signed("return 1;"), auth);
    check("S8 live — executor-only test principal without role cannot invoke endpoint",
      noRole.status === 403 || noRole.status === 401, `(status ${noRole.status})`);

    const grant = await apiOk("POST", "/api/now/table/sys_user_has_role", { user: userId, role: roleId });
    principal.roleGrantId = grant.json?.result?.sys_id;
    if (!principal.roleGrantId) throw new Error("Temporary executor-only role grant did not return sys_id.");
    await waitForExecutorRole(auth);
    return principal;
  } catch (e) {
    await cleanupExecutorOnlyPrincipal(principal);
    throw e;
  }
}
async function waitForExecutorRole(auth, timeoutMs = 15_000, stepMs = 1_000) {
  const deadline = Date.now() + timeoutMs;
  let lastStatus = "none";
  while (Date.now() < deadline) {
    const r = await call(await signed("return 1;"), auth);
    lastStatus = String(r.status);
    if (r.status >= 200 && r.status < 300) return;
    if (r.status !== 401 && r.status !== 403) {
      throw new Error(`Executor role readiness probe failed with HTTP ${r.status}: ${JSON.stringify(r.body)}`);
    }
    await new Promise((resolve) => setTimeout(resolve, stepMs));
  }
  throw new Error(`Executor role grant did not become effective before timeout; last status ${lastStatus}.`);
}
async function cleanupExecutorOnlyPrincipal(principal) {
  if (!principal?.managed) return;
  if (principal.roleGrantId) {
    await api("DELETE", `/api/now/table/sys_user_has_role/${principal.roleGrantId}`);
  } else if (principal.userId && principal.roleId) {
    const query = encodeURIComponent(`user=${principal.userId}^role=${principal.roleId}`);
    const grants = (await api("GET", `/api/now/table/sys_user_has_role?sysparm_query=${query}&sysparm_fields=sys_id`)).json?.result ?? [];
    for (const grant of grants) {
      if (grant?.sys_id) await api("DELETE", `/api/now/table/sys_user_has_role/${grant.sys_id}`);
    }
  }
  if (principal.userId) await api("DELETE", `/api/now/table/sys_user/${principal.userId}`);
}
async function assertExecutorCannotReadHmacProperties(executorAuth) {
  const query = encodeURIComponent(HMAC_PROPERTY_NAMES.map((name) => `name=${name}`).join("^OR"));
  const res = await api(
    "GET",
    `/api/now/table/sys_properties?sysparm_query=${query}&sysparm_fields=name,value&sysparm_limit=2`,
    undefined,
    executorAuth,
  );
  const rows = Array.isArray(res.json?.result) ? res.json.result : [];
  const responseBody = JSON.stringify(res.json ?? {});
  const rawSecret = dv("X_MCP_EXECUTOR_HMAC_KEY") ?? "";
  const noRawSecret = rawSecret.length > 0 && !responseBody.includes(rawSecret);
  const probeCompleted = res.status === 401 || res.status === 403 || (res.status >= 200 && res.status < 300);
  check(
    "HMAC secret isolation — executor-only principal cannot read raw HMAC properties",
    noRawSecret && probeCompleted,
    `(status ${res.status}, rows ${rows.length}, rawSecretExposed=${!noRawSecret})`,
  );
}
async function signed(script, opts = {}) {
  const actor = {
    mcp_actor_user_id: "u1", mcp_actor_email: "ada@example.com", snow_effective_user_sys_id: "sys1",
    // `instance` is SIGNED (set before the HMAC) — opts.instance lets a test forge a VALIDLY-
    // signed actor for a DIFFERENT instance (case 2 cross-instance replay).
    instance: opts.instance ?? host, request_id: `req-${crypto.randomUUID()}`,
    script_sha256: await sha256Base64(script), issued_at: Date.now(),
    // opts.nonce lets cases 1/5 reuse a fixed nonce; default is random.
    nonce: opts.nonce ?? `n-${crypto.randomUUID()}`,
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
  let actor_sig = sig;
  if ("actorSig" in opts) actor_sig = opts.actorSig;
  else if (opts.badSig) actor_sig = "AAAA";
  return { script, actor, actor_sig };
}
async function call(payload, authorization = endpointAuth) {
  const r = await fetch(ENDPOINT, { method: "POST", headers: { authorization, accept: "application/json", "content-type": "application/json" }, body: JSON.stringify(payload) });
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
let executorToggleSnapshot = [];
let executorPrincipal;
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

// Fresh installs deliberately default both kill switches off. Enable them only for this live
// verification window, then restore the operator's starting values in finally.
executorToggleSnapshot = await enableExecutorTogglesForVerify();

// Use a non-admin principal with only x_1793136_mcp.executor for the executor endpoint. The admin
// credential above remains setup/cleanup only and never proves endpoint-role or secret isolation.
executorPrincipal = await createExecutorOnlyPrincipal(roleId);
endpointAuth = executorPrincipal.auth;
await assertExecutorCannotReadHmacProperties(executorPrincipal.auth);

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
  const sameNonce = `concur-${crypto.randomUUID()}`;
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
  const knownReason = `p7-audited-reason-${crypto.randomUUID()}`;
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
  const freshNonce = `size-then-nonce-${crypto.randomUUID()}`;
  const big = "x".repeat(40000); // > 32768-byte default max_bytes
  const oversized = await call(await signed(`return "${big}";`, { nonce: freshNonce }));
  const rejected413 = oversized.status === 413 && oversized.body?.error === "code_size";
  // Same nonce on a small valid call: must still succeed if the 413 did NOT burn the nonce.
  const reuse = await call(await signed("return 1;", { nonce: freshNonce }));
  check("SIZE/413 runs BEFORE nonce-burn: oversized -> 413, SAME nonce then reused on valid call -> 200",
    rejected413 && reuse.status === 200, `(oversized ${oversized.status}, reuse ${reuse.status})`);
}

// L-6: the scoped `MCP Nonce Purge` ScheduledScript must have the exact 15-minute period generated
// from the Fluent Duration helper. Replay protection is still enforced by the unique nonce index,
// but retention must fail verification if the deploy leaves the purge job unbounded.
{
  const query = encodeURIComponent(`name=${NONCE_PURGE_JOB_NAME}`);
  const job = (await api("GET", `/api/now/table/sysauto_script?sysparm_query=${query}&sysparm_limit=1&sysparm_fields=sys_id,run_period,run_type`)).json?.result?.[0];
  const period = String(job?.run_period ?? "");
  check("L-6 — MCP Nonce Purge job has the 15-minute run_period (table stays bounded)",
    Boolean(job) && job.run_type === "periodically" && period === NONCE_PURGE_RUN_PERIOD,
    `(run_period "${period || "MISSING"}", run_type "${job?.run_type ?? "MISSING"}")`);
}

} finally {
  try {
    if (executorToggleSnapshot.length) await restoreExecutorToggles(executorToggleSnapshot);
  } catch (e) {
    cleanupFailed = true;
    console.error("FAILED to restore executor kill-switch properties:", e instanceof Error ? e.message : String(e));
  }
  try {
    await cleanupExecutorOnlyPrincipal(executorPrincipal);
  } catch (e) {
    cleanupFailed = true;
    console.error("FAILED to clean up executor-only verify principal:", e instanceof Error ? e.message : String(e));
  }
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
