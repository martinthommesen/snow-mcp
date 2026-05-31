import { describe, expect, it } from "vitest";
import { signActor, verifyActorSignatureLocal, canonicalize, type ActorClaims } from "../src/auth/actor.js";
import {
  assertActorPolicy,
  applyRowFilter,
  maskRow,
  assertRequestedFieldsAllowed,
  permissivePolicy,
  loadActorPolicy,
  type ActorPolicy,
  type PolicyEnv,
} from "../src/authz/actor-policy.js";
import { requireCapability, hasCapability, BUDGETS } from "../src/config.js";
import { RunBudget } from "../src/sn/run-budget.js";
import { McpToolError } from "../src/sn/errors.js";
import type { Mode } from "@servicenow-codemode/shared";

const claims: ActorClaims = {
  mcp_actor_user_id: "u1",
  mcp_actor_email: "ada@example.com",
  snow_effective_user_sys_id: "sys123",
  instance: "inst1.service-now.com",
  request_id: "req-1",
};
const HKEY = new Uint8Array(32).fill(7);
const SCRIPT = "return gs.getUserName();";
const T0 = 1_700_000_000_000;

// ─── §2.0 — actor signing (host side; authoritative verify is on ServiceNow) ──
const REASON = "rotate key";
describe("§2.0 actor signing", () => {
  it("canonicalization is deterministic and key-ordered", async () => {
    const a = await signActor({ claims, script: SCRIPT, issuedAt: T0, nonce: "n1", reason: REASON, hmacKey: HKEY });
    expect(canonicalize(a.actor).startsWith('{"mcp_actor_user_id":"u1"')).toBe(true);
    expect(typeof a.actor_sig).toBe("string");
  });

  it("signs `reason` as the LAST canonical key (P7: integrity-bound justification)", async () => {
    // Failing-first against the pre-P7 signer (which had no `reason` claim). The executor
    // _canonical in all THREE JS cores must list `reason` last too, or the HMAC breaks (B1).
    const a = await signActor({ claims, script: SCRIPT, issuedAt: T0, nonce: "n1", reason: REASON, hmacKey: HKEY });
    expect(a.actor.reason).toBe(REASON);
    const canon = canonicalize(a.actor);
    expect(canon).toContain(`,"nonce":"n1","reason":"rotate key"}`);
    expect(canon.endsWith(`,"reason":"rotate key"}`)).toBe(true);
  });

  it("a valid signature verifies (local mirror of the in-scope check)", async () => {
    const a = await signActor({ claims, script: SCRIPT, issuedAt: T0, nonce: "n1", reason: REASON, hmacKey: HKEY });
    expect(await verifyActorSignatureLocal(a, SCRIPT, HKEY, { now: T0 + 1000 })).toBe(true);
  });

  it("a tampered `reason` (re-signed payload field) fails the signature", async () => {
    const a = await signActor({ claims, script: SCRIPT, issuedAt: T0, nonce: "n1", reason: REASON, hmacKey: HKEY });
    const forged = { ...a, actor: { ...a.actor, reason: "forged justification" } };
    expect(await verifyActorSignatureLocal(forged, SCRIPT, HKEY, { now: T0 })).toBe(false);
  });

  it("canonical form is ASCII-only and deterministic even with non-ASCII actor fields", async () => {
    // Cross-engine linchpin: V8 and ServiceNow's engine must produce identical bytes.
    const unicodeClaims: ActorClaims = { ...claims, mcp_actor_email: " André@例子.com" };
    const a = await signActor({ claims: unicodeClaims, script: SCRIPT, issuedAt: T0, nonce: "n1", reason: REASON, hmacKey: HKEY });
    const canon = canonicalize(a.actor);
    // Pure ASCII (no code point >= 0x80) — non-ASCII escaped as \uXXXX.
    expect([...canon].every((ch) => ch.charCodeAt(0) < 0x80)).toBe(true);
    expect(canon).toContain("\\u00e9"); // é
    // Deterministic + round-trips locally.
    expect(canonicalize(a.actor)).toBe(canon);
    expect(await verifyActorSignatureLocal(a, SCRIPT, HKEY, { now: T0 })).toBe(true);
  });

  it("B1-shape: forged email, wrong key, stale time, or altered script all fail", async () => {
    const a = await signActor({ claims, script: SCRIPT, issuedAt: T0, nonce: "n1", reason: REASON, hmacKey: HKEY });

    const forged = { ...a, actor: { ...a.actor, mcp_actor_email: "evil@x.com" } };
    expect(await verifyActorSignatureLocal(forged, SCRIPT, HKEY, { now: T0 })).toBe(false);

    expect(await verifyActorSignatureLocal(a, SCRIPT, new Uint8Array(32).fill(8), { now: T0 })).toBe(false);
    expect(await verifyActorSignatureLocal(a, SCRIPT, HKEY, { now: T0 + 10 * 60_000 })).toBe(false); // stale
    expect(await verifyActorSignatureLocal(a, "return 1;", HKEY, { now: T0 })).toBe(false); // script mismatch
  });
});

// ─── §2.12 — ActorPolicy (gate B5) ────────────────────────────────────────────
describe("§2.12 ActorPolicy (B5)", () => {
  const policy: ActorPolicy = {
    allowedInstances: ["inst1.service-now.com"],
    tables: { allow: [/^incident$/, /^problem$/], deny: [/^sys_user$/] },
    fieldMasks: { incident: ["caller_id", "u_ssn"] },
    maxMode: "write",
    maxRowsPerRun: 1000,
    maxBytesPerRun: 1_000_000,
    rowFilters: { incident: "active=true" },
  };

  it("denies a non-allowlisted instance", () => {
    expect(() => assertActorPolicy(policy, { instance: "evil.service-now.com", table: "incident", mode: "read_only" }))
      .toThrow(McpToolError);
  });

  it("denies a table outside the allowlist and an explicitly denied table", () => {
    expect(() => assertActorPolicy(policy, { instance: "inst1.service-now.com", table: "change_request", mode: "read_only" })).toThrow(McpToolError);
    expect(() => assertActorPolicy(policy, { instance: "inst1.service-now.com", table: "sys_user", mode: "read_only" })).toThrow(McpToolError);
  });

  it("denies a mode above the actor's maxMode", () => {
    expect(() => assertActorPolicy(policy, { instance: "inst1.service-now.com", table: "incident", mode: "admin_script" })).toThrow(McpToolError);
  });

  it("AND-s in the mandatory row filter and strips masked fields", () => {
    expect(applyRowFilter(policy, "incident", "priority=1")).toBe("active=true^priority=1");
    expect(applyRowFilter(policy, "incident", "")).toBe("active=true");
    const masked = maskRow(policy, "incident", { number: "INC1", caller_id: "x", u_ssn: "123", short_description: "d" });
    expect(masked).toEqual({ number: "INC1", short_description: "d" });
  });

  it("rejects an explicit request for a masked field", () => {
    expect(() => assertRequestedFieldsAllowed(policy, "incident", ["number", "u_ssn"])).toThrow(McpToolError);
    expect(() => assertRequestedFieldsAllowed(policy, "incident", ["number"])).not.toThrow();
  });

  it("a permissive policy (single trusted operator) allows broadly", () => {
    const p = permissivePolicy(["inst1.service-now.com"]);
    expect(() => assertActorPolicy(p, { instance: "inst1.service-now.com", table: "anything", mode: "admin_script" })).not.toThrow();
  });

  // ─── Phase P6a — fail-closed on a non-Mode value (closes the latent fail-open) ──
  // Pre-P6a: MODE_RISK[unknown] === undefined, so `undefined > MODE_RISK[maxMode]` was false
  // and an unknown mode passed the policy gate. Now an unknown mode scores +Infinity and is
  // DENIED, even under a permissive (admin_script) policy.
  it("denies an unknown (non-Mode) requested mode, even under a permissive policy", () => {
    const p = permissivePolicy(["inst1.service-now.com"]);
    expect(() =>
      assertActorPolicy(p, { instance: "inst1.service-now.com", table: "incident", mode: "super_admin" as unknown as Mode }),
    ).toThrow(McpToolError);
  });
});

// ─── §6b — loadActorPolicy (config-driven restrictive policy; NON-BREAKING default) ──
describe("§6b loadActorPolicy", () => {
  const INSTANCE = "inst1.service-now.com";

  it("falls back to the PERMISSIVE single-operator policy when NO policy config is set", () => {
    const p = loadActorPolicy({}, INSTANCE);
    // Same shape as permissivePolicy: no allowlist, no masks, admin_script, unbounded ceilings.
    expect(p).toEqual(permissivePolicy([INSTANCE]));
    expect(() => assertActorPolicy(p, { instance: INSTANCE, table: "anything", mode: "admin_script" })).not.toThrow();
  });

  it("builds a RESTRICTIVE policy when config IS provided and denies a non-allowlisted table", () => {
    const env: PolicyEnv = { ACTOR_POLICY_TABLE_ALLOWLIST: "incident, problem" };
    const p = loadActorPolicy(env, INSTANCE);
    expect(() => assertActorPolicy(p, { instance: INSTANCE, table: "incident", mode: "read_only" })).not.toThrow();
    expect(() => assertActorPolicy(p, { instance: INSTANCE, table: "sys_user", mode: "read_only" })).toThrow(McpToolError);
  });

  it("anchors allowlist entries to a WHOLE-name match (no substring leak)", () => {
    const p = loadActorPolicy({ ACTOR_POLICY_TABLE_ALLOWLIST: "incident" }, INSTANCE);
    expect(() => assertActorPolicy(p, { instance: INSTANCE, table: "incident_extra", mode: "read_only" })).toThrow(McpToolError);
    expect(() => assertActorPolicy(p, { instance: INSTANCE, table: "incident", mode: "read_only" })).not.toThrow();
  });

  it("defaults a restrictive policy's maxMode to read_only (denies admin_script unless raised)", () => {
    const p = loadActorPolicy({ ACTOR_POLICY_TABLE_ALLOWLIST: "incident" }, INSTANCE);
    expect(() => assertActorPolicy(p, { instance: INSTANCE, table: "incident", mode: "admin_script" })).toThrow(McpToolError);
    const raised = loadActorPolicy({ ACTOR_POLICY_TABLE_ALLOWLIST: "incident", ACTOR_POLICY_MAX_MODE: "admin_script" }, INSTANCE);
    expect(() => assertActorPolicy(raised, { instance: INSTANCE, table: "incident", mode: "admin_script" })).not.toThrow();
  });

  // P6b-2 FIX 1 — fail-CLOSED on a SET-but-INVALID maxMode (closes a fail-OPEN in this hardening
  // pass). assertActorPolicy compares modeRisk(ctx.mode) > modeRisk(policy.maxMode); modeRisk(non-
  // Mode)=+Infinity. Because maxMode is the CEILING (right operand), an unvalidated invalid string
  // ("readonly") made `finite > +Infinity` === false === ALLOW — silently disabling the ceiling and
  // admitting admin_script. loadActorPolicy now coerces a set-but-invalid maxMode to read_only.
  it("coerces a SET-but-INVALID maxMode to read_only (fail-closed; denies admin_script)", () => {
    const p = loadActorPolicy(
      { ACTOR_POLICY_TABLE_ALLOWLIST: "incident", ACTOR_POLICY_MAX_MODE: "readonly" as unknown as Mode },
      INSTANCE,
    );
    expect(p.maxMode).toBe("read_only");
    expect(() => assertActorPolicy(p, { instance: INSTANCE, table: "incident", mode: "admin_script" })).toThrow(McpToolError);
  });

  it("parses field masks (table:field,field;table:field) — masks reads AND rejects write requests", () => {
    const p = loadActorPolicy({ ACTOR_POLICY_FIELD_MASKS: "incident:caller_id,u_ssn;sys_user:vip" }, INSTANCE);
    expect(maskRow(p, "incident", { number: "INC1", caller_id: "x", u_ssn: "1" })).toEqual({ number: "INC1" });
    expect(() => assertRequestedFieldsAllowed(p, "incident", ["u_ssn"])).toThrow(McpToolError);
    expect(() => assertRequestedFieldsAllowed(p, "sys_user", ["vip"])).toThrow(McpToolError);
  });

  it("parses row filters (table:encoded^query) and AND-s them in", () => {
    const p = loadActorPolicy({ ACTOR_POLICY_ROW_FILTERS: "incident:active=true" }, INSTANCE);
    expect(applyRowFilter(p, "incident", "priority=1")).toBe("active=true^priority=1");
  });

  it("REJECTS a self-defeating mandatory rowFilter (^OR) AT LOAD (fail-closed)", () => {
    expect(() => loadActorPolicy({ ACTOR_POLICY_ROW_FILTERS: "incident:active=true^ORactive=false" }, INSTANCE)).toThrow();
    // ^ORDERBY is benign and must NOT be rejected at load (token boundary).
    expect(() => loadActorPolicy({ ACTOR_POLICY_ROW_FILTERS: "incident:active=true^ORDERBYnumber" }, INSTANCE)).not.toThrow();
  });

  it("the restrictive per-run ceilings carry onto the policy (parse only)", () => {
    const p = loadActorPolicy({ ACTOR_POLICY_TABLE_ALLOWLIST: "incident", ACTOR_POLICY_MAX_ROWS_PER_RUN: "50", ACTOR_POLICY_MAX_BYTES_PER_RUN: "1000" }, INSTANCE);
    expect(p.maxRowsPerRun).toBe(50);
    expect(p.maxBytesPerRun).toBe(1000);
  });

  // P6b-2 FIX 5 — prove the policy→RunBudget link is ENFORCED end-to-end, not just parsed. Mirror
  // handlers.ts:402 (`new RunBudget(BUDGETS.perRun, { maxRows: policy.maxRowsPerRun, maxBytes:
  // policy.maxBytesPerRun })`) but SOURCE the ceilings from a loaded policy, then assert countRows
  // /countBytes trip budget_exceeded on the right dimension (mirrors run-budget.test.ts).
  it("the policy's row/byte ceilings ENFORCE via RunBudget (budget_exceeded on the right dimension)", () => {
    const p = loadActorPolicy(
      { ACTOR_POLICY_TABLE_ALLOWLIST: "incident", ACTOR_POLICY_MAX_ROWS_PER_RUN: "50", ACTOR_POLICY_MAX_BYTES_PER_RUN: "1000" },
      INSTANCE,
    );
    const budget = new RunBudget(BUDGETS.perRun, { maxRows: p.maxRowsPerRun, maxBytes: p.maxBytesPerRun });
    budget.countRows(50); // exactly at the cap — ok
    try {
      budget.countRows(1); // 51 > 50 — trips
      throw new Error("expected budget_exceeded (rows)");
    } catch (e) {
      expect(e).toBeInstanceOf(McpToolError);
      expect((e as McpToolError).code).toBe("budget_exceeded");
      expect((e as McpToolError).detail?.dimension).toBe("rowsReturned");
    }

    const byteBudget = new RunBudget(BUDGETS.perRun, { maxRows: p.maxRowsPerRun, maxBytes: p.maxBytesPerRun });
    byteBudget.countBytes(1000); // exactly at the cap — ok
    try {
      byteBudget.countBytes(1); // 1001 > 1000 — trips
      throw new Error("expected budget_exceeded (bytes)");
    } catch (e) {
      expect(e).toBeInstanceOf(McpToolError);
      expect((e as McpToolError).code).toBe("budget_exceeded");
      expect((e as McpToolError).detail?.dimension).toBe("bytesReturned");
    }
  });

  it("rejects a non-positive-integer ceiling at load", () => {
    expect(() => loadActorPolicy({ ACTOR_POLICY_TABLE_ALLOWLIST: "incident", ACTOR_POLICY_MAX_ROWS_PER_RUN: "0" }, INSTANCE)).toThrow();
    expect(() => loadActorPolicy({ ACTOR_POLICY_TABLE_ALLOWLIST: "incident", ACTOR_POLICY_MAX_BYTES_PER_RUN: "-5" }, INSTANCE)).toThrow();
  });
});

// ─── §3.5 — capability gating ────────────────────────────────────────────────
describe("§3.5 mode→capability gating", () => {
  it("read_only permits readTables but not writeTables/runServerScript", () => {
    expect(hasCapability("read_only", "readTables")).toBe(true);
    expect(() => requireCapability("read_only", "readTables")).not.toThrow();
    expect(() => requireCapability("read_only", "writeTables")).toThrow(McpToolError);
    expect(() => requireCapability("read_only", "runServerScript")).toThrow(McpToolError);
  });

  it("only admin_script permits runServerScript and deleteRecords", () => {
    expect(() => requireCapability("write", "runServerScript")).toThrow(McpToolError);
    expect(() => requireCapability("write", "deleteRecords")).toThrow(McpToolError);
    expect(() => requireCapability("admin_script", "runServerScript")).not.toThrow();
    expect(() => requireCapability("admin_script", "deleteRecords")).not.toThrow();
  });
});
