import { describe, expect, it } from "vitest";
import { signActor, verifyActorSignatureLocal, canonicalize, type ActorClaims } from "../src/auth/actor.js";
import {
  assertActorPolicy,
  applyRowFilter,
  maskRow,
  assertRequestedFieldsAllowed,
  permissivePolicy,
  type ActorPolicy,
} from "../src/authz/actor-policy.js";
import { requireCapability, hasCapability } from "../src/config.js";
import { McpToolError } from "../src/sn/errors.js";

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
describe("§2.0 actor signing", () => {
  it("canonicalization is deterministic and key-ordered", async () => {
    const a = await signActor({ claims, script: SCRIPT, issuedAt: T0, nonce: "n1", hmacKey: HKEY });
    expect(canonicalize(a.actor).startsWith('{"mcp_actor_user_id":"u1"')).toBe(true);
    expect(typeof a.actor_sig).toBe("string");
  });

  it("a valid signature verifies (local mirror of the in-scope check)", async () => {
    const a = await signActor({ claims, script: SCRIPT, issuedAt: T0, nonce: "n1", hmacKey: HKEY });
    expect(await verifyActorSignatureLocal(a, SCRIPT, HKEY, { now: T0 + 1000 })).toBe(true);
  });

  it("canonical form is ASCII-only and deterministic even with non-ASCII actor fields", async () => {
    // Cross-engine linchpin: V8 and ServiceNow's engine must produce identical bytes.
    const unicodeClaims: ActorClaims = { ...claims, mcp_actor_email: " André@例子.com" };
    const a = await signActor({ claims: unicodeClaims, script: SCRIPT, issuedAt: T0, nonce: "n1", hmacKey: HKEY });
    const canon = canonicalize(a.actor);
    // Pure ASCII (no code point >= 0x80) — non-ASCII escaped as \uXXXX.
    expect([...canon].every((ch) => ch.charCodeAt(0) < 0x80)).toBe(true);
    expect(canon).toContain("\\u00e9"); // é
    // Deterministic + round-trips locally.
    expect(canonicalize(a.actor)).toBe(canon);
    expect(await verifyActorSignatureLocal(a, SCRIPT, HKEY, { now: T0 })).toBe(true);
  });

  it("B1-shape: forged email, wrong key, stale time, or altered script all fail", async () => {
    const a = await signActor({ claims, script: SCRIPT, issuedAt: T0, nonce: "n1", hmacKey: HKEY });

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
