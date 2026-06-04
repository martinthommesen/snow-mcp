import { describe, expect, it } from "vitest";
import { assertAdminScriptApproved, type ApprovalContext } from "../src/authz/approval.js";
import { redactString, redactValue, REDACTED } from "../src/observability/redact.js";
import { McpToolError } from "../src/sn/errors.js";

// ─── §7.9 — admin_script approval gate ────────────────────────────────────────
describe("§7.9 admin_script approval", () => {
  const base: ApprovalContext = {
    mode: "admin_script",
    actorUserId: "u1",
    reason: "rotate cache",
    adminScriptAllowlist: ["u1"],
    validApprovalTokens: new Set(["good-token"]),
    approvalToken: "good-token",
  };

  it("passes with allowlist + reason + valid token", () => {
    expect(() => assertAdminScriptApproved(base)).not.toThrow();
  });

  it("passes with allowlist + reason + access group instead of token", () => {
    expect(() =>
      assertAdminScriptApproved({ ...base, approvalToken: undefined, validApprovalTokens: undefined, actorAccessGroups: ["mcp-admins"], requiredAccessGroup: "mcp-admins" }),
    ).not.toThrow();
  });

  it("denies when the actor is not on the admin_script allowlist", () => {
    expect(() => assertAdminScriptApproved({ ...base, adminScriptAllowlist: ["someone-else"] })).toThrow(McpToolError);
  });

  it("denies when no second approval is present (token invalid, no group)", () => {
    expect(() => assertAdminScriptApproved({ ...base, approvalToken: "wrong" })).toThrow(/second approval/i);
  });

  it("denies when reason is missing", () => {
    expect(() => assertAdminScriptApproved({ ...base, reason: "  " })).toThrow(/reason/i);
  });

  it("no-ops for non-admin_script modes", () => {
    expect(() => assertAdminScriptApproved({ ...base, mode: "write", adminScriptAllowlist: [] })).not.toThrow();
    expect(() => assertAdminScriptApproved({ ...base, mode: "read_only", adminScriptAllowlist: [] })).not.toThrow();
  });
});

// ─── §7.1 — redaction ─────────────────────────────────────────────────────────
describe("§7.1 redaction", () => {
  it("scrubs auth headers and secret assignments from strings", () => {
    expect(redactString("authorization: Bearer abcdef1234567890")).toContain(REDACTED);
    expect(redactString("Basic dXNlcjpwYXNzd29yZA==")).toContain(REDACTED);
    expect(redactString("client_secret=supersecretvalue here")).toContain(REDACTED);
    expect(redactString("OIDC_CLIENT_SECRET=oidc-secret-value")).toContain(REDACTED);
    expect(redactString("accessToken=access-secret-value")).toContain(REDACTED);
    expect(redactString("approvalToken=approval-secret-value")).toContain(REDACTED);
    expect(redactString("operator_secret=operator-secret-value")).toContain(REDACTED);
    // hmac/kek secret families redact in strings too (parity with DENY_FIELDS object redaction).
    expect(redactString("X_MCP_EXECUTOR_HMAC_KEY=AABBCCDDEEFF0011")).toContain(REDACTED);
    expect(redactString("SNAPSHOT_KEK_CURRENT=deadbeefcafef00d")).toContain(REDACTED);
    expect(redactString("token_kek=passphrase-value")).toContain(REDACTED);
    // the field name + separator are preserved; only the value is scrubbed.
    expect(redactString("snapshot_kek=secret-value")).toBe(`snapshot_kek=${REDACTED}`);
    expect(redactString("nothing sensitive here")).toBe("nothing sensitive here");
  });

  it("deep-redacts denylisted fields in objects", () => {
    const obj = { user: "ada", password: "p@ss", nested: { refresh_token: "rt", accessToken: "at", ok: "keep" }, authorization: "Bearer x" };
    const r = redactValue(obj) as Record<string, unknown>;
    expect(r.user).toBe("ada");
    expect(r.password).toBe(REDACTED);
    expect((r.nested as Record<string, unknown>).refresh_token).toBe(REDACTED);
    expect((r.nested as Record<string, unknown>).accessToken).toBe(REDACTED);
    expect((r.nested as Record<string, unknown>).ok).toBe("keep");
    expect(r.authorization).toBe(REDACTED);
  });
});
