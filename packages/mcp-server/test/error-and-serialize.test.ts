import { describe, expect, it } from "vitest";
import { ERROR_CODES } from "@servicenow-codemode/shared";
import { McpToolError, mapServiceNowError, parseSandboxError, toToolResult } from "../src/sn/errors.js";
import { REDACTED } from "../src/observability/redact.js";
import { serializeResult, truncateUtf8, utf8Len } from "../src/sandbox/serialize.js";

// ─── Phase P2 — error-code integrity + byte-safe output (pure helpers) ──────────

describe("parseSandboxError — membership-checked code (§P2)", () => {
  it("honors a known union code", () => {
    expect(parseSandboxError("[[reauth_required]] please re-auth")).toEqual({
      code: "reauth_required",
      message: "please re-auth",
    });
  });

  it("drops a non-union forged code but keeps the advisory message", () => {
    // A snippet-forged `[[not_a_code]]` must not pass through as a typed code.
    expect(parseSandboxError("[[not_a_code]] sneaky")).toEqual({ message: "sneaky" });
  });

  it("returns no code for a plain message", () => {
    expect(parseSandboxError("just an error")).toEqual({ message: "just an error" });
  });

  it("ERROR_CODES contains run_error and is otherwise complete", () => {
    expect(ERROR_CODES).toContain("run_error");
    expect(ERROR_CODES).toContain("budget_exceeded");
    expect(ERROR_CODES).toContain("table_not_found");
    expect(ERROR_CODES).toContain("precondition_required");
    expect(ERROR_CODES).toContain("idempotency_conflict");
    expect(new Set(ERROR_CODES).size).toBe(ERROR_CODES.length);
  });
});

// ─── Phase P6a — the client-facing message is GENERIC; raw SN detail never leaks (finding 22) ──
describe("mapServiceNowError — generic client message, typed code (§P6a, finding 22)", () => {
  it("returns a GENERIC per-status message and keeps the typed code; raw SN detail does not leak", () => {
    // A ServiceNow 403 body echoing ACL/identity/schema detail (sys_id, table, role, email).
    const body = {
      error: {
        message:
          "ACL denied for 6816f79cc0a8016401c5a33be04be441 on table 'sys_user' for role 'itil_admin' (admin@example.com)",
      },
    };
    const err = mapServiceNowError(403, body);
    expect(err).toBeInstanceOf(McpToolError);
    expect(err!.code).toBe("actor_policy_denied"); // typed code intact
    expect(err!.message).toBe("ServiceNow denied access (403)."); // generic, per-status
    // None of the raw SN detail reaches the client-facing message.
    expect(err!.message).not.toContain("6816f79cc0a8016401c5a33be04be441");
    expect(err!.message).not.toContain("sys_user");
    expect(err!.message).not.toContain("itil_admin");
    expect(err!.message).not.toContain("admin@example.com");
  });

  it("maps the status families to generic messages (5xx -> instance_hibernating)", () => {
    expect(mapServiceNowError(401)!.code).toBe("reauth_required");
    expect(mapServiceNowError(404)!.code).toBe("table_not_found");
    expect(mapServiceNowError(429)!.code).toBe("budget_exceeded");
    const five = mapServiceNowError(503, { error: { message: "node 7 down" } });
    expect(five!.code).toBe("instance_hibernating");
    expect(five!.message).toBe("ServiceNow is unavailable (5xx).");
    expect(five!.message).not.toContain("node 7 down");
  });

  it("maps definitive ServiceNow 4xxs to clean typed failures instead of internal_error", () => {
    expect(mapServiceNowError(400, { error: { message: "encoded query error on sys_user" } })!.code).toBe("path_denied");
    expect(mapServiceNowError(413, { error: "code_size" })!.code).toBe("code_size");
    expect(mapServiceNowError(413, { error: { message: "payload too large" } })!.code).toBe("path_denied");
  });

  it("maps executor-disabled 503s to a clean capability denial", () => {
    const disabled = mapServiceNowError(503, { error: "executor_disabled" });
    expect(disabled).toBeInstanceOf(McpToolError);
    expect(disabled!.code).toBe("capability_denied");
    expect(disabled!.message).toMatch(/executor is disabled/i);
  });

  it("the generic message survives through toToolResult with the typed code (discovery path)", () => {
    const res = toToolResult(mapServiceNowError(500, { error: { message: "stack trace + sys_id leak" } }));
    expect(res.structuredContent.code).toBe("instance_hibernating");
    expect(res.structuredContent.message).toBe("ServiceNow is unavailable (5xx).");
    expect(JSON.stringify(res)).not.toContain("sys_id leak");
  });

  it("toToolResult scrubs secrets in a non-SN error string (secondary chokepoint)", () => {
    // A non-SN error (e.g. servicenow-oauth.ts's `servicenow_oauth_failed: …`) is redacted by
    // toToolResult even though it never passes through mapServiceNowError.
    const res = toToolResult(new McpToolError("internal_error", "client_secret=supersecretvalue leaked"));
    expect(res.structuredContent.message).toContain(REDACTED);
    expect(JSON.stringify(res)).not.toContain("supersecretvalue");
  });
});

describe("toToolResult — detail propagation (§P2)", () => {
  it("propagates McpToolError.detail into structuredContent", () => {
    const err = new McpToolError("reauth_required", "re-auth", { authorizeUrl: "https://real/login" });
    const res = toToolResult(err);
    expect(res.structuredContent.code).toBe("reauth_required");
    expect(res.structuredContent.detail).toEqual({ authorizeUrl: "https://real/login" });
  });

  it("propagates budget_exceeded dimension (daily-reserve path)", () => {
    const err = new McpToolError("budget_exceeded", "cap", { dimension: "uniqueWorkers" });
    expect(toToolResult(err).structuredContent.detail).toEqual({ dimension: "uniqueWorkers" });
  });

  it("omits detail when none is present", () => {
    const res = toToolResult(new McpToolError("internal_error", "x"));
    expect(res.structuredContent.detail).toBeUndefined();
  });
});

describe("truncateUtf8 / serializeResult — byte-safe truncation (§P2)", () => {
  it("never splits a multi-byte sequence and stays within maxBytes", () => {
    // "€" is 3 UTF-8 bytes. A code-unit slice at a non-aligned byte would split it.
    const s = "€".repeat(50); // 150 bytes
    const out = truncateUtf8(s, 100);
    expect(utf8Len(out)).toBeLessThanOrEqual(100);
    // valid UTF-8 (no U+FFFD replacement char from a split sequence)
    expect(out).not.toContain("�");
    expect(out).toBe("€".repeat(33)); // 99 bytes, last whole sequence
  });

  it("returns the input unchanged when within the cap", () => {
    expect(truncateUtf8("abc", 100)).toBe("abc");
  });

  it("serializeResult truncates multi-byte JSON within the byte cap", () => {
    const value = { note: "✓".repeat(1000) }; // each ✓ is 3 bytes
    const ser = serializeResult(value, 200);
    expect(ser.truncated).toBe(true);
    expect(utf8Len(ser.text)).toBeLessThanOrEqual(200);
    expect(ser.text).not.toContain("�");
    expect(ser.totalBytes).toBe(utf8Len(JSON.stringify(value)));
  });

  it("serializeResult reports the first non-JSON path and includes a sanitized value", () => {
    const value: { count: bigint; nested?: unknown } = { count: 1n };
    value.nested = { self: value };
    const ser = serializeResult(value, 10_000);
    expect(ser.truncated).toBe(false);
    const parsed = JSON.parse(ser.text) as { error: string; path: string; value: { count: string; nested: { self: string } } };
    expect(parsed.error).toBe("result_not_serializable");
    expect(parsed.path).toBe("$.count");
    expect(parsed.value.count).toBe("1");
    expect(parsed.value.nested.self).toBe("[Circular]");
  });

  it("serializeResult truncates the sanitized fallback within the byte cap", () => {
    const value = { count: 1n, payload: "x".repeat(1000) };
    const ser = serializeResult(value, 80);
    expect(ser.truncated).toBe(true);
    expect(utf8Len(ser.text)).toBeLessThanOrEqual(80);
    expect(ser.totalBytes).toBeGreaterThan(80);
  });
});
