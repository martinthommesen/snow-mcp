import { describe, expect, it } from "vitest";
import { ERROR_CODES } from "@servicenow-codemode/shared";
import { McpToolError, parseSandboxError, toToolResult } from "../src/sn/errors.js";
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
    expect(new Set(ERROR_CODES).size).toBe(ERROR_CODES.length);
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
});
