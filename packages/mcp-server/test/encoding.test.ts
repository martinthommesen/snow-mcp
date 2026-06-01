import { describe, expect, it } from "vitest";
import {
  base64ToBytes,
  base64UrlToString,
  bytesToBase64,
  bytesToBase64Url,
  bytesToHex,
  constantTimeEqualAscii,
  decodeFixedBase64Secret,
} from "../src/auth/encoding.js";

describe("auth encoding helpers", () => {
  it("round-trips binary data through base64", () => {
    const bytes = new Uint8Array([0, 1, 2, 253, 254, 255]);
    expect([...base64ToBytes(bytesToBase64(bytes))]).toEqual([...bytes]);
  });

  it("encodes base64url without padding and decodes it as a string", () => {
    const encoded = bytesToBase64Url(new TextEncoder().encode("ticket.payload"));
    expect(encoded).not.toMatch(/[+/=]/);
    expect(base64UrlToString(encoded)).toBe("ticket.payload");
  });

  it("renders lowercase hex", () => {
    expect(bytesToHex(new Uint8Array([0, 15, 16, 255]))).toBe("000f10ff");
  });

  it("compares ASCII strings without leaking equality through partial matches", () => {
    expect(constantTimeEqualAscii("same", "same")).toBe(true);
    expect(constantTimeEqualAscii("same", "sane")).toBe(false);
    expect(constantTimeEqualAscii("same", "same-but-longer")).toBe(false);
  });

  it("decodes fixed-length base64 secrets and rejects malformed or weak values", () => {
    const secret = bytesToBase64(new Uint8Array(32).fill(7));
    expect([...decodeFixedBase64Secret("X_MCP_EXECUTOR_HMAC_KEY", secret, 32)]).toEqual([...new Uint8Array(32).fill(7)]);

    expect(() => decodeFixedBase64Secret("X_MCP_EXECUTOR_HMAC_KEY", "not base64!", 32)).toThrow(/valid base64/);
    expect(() => decodeFixedBase64Secret("X_MCP_EXECUTOR_HMAC_KEY", bytesToBase64(new Uint8Array(16)), 32)).toThrow(/32 bytes/);
  });
});
