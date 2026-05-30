import { describe, expect, it } from "vitest";
import { seal, open, tokenAad, type KekRing } from "../src/auth/crypto.js";

// ─── §2.7 — AES-256-GCM token envelope (S7 fragments) ─────────────────────────
// WebCrypto, fully verified locally.

function key(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}
const ringV1: KekRing = { current: { version: "2026-05", keyBytes: key(1) } };
const aad = tokenAad("userA", "inst1.service-now.com", "refresh");

describe("§2.7 token envelope", () => {
  it("round-trips under the current KEK", async () => {
    const env = await seal("super-secret-refresh-token", aad, ringV1);
    expect(env.alg).toBe("AES-256-GCM");
    expect(env.aad).toBe(aad);
    expect(await open(env, aad, ringV1)).toBe("super-secret-refresh-token");
  });

  it("fails closed on AAD mismatch (wrong user/instance/type)", async () => {
    const env = await seal("tok", aad, ringV1);
    const wrong = tokenAad("userB", "inst1.service-now.com", "refresh");
    await expect(open(env, wrong, ringV1)).rejects.toThrow(/AAD mismatch/);
  });

  it("fails closed on ciphertext tampering", async () => {
    const env = await seal("tok", aad, ringV1);
    const ctBytes = atob(env.ciphertext).split("");
    ctBytes[0] = ctBytes[0] === "A" ? "B" : "A";
    const tampered = { ...env, ciphertext: btoa(ctBytes.join("")) };
    await expect(open(tampered, aad, ringV1)).rejects.toThrow();
  });

  it("decrypts under the previous KEK during a rotation window", async () => {
    // Sealed under v1; then v2 becomes current and v1 becomes previous.
    const env = await seal("tok", aad, ringV1);
    const rotated: KekRing = {
      current: { version: "2026-06", keyBytes: key(2) },
      previous: { version: "2026-05", keyBytes: key(1) },
    };
    expect(await open(env, aad, rotated)).toBe("tok");
  });

  it("cannot decrypt once the previous KEK ages out of the ring", async () => {
    const env = await seal("tok", aad, ringV1);
    const newRing: KekRing = { current: { version: "2026-07", keyBytes: key(9) } };
    await expect(open(env, aad, newRing)).rejects.toThrow();
  });
});
