import { describe, expect, it } from "vitest";
import { seal, open, tokenAad, buildKekRing, deriveKeyBytes, type KekRing } from "../src/auth/crypto.js";

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

// ─── P3 — content-addressed versioned KEK ring (closes finding 28 wiring) ─────
describe("§P3 buildKekRing", () => {
  it("uses content-addressed labels (not the constant 'current'); distinct keys differ", async () => {
    const ringA = await buildKekRing("passphrase-A");
    const ringB = await buildKekRing("passphrase-B");
    expect(ringA.current.version).toMatch(/^kek-[0-9a-f]{8}$/);
    expect(ringA.current.version).not.toBe("current");
    expect(ringB.current.version).not.toBe(ringA.current.version);
    // Same passphrase → stable label across deploys.
    expect((await buildKekRing("passphrase-A")).current.version).toBe(ringA.current.version);
  });

  it("round-trips across a rotation: seal under current, open after current→prev + new current", async () => {
    const oldRing = await buildKekRing("old-pass");
    const env = await seal("tok", aad, oldRing);
    const rotated = await buildKekRing("new-pass", "old-pass"); // current=new, previous=old
    expect(rotated.previous?.version).toBe(oldRing.current.version);
    expect(await open(env, aad, rotated)).toBe("tok");
  });

  it("migration: a legacy envelope stamped kekVersion:'current' still opens under the new ring", async () => {
    // Old code sealed with version label "current" and key = deriveKeyBytes(passphrase).
    const legacyRing: KekRing = { current: { version: "current", keyBytes: await deriveKeyBytes("legacy-pass") } };
    const legacyEnv = await seal("legacy-token", aad, legacyRing);
    expect(legacyEnv.kekVersion).toBe("current");
    // New ring built from the SAME passphrase → label is content-addressed (matches neither),
    // so open()'s try-all fallback decrypts it.
    const newRing = await buildKekRing("legacy-pass");
    expect(newRing.current.version).not.toBe("current");
    expect(await open(legacyEnv, aad, newRing)).toBe("legacy-token");
  });

  it("fails closed when no current secret is given (missing KEK)", async () => {
    await expect(buildKekRing("")).rejects.toThrow(/fail closed/i);
  });
});
