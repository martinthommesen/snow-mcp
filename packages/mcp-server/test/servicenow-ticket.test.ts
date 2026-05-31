import { describe, expect, it } from "vitest";
import { mintTicket, verifyTicket } from "../src/auth/servicenow-ticket.js";

// ─── §6b — host-HMAC reauth ticket (identity bridge into /servicenow/authorize) ──
// The ticket is the SOLE identity authority at /servicenow/authorize (which has no ctx.props).
// It must round-trip under the host secret, reject tampering / a wrong secret, and expire.

const SECRET = "host-oauth-provider-secret";

describe("§6b reauth ticket mint/verify", () => {
  it("round-trips a valid ticket and returns its claims", async () => {
    const ticket = { userId: "alice", instanceHost: "inst1.service-now.com", nonce: "n1", exp: 10_000 };
    const token = await mintTicket(ticket, SECRET);
    const verified = await verifyTicket(token, SECRET, 5_000); // before exp
    expect(verified).toEqual(ticket);
  });

  it("rejects an expired ticket (null, fail closed)", async () => {
    const token = await mintTicket({ userId: "alice", instanceHost: "inst1", nonce: "n", exp: 1_000 }, SECRET);
    expect(await verifyTicket(token, SECRET, 5_000)).toBeNull(); // now > exp
  });

  it("rejects a ticket signed with a DIFFERENT secret (forgery)", async () => {
    const token = await mintTicket({ userId: "alice", instanceHost: "inst1", nonce: "n", exp: 10_000 }, SECRET);
    expect(await verifyTicket(token, "another-secret", 5_000)).toBeNull();
  });

  it("rejects a tampered payload (signature no longer matches the claims)", async () => {
    const token = await mintTicket({ userId: "alice", instanceHost: "inst1", nonce: "n", exp: 10_000 }, SECRET);
    // Flip the userId in the base64url payload while keeping the original signature.
    const [, sig] = token.split(".");
    const forged = btoa(JSON.stringify({ userId: "mallory", instanceHost: "inst1", nonce: "n", exp: 10_000 }))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(await verifyTicket(`${forged}.${sig}`, SECRET, 5_000)).toBeNull();
  });

  it("rejects a malformed token (no dot separator)", async () => {
    expect(await verifyTicket("not-a-ticket", SECRET, 5_000)).toBeNull();
  });
});
