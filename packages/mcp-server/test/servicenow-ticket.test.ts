import { describe, expect, it } from "vitest";
import { mintTicket, verifyTicket } from "../src/auth/servicenow-ticket.js";

// ─── §6b — host-HMAC reauth ticket (identity bridge into /servicenow/authorize) ──
// The ticket is the SOLE identity authority at /servicenow/authorize (which has no ctx.props).
// It must round-trip under the host secret, reject tampering / a wrong secret, and expire.

const SECRET = "host-oauth-provider-secret";

// Most tests mint the same baseline ticket and vary exactly one field.
type Ticket = Parameters<typeof mintTicket>[0];
const mkTicket = (o: Partial<Ticket> = {}): Ticket => ({
  userId: "alice", actorEmail: "alice@example.com", instanceHost: "inst1", nonce: "n", exp: 10_000, ...o,
});

describe("§6b reauth ticket mint/verify", () => {
  it("round-trips a valid ticket and returns its claims", async () => {
    const ticket = { userId: "alice", actorEmail: "alice@example.com", instanceHost: "inst1.service-now.com", nonce: "n1", exp: 10_000 };
    const token = await mintTicket(ticket, SECRET);
    const verified = await verifyTicket(token, SECRET, 5_000); // before exp
    expect(verified).toEqual(ticket);
  });

  it("round-trips UTF-8 user ids without changing the TokenStore partition key", async () => {
    const ticket = { userId: "åse-操作", actorEmail: "ase@example.com", instanceHost: "inst1.service-now.com", nonce: "n1", exp: 10_000 };
    const token = await mintTicket(ticket, SECRET);
    const verified = await verifyTicket(token, SECRET, 5_000);
    expect(verified).toEqual(ticket);
  });

  it("normalizes actor email and carries an expected ServiceNow sys_id", async () => {
    const token = await mintTicket(
      { userId: "alice", actorEmail: " Alice@Example.COM ", instanceHost: "inst1", nonce: "n", expectedSnSysId: "SYS1", exp: 10_000 },
      SECRET,
    );
    expect(await verifyTicket(token, SECRET, 5_000)).toEqual({
      userId: "alice",
      actorEmail: "alice@example.com",
      instanceHost: "inst1",
      nonce: "n",
      expectedSnSysId: "SYS1",
      exp: 10_000,
    });
  });

  it("rejects an expired ticket (null, fail closed)", async () => {
    const token = await mintTicket(mkTicket({ exp: 1_000 }), SECRET);
    expect(await verifyTicket(token, SECRET, 5_000)).toBeNull(); // now > exp
  });

  it("rejects a ticket without a nonce", async () => {
    const token = await mintTicket(mkTicket({ nonce: "" }), SECRET);
    expect(await verifyTicket(token, SECRET, 5_000)).toBeNull();
  });

  it("allows a ticket without an actor email for IdPs that do not provide email", async () => {
    const token = await mintTicket(mkTicket({ actorEmail: "" }), SECRET);
    expect(await verifyTicket(token, SECRET, 5_000)).toEqual({
      userId: "alice",
      instanceHost: "inst1",
      nonce: "n",
      exp: 10_000,
    });
  });

  it("rejects a ticket signed with a DIFFERENT secret (forgery)", async () => {
    const token = await mintTicket(mkTicket(), SECRET);
    expect(await verifyTicket(token, "another-secret", 5_000)).toBeNull();
  });

  it("rejects a tampered payload (signature no longer matches the claims)", async () => {
    const token = await mintTicket(mkTicket(), SECRET);
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
