import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker, { type Env } from "../src/index.js";
import { isOriginAllowed } from "../src/observability/origin.js";

describe("Phase 0.7 / 1B — health endpoints", () => {
  it("returns ok", async () => {
    const res = await SELF.fetch("http://localhost/health");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, service: "servicenow-codemode-mcp" });
  });

  it("serves liveness before the OAuth provider", async () => {
    const res = await SELF.fetch("http://localhost/health/live");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, service: "servicenow-codemode-mcp" });
  });

  it("serves readiness from the non-throwing posture collector", async () => {
    const res = await SELF.fetch("http://localhost/health/ready");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      ok: true,
      service: "servicenow-codemode-mcp",
      profile: "pilot",
      violations: [],
    });
  });

  it("redacts public readiness posture details when production config is invalid", async () => {
    const res = await worker.fetch(
      new Request("http://localhost/health/ready"),
      { DEPLOYMENT_PROFILE: "production" } as Env,
      {} as ExecutionContext,
    );
    expect(res.status).toBe(503);
    const body = await res.json() as { violationCount?: number; violations?: unknown };
    expect(body.violationCount).toBeGreaterThan(0);
    expect(body).not.toHaveProperty("violations");
  });

  it("serves static version metadata without requiring auth", async () => {
    const res = await SELF.fetch("http://localhost/health/version");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      ok: true,
      service: "servicenow-codemode-mcp",
      appVersion: "0.1.0",
      compatibilityDate: "2026-05-13",
      commitSha: null,
      buildTimestamp: null,
    });
  });
});

describe("§2.4/§7.8 — /mcp requires a valid OAuth token (no longer open)", () => {
  it("rejects an unauthenticated /mcp request (401), not reaching the tools", async () => {
    const res = await SELF.fetch("http://localhost/mcp", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    expect(res.status).toBe(401);
  });

  it("exposes OAuth 2.1 server metadata (RFC-8414)", async () => {
    const res = await SELF.fetch("http://localhost/.well-known/oauth-authorization-server");
    expect(res.status).toBe(200);
    const meta = (await res.json()) as { token_endpoint?: string; scopes_supported?: string[] };
    expect(meta.token_endpoint).toContain("/oauth/token");
    expect(meta.scopes_supported).toContain("servicenow:admin_script");
  });
});

// Origin validation (S12) is enforced inside the authenticated apiHandler; the pure
// predicate is unit-tested here (DNS-rebinding defense for authenticated browser clients).
describe("Phase 0.11 — Origin validation predicate (S12)", () => {
  const cfg = { allowedOrigins: ["https://app.example.com"], allowLocalhost: true };
  it("rejects a foreign browser Origin", () => {
    const req = new Request("http://localhost/mcp", { headers: { Origin: "https://evil.example.com" } });
    expect(isOriginAllowed(req, cfg)).toBe(false);
  });
  it("allows loopback, a configured origin, and absent Origin (non-browser)", () => {
    expect(isOriginAllowed(new Request("http://localhost/mcp", { headers: { Origin: "http://localhost:8787" } }), cfg)).toBe(true);
    expect(isOriginAllowed(new Request("http://localhost/mcp", { headers: { Origin: "https://app.example.com" } }), cfg)).toBe(true);
    expect(isOriginAllowed(new Request("http://localhost/mcp"), cfg)).toBe(true);
  });
  it("does not treat a matching host with a different scheme as same-origin", () => {
    const req = new Request("https://worker.example/mcp", {
      headers: { Origin: "http://worker.example" },
    });
    expect(isOriginAllowed(req, { allowedOrigins: [], allowLocalhost: false })).toBe(false);
  });
  it("L-2 — denies a loopback Origin when allowLocalhost is OMITTED (fail-closed default)", () => {
    const req = new Request("https://app.example.com/mcp", { headers: { Origin: "http://localhost:8787" } });
    expect(isOriginAllowed(req, { allowedOrigins: ["https://app.example.com"] })).toBe(false);
  });
});
