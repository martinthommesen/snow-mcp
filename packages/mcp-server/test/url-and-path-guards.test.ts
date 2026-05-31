import { describe, expect, it } from "vitest";
import { canonicalizeInstanceHost, UrlNotAllowed } from "../src/sn/url-allowlist.js";
import { checkScriptedRestPath, PathDenied } from "../src/sn/scripted-rest-denylist.js";
import { SnFetchClient } from "../src/sn/http.js";

// ─── S15 — URL allowlist / SSRF canonicalization (Phase 2.4) ──────────────────
const allow = { allowedHostSuffixes: ["service-now.com"] } as const;

describe("S15 — instance host allowlist / SSRF", () => {
  it("accepts a bare PDI host and a full https URL, returning the canonical host", () => {
    expect(canonicalizeInstanceHost("dev12345.service-now.com", allow)).toBe("dev12345.service-now.com");
    expect(canonicalizeInstanceHost("https://DEV12345.Service-Now.com/", allow)).toBe("dev12345.service-now.com");
  });

  it("rejects non-https, userinfo, paths, off-allowlist hosts, and IP literals", () => {
    const bad: Array<[string, string]> = [
      ["http://dev1.service-now.com", "not_https"],
      ["https://user:pass@dev1.service-now.com", "has_userinfo"],
      ["https://dev1.service-now.com/api/now/table", "has_path_query_or_fragment"],
      ["https://evil.example.com", "not_allowlisted"],
      ["https://10.0.0.5", "private_or_loopback"],
      ["https://localhost", "private_or_loopback"],
    ];
    for (const [input, reason] of bad) {
      try {
        canonicalizeInstanceHost(input, allow);
        throw new Error(`expected rejection for ${input}`);
      } catch (e) {
        expect(e).toBeInstanceOf(UrlNotAllowed);
        expect((e as UrlNotAllowed).reason).toBe(reason);
      }
    }
  });

  it("strips a trailing dot and matches the suffix exactly (no partial-suffix bypass)", () => {
    expect(canonicalizeInstanceHost("dev1.service-now.com.", allow)).toBe("dev1.service-now.com");
    expect(() => canonicalizeInstanceHost("evilservice-now.com", allow)).toThrow(UrlNotAllowed);
  });
});

// ─── B2 — scriptedRest path denylist (Phase 3.2) ──────────────────────────────
describe("B2 — scriptedRest cannot reach the executor or tamper config/audit", () => {
  it("permits an ordinary /api path", () => {
    expect(checkScriptedRestPath("/api/now/table/incident")).toBe("/api/now/table/incident");
  });

  it("denies the executor endpoint at any depth (incl. numeric global-scope namespace)", () => {
    expect(() => checkScriptedRestPath("/api/x_mcp/executor/run")).toThrow(PathDenied);
    expect(() => checkScriptedRestPath("/api/some_scope/executor/go")).toThrow(PathDenied);
    expect(() => checkScriptedRestPath("/api/1793136/x_mcp/executor/run")).toThrow(PathDenied);
  });

  it("denies config/audit/auth/login tampering paths", () => {
    for (const p of [
      "/api/now/table/sys_properties",
      "/api/now/table/x_mcp_audit_log",
      "/oauth_token.do",
      "/login.do",
    ]) {
      expect(() => checkScriptedRestPath(p)).toThrow(PathDenied);
    }
  });

  it("denies absolute URLs, userinfo, non-/api paths, and traversal", () => {
    for (const p of [
      "https://evil.com/api/now/table/incident",
      "//evil.com/api/x",
      "/api/now/../x_mcp/executor/run",
      "/sys_properties.do",
      "/api/now/table/incident/%2e%2e/sys_properties",
    ]) {
      expect(() => checkScriptedRestPath(p)).toThrow(PathDenied);
    }
  });
});

// ─── P1 — SnFetchClient transport path hardening (defense in depth) ────────────
describe("P1 — SnFetchClient rejects traversal before any fetch", () => {
  function client(): { c: SnFetchClient; fetched: string[] } {
    const fetched: string[] = [];
    const fetchImpl = (async (url: string) => {
      fetched.push(String(url));
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    }) as unknown as typeof fetch;
    const c = new SnFetchClient({
      instanceHost: "dev1.service-now.com",
      allowlist: { allowedHostSuffixes: ["service-now.com"] },
      getAuthorization: async () => "Bearer t",
      fetchImpl,
    });
    return { c, fetched };
  }

  it("rejects literal and percent-encoded dot-segment traversal in the raw path", async () => {
    const { c, fetched } = client();
    for (const path of [
      "/api/now/table/incident/../sys_properties",
      "/api/now/table/incident/%2e%2e/sys_properties",
      "/api/now/table/incident/%2E%2E/sys_properties",
    ]) {
      await expect(c.request({ method: "GET", path })).rejects.toThrow(/unsafe ServiceNow path/);
    }
    expect(fetched).toEqual([]); // never reached the network
  });

  it("allows an ordinary /api path through to fetch", async () => {
    const { c, fetched } = client();
    await c.request({ method: "GET", path: "/api/now/table/incident" });
    expect(fetched[0]).toContain("/api/now/table/incident");
  });
});
