import { describe, expect, it } from "vitest";
import { canonicalizeInstanceHost, UrlNotAllowed } from "../src/sn/url-allowlist.js";
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

  it("exposes response headers to callers", async () => {
    const fetchImpl = (async () =>
      new Response(JSON.stringify({ result: [] }), {
        status: 200,
        headers: { "content-type": "application/json", "x-total-count": "42" },
      })) as unknown as typeof fetch;
    const c = new SnFetchClient({
      instanceHost: "dev1.service-now.com",
      allowlist: { allowedHostSuffixes: ["service-now.com"] },
      getAuthorization: async () => "Bearer t",
      fetchImpl,
    });
    const res = await c.request({ method: "GET", path: "/api/now/table/sys_db_object" });
    expect(res.headers?.["x-total-count"]).toBe("42");
  });

  it("sends pre-serialized bodyJson verbatim instead of re-stringifying req.body", async () => {
    let body: string | null | undefined;
    const fetchImpl = (async (_url: string, init?: RequestInit) => {
      body = init?.body as string | null | undefined;
      return new Response(JSON.stringify({ result: { ok: true } }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch;
    const c = new SnFetchClient({
      instanceHost: "dev1.service-now.com",
      allowlist: { allowedHostSuffixes: ["service-now.com"] },
      getAuthorization: async () => "Bearer t",
      fetchImpl,
    });
    await c.request({ method: "PATCH", path: "/api/now/table/incident/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", bodyJson: "{\"a\":1}" });
    expect(body).toBe("{\"a\":1}");
  });
});
