// ServiceNow HTTP client abstraction (plan §1.5). The interface lets the RPC layer be
// unit-verified against a mock; the concrete fetch client (bearer injection host-side,
// retry/jitter) is structurally complete but its network behavior needs a live
// instance (Phase 1.5 — NOT verified here).

import { canonicalizeInstanceHost, type InstanceAllowlist } from "./url-allowlist.js";

export interface SnRequest {
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  /** Relative `/api/...` path; validated against the denylist before use. */
  path: string;
  query?: Record<string, string>;
  body?: unknown;
}

export interface SnResponse {
  status: number;
  json: unknown;
}

export interface SnHttpClient {
  request(req: SnRequest): Promise<SnResponse>;
}

/** Options for the concrete client (credential is injected host-side, never exposed). */
export interface SnFetchClientOptions {
  instanceHost: string;
  allowlist: InstanceAllowlist;
  /**
   * Returns the full `Authorization` header value (e.g. "Bearer <tok>" for OAuth, or
   * "Basic <b64>" for the dev path). Called per request so rotation is transparent.
   */
  getAuthorization: () => Promise<string>;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

/**
 * Concrete ServiceNow client. Validates host + path, injects the bearer host-side,
 * and applies a request timeout. Retry/jitter on 429/5xx is a Phase-1.5 addition.
 * NOTE: network behavior is unverified locally — see OPEN_QUESTIONS.md.
 */
export class SnFetchClient implements SnHttpClient {
  private readonly host: string;
  private readonly opts: SnFetchClientOptions;
  constructor(opts: SnFetchClientOptions) {
    this.host = canonicalizeInstanceHost(opts.instanceHost, opts.allowlist); // SSRF guard (S15)
    this.opts = opts;
  }

  async request(req: SnRequest): Promise<SnResponse> {
    // Transport-level path safety only (no scheme/userinfo, must be /api/...). NOTE (L-1): the B2
    // executor-bypass DENYLIST (scripted-rest-denylist.ts) is DEFINED BUT NOT YET WIRED — there is
    // no generic `scriptedRest` RPC method today, so nothing routes through it. If a generic
    // scripted-REST tool is ever added it MUST call checkScriptedRestPath(); the sanctioned
    // runServerScript() path legitimately targets the executor endpoint and passes through here.
    if (!req.path.startsWith("/api/") || req.path.includes("://") || req.path.includes("@")) {
      throw new Error(`unsafe ServiceNow path: ${req.path}`);
    }
    // Reject dot-segment traversal in the raw path (literal or percent-encoded) before
    // URL parsing normalizes it away (defense in depth behind the RPC identifier checks).
    const lowered = req.path.toLowerCase();
    if (lowered.includes("..") || lowered.includes("%2e")) {
      throw new Error(`unsafe ServiceNow path: ${req.path}`);
    }
    const url = new URL(`https://${this.host}${req.path}`);
    // After normalization, the pathname must STILL be under /api/ — catches any residual
    // traversal/normalization that escaped the raw-string checks above.
    if (!url.pathname.startsWith("/api/")) {
      throw new Error(`unsafe ServiceNow path: ${req.path}`);
    }
    for (const [k, v] of Object.entries(req.query ?? {})) url.searchParams.set(k, v);

    const authorization = await this.opts.getAuthorization();
    const fetchImpl = this.opts.fetchImpl ?? fetch;
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), this.opts.timeoutMs ?? 30_000);
    try {
      const res = await fetchImpl(url.toString(), {
        method: req.method,
        headers: {
          authorization,
          accept: "application/json",
          ...(req.body !== undefined ? { "content-type": "application/json" } : {}),
        },
        ...(req.body !== undefined ? { body: JSON.stringify(req.body) } : {}),
        // M-7: never auto-follow redirects with the Authorization bearer attached. Cloudflare's
        // runtime forwards `Authorization` across cross-origin redirects (unlike browsers), and the
        // SSRF allowlist (canonicalizeInstanceHost) only validates the INITIAL host — a 3xx from the
        // instance (open redirect / on-path MITM / misconfig) would otherwise steer the
        // credential-bearing request to an arbitrary host (S15 bypass + credential exfil). SN
        // Table/scripted-REST APIs return data directly and never legitimately 3xx.
        redirect: "manual",
        signal: ac.signal,
      });
      // A redirect from a ServiceNow data API is anomalous; fail CLOSED rather than follow it with
      // credentials attached. (With redirect:"manual" the 3xx is surfaced here, not followed.)
      if (res.status >= 300 && res.status < 400) {
        throw new Error(`refusing to follow a ${res.status} redirect from ServiceNow (credentials attached; off-allowlist egress risk)`);
      }
      const text = await res.text();
      let json: unknown = null;
      try {
        json = text ? JSON.parse(text) : null;
      } catch {
        json = { raw: text };
      }
      return { status: res.status, json };
    } finally {
      clearTimeout(timer);
    }
  }
}
