// Origin validation for Streamable HTTP transport (plan §3.1, Phase 0.11 / 7.4, S12).
//
// DNS-rebinding defense: a browser page on evil.com must not be able to drive a
// local/remote MCP endpoint via a forged Host while the victim's browser supplies
// cookies/headers. The MCP transport spec (2025-11-25) requires Origin validation.
//
// Policy:
//  - No Origin header (non-browser client: Inspector, Claude, curl) -> allowed.
//    Origin is browser-enforced; its ABSENCE means the request is not a browser
//    cross-origin call. Auth (Phase 1) is the control for non-browser callers.
//  - Origin present -> must be in the configured allowlist (exact, scheme+host+port).
//  - localhost / 127.0.0.1 / [::1] origins -> allowed for local dev.

export interface OriginConfig {
  /** Exact allowed origins, e.g. "https://app.example.com". Compared case-insensitively. */
  allowedOrigins: readonly string[];
  /** Allow localhost/loopback origins (dev). Default true. */
  allowLocalhost?: boolean;
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

function isLoopbackOrigin(origin: string): boolean {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return false;
  }
  return LOOPBACK_HOSTS.has(url.hostname);
}

/**
 * Returns true if the request's Origin is acceptable.
 * Absent Origin is treated as a non-browser request and allowed (see policy above).
 */
export function isOriginAllowed(request: Request, config: OriginConfig): boolean {
  const origin = request.headers.get("Origin");
  if (origin === null) return true; // non-browser client

  const allowLocalhost = config.allowLocalhost ?? true;
  if (allowLocalhost && isLoopbackOrigin(origin)) return true;

  const normalized = origin.toLowerCase().replace(/\/$/, "");
  return config.allowedOrigins.some((o) => o.toLowerCase().replace(/\/$/, "") === normalized);
}

/** Build a 403 Response for a rejected Origin. */
export function originDeniedResponse(): Response {
  return new Response(
    JSON.stringify({ error: "origin_not_allowed" }),
    { status: 403, headers: { "content-type": "application/json" } },
  );
}
