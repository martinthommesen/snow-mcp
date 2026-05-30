// ServiceNow base-URL allowlist + canonicalization (plan §1.5, §2.4; gate S15/SSRF).
//
// Pure host logic, fully verifiable locally. The ServiceNow client (Phase 1.5) calls
// canonicalizeInstanceHost() once per configured instance and refuses anything that
// is not an https host on the tenant allowlist — defeating SSRF / host-spoofing
// before any token is attached.

export type UrlRejectReason =
  | "not_https"
  | "has_userinfo"
  | "has_path_query_or_fragment"
  | "not_allowlisted"
  | "private_or_loopback"
  | "malformed";

export class UrlNotAllowed extends Error {
  readonly reason: UrlRejectReason;
  constructor(reason: UrlRejectReason, detail?: string) {
    super(`instance host rejected: ${reason}${detail ? ` (${detail})` : ""}`);
    this.name = "UrlNotAllowed";
    this.reason = reason;
  }
}

export interface InstanceAllowlist {
  /**
   * Allowed host suffixes, lowercased, no leading dot, e.g. ["service-now.com"]
   * for PDIs/dev or ["mycorp.service-now.com"] to pin one instance. A host matches
   * if it equals a suffix or ends with "." + suffix.
   */
  allowedHostSuffixes: readonly string[];
}

// Literal-IP and loopback rejection (defense-in-depth; ServiceNow is always a hostname).
const LOOPBACK = new Set(["localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"]);
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

function isPrivateOrLoopback(host: string): boolean {
  if (LOOPBACK.has(host)) return true;
  if (host.startsWith("[")) return true; // bracketed IPv6 literal
  if (IPV4.test(host)) {
    const octets = host.split(".").map(Number) as [number, number, number, number];
    const [a, b] = octets;
    if (a === 10 || a === 127) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 169 && b === 254) return true; // link-local
    return true; // any bare IPv4 literal is suspect for a ServiceNow host
  }
  return false;
}

function hostMatchesSuffix(host: string, suffix: string): boolean {
  return host === suffix || host.endsWith(`.${suffix}`);
}

/**
 * Accepts a bare host ("dev123.service-now.com") or a full https URL with no path.
 * Returns the canonical lowercase host. Throws UrlNotAllowed otherwise.
 */
export function canonicalizeInstanceHost(input: string, allowlist: InstanceAllowlist): string {
  const raw = input.trim();
  // Allow a bare host by prefixing a scheme for URL parsing.
  const candidate = raw.includes("://") ? raw : `https://${raw}`;

  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    throw new UrlNotAllowed("malformed", raw);
  }

  if (url.protocol !== "https:") throw new UrlNotAllowed("not_https", url.protocol);
  if (url.username !== "" || url.password !== "") throw new UrlNotAllowed("has_userinfo");

  // A base URL must carry no path/query/fragment (path "/" is acceptable).
  if ((url.pathname !== "" && url.pathname !== "/") || url.search !== "" || url.hash !== "") {
    throw new UrlNotAllowed("has_path_query_or_fragment", url.pathname + url.search + url.hash);
  }

  // Normalize host: lowercase, strip a single trailing dot. (URL already applies IDNA/punycode.)
  const host = url.hostname.toLowerCase().replace(/\.$/, "");

  if (isPrivateOrLoopback(host)) throw new UrlNotAllowed("private_or_loopback", host);

  const ok = allowlist.allowedHostSuffixes.some((s) => hostMatchesSuffix(host, s.toLowerCase()));
  if (!ok) throw new UrlNotAllowed("not_allowlisted", host);

  return host;
}
