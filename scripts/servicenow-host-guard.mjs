const DEFAULT_ALLOWED_SUFFIXES = ["service-now.com"];
const LOOPBACK = new Set(["localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"]);
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

function reject(reason, detail) {
  throw new Error(`SNOW_INSTANCE_HOST rejected: ${reason}${detail ? ` (${detail})` : ""}`);
}

function isPrivateOrLoopback(host) {
  if (LOOPBACK.has(host)) return true;
  if (host.startsWith("[")) return true;
  if (IPV4.test(host)) {
    const [a, b] = host.split(".").map(Number);
    if (a === 10 || a === 127) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 169 && b === 254) return true;
    return true;
  }
  return false;
}

function hostMatchesSuffix(host, suffix) {
  return host === suffix || host.endsWith(`.${suffix}`);
}

export function canonicalServiceNowHost(raw, allowedSuffixes = DEFAULT_ALLOWED_SUFFIXES) {
  if (typeof raw !== "string" || !raw.trim()) reject("missing");
  const trimmed = raw.trim();
  const candidate = trimmed.includes("://") ? trimmed : `https://${trimmed}`;
  let url;
  try {
    url = new URL(candidate);
  } catch {
    reject("malformed", trimmed);
  }
  if (url.protocol !== "https:") reject("not_https", url.protocol);
  if (url.username || url.password) reject("has_userinfo");
  if ((url.pathname !== "" && url.pathname !== "/") || url.search || url.hash) {
    reject("has_path_query_or_fragment", `${url.pathname}${url.search}${url.hash}`);
  }
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (isPrivateOrLoopback(host)) reject("private_or_loopback", host);
  const suffixes = allowedSuffixes.map((suffix) => suffix.toLowerCase().replace(/^\./, ""));
  if (!suffixes.some((suffix) => hostMatchesSuffix(host, suffix))) reject("not_allowlisted", host);
  return host;
}
