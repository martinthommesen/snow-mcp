import type { ConsentRateDO } from "../do/consent-rate.js";

export type ConsentRateNamespace = DurableObjectNamespace<ConsentRateDO>;

export async function sourceIpRateLimited(
  request: Request,
  namespace: ConsentRateNamespace | undefined,
  limiterName: string,
): Promise<boolean> {
  if (!namespace) {
    console.error(JSON.stringify({ event: "consent_rate_limit_unbound", limiterName }));
    return true;
  }
  // CF-Connecting-IP is always present on the Cloudflare edge; a missing header collapses to one
  // shared key, so local/test callers remain collectively capped instead of bypassing the limit.
  const ip = request.headers.get("CF-Connecting-IP") ?? "";
  const limiter = namespace.get(namespace.idFromName(limiterName));
  return !(await limiter.allow(ip, Date.now()));
}
