/** Validate and canonicalize the worker's externally reachable origin for OAuth redirects. */
export function canonicalPublicOrigin(value: string | undefined): string | null {
  if (!value) return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== "https:") return null;
  if (url.username || url.password || url.pathname !== "/" || url.search || url.hash) return null;
  return url.origin;
}
