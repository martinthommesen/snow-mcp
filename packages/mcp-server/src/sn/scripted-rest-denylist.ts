// scriptedRest path policy (plan §3.2; gate B2; threat T18).
//
// Generic scriptedRest must NOT become a bypass around runServerScript()'s mode gate,
// ledger, actor signing, and executor audit. Only relative `/api/...` paths are
// permitted, and an explicit denylist blocks the executor endpoint, config/audit
// tampering, and the auth/login surfaces. Pure host logic, fully verifiable locally.
// (The positive guarantee — "the executor is reachable ONLY via runServerScript()" —
// is enforced where the executor client lives, Phase 5.6.)

export type PathRejectReason =
  | "not_relative_api_path"
  | "has_userinfo_or_absolute"
  | "path_traversal"
  | "denylisted";

export class PathDenied extends Error {
  readonly reason: PathRejectReason;
  constructor(reason: PathRejectReason, detail?: string) {
    super(`path_denied: ${reason}${detail ? ` (${detail})` : ""}`);
    this.name = "PathDenied";
    this.reason = reason;
  }
}

// Denylist (plan §3.2). Patterns match against the normalized lowercase path.
const DENY_PATTERNS: readonly RegExp[] = [
  /\/executor(\/|$)/, // ANY executor-shaped resource at ANY path depth (incl. the
  // numeric-namespace form `/api/1793136/x_mcp/executor/run` global-scope APIs get) —
  // reachable ONLY via runServerScript()
  /^\/api\/now\/table\/sys_properties(\/|$)/, // kill switch / config tampering
  /^\/api\/now\/table\/x_mcp_audit_log(\/|$)/, // audit tampering
  /^\/oauth_[^/]*\.do(\/|$|\?)/, // token endpoints
  /^\/login\.do(\/|$|\?)/, // login / UI
];

/**
 * Validate a scriptedRest path. Returns the normalized path or throws PathDenied.
 * Accepts ONLY relative paths beginning with `/api/`. Absolute URLs, userinfo,
 * and `..` traversal are rejected before denylist evaluation.
 */
export function checkScriptedRestPath(input: string): string {
  const path = input.trim();

  // Reject absolute URLs and anything with a scheme or userinfo.
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(path) || path.includes("@") || path.startsWith("//")) {
    throw new PathDenied("has_userinfo_or_absolute", path);
  }

  if (!path.startsWith("/api/")) {
    throw new PathDenied("not_relative_api_path", path);
  }

  // Path traversal (raw or percent-encoded).
  const lowered = path.toLowerCase();
  if (lowered.includes("..") || lowered.includes("%2e%2e")) {
    throw new PathDenied("path_traversal", path);
  }

  for (const re of DENY_PATTERNS) {
    if (re.test(lowered)) {
      throw new PathDenied("denylisted", path);
    }
  }

  return path;
}
