// Shared types used across the host Worker and (eventually) the stdio shim.
// Kept dependency-free so both runtimes can import it.

/** ServiceNow credential mode (plan §2.0). */
export type ServiceNowCredentialMode = "integration_user" | "per_user_oauth";

/** run_code execution mode, ordered by risk: read_only < write < admin_script (plan §2.0.1). */
export type Mode = "read_only" | "write" | "admin_script";

/** Risk ordering for `minByRisk` mode resolution (plan §2.0.1). */
export const MODE_RISK: Readonly<Record<Mode, number>> = {
  read_only: 0,
  write: 1,
  admin_script: 2,
};

/** Typed error codes surfaced to MCP clients (plan §1.6, §3.x). */
export type ErrorCode =
  | "capability_denied"
  | "mode_not_permitted"
  | "actor_policy_denied"
  | "budget_exceeded"
  | "path_denied"
  | "instance_hibernating"
  | "reauth_required"
  | "executor_disabled"
  | "run_server_script_disabled"
  | "actor_signature_invalid"
  | "code_size"
  | "transpile_error"
  | "timeout"
  | "run_error"
  | "internal_error";

/**
 * Runtime tuple of every {@link ErrorCode}, for membership checks (plan §P2). Kept in
 * sync with the union above. `run_error` is the host-attested fallback for an uncaught
 * snippet/RPC error whose typed code the host cannot vouch for.
 */
export const ERROR_CODES = [
  "capability_denied",
  "mode_not_permitted",
  "actor_policy_denied",
  "budget_exceeded",
  "path_denied",
  "instance_hibernating",
  "reauth_required",
  "executor_disabled",
  "run_server_script_disabled",
  "actor_signature_invalid",
  "code_size",
  "transpile_error",
  "timeout",
  "run_error",
  "internal_error",
] as const satisfies readonly ErrorCode[];

// Compile-time exhaustiveness guard (P2): `satisfies` above proves every entry IS an
// ErrorCode; this proves the converse — if a future ErrorCode is added to the union
// without being appended to ERROR_CODES, `Exclude` resolves to that member and this
// line fails to typecheck (so parseSandboxError's membership check can never silently
// drop a real code). Tuple-wrapped to avoid `never` distribution. No runtime effect.
true satisfies [Exclude<ErrorCode, (typeof ERROR_CODES)[number]>] extends [never] ? true : false;
