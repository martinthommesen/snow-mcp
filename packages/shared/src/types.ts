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
  | "internal_error";
