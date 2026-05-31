// Per-actor authorization, enforced host-side before every RPC (plan §2.12; gate B5).
//
// In integration_user mode ServiceNow ACLs do NOT bound a given MCP user — the broad
// identity can read anything — so the Worker must. Pure host logic, unit-verified
// locally. (per_user_oauth mode can use a permissive policy: ServiceNow ACLs bound
// access natively.)

import { McpToolError } from "../sn/errors.js";
import { assertMandatoryRowFilterSafe } from "../sn/validate.js";
import { modeRisk, type Mode } from "@servicenow-codemode/shared";

export interface ActorPolicy {
  /** Instance hosts this actor may reach. Empty = none. */
  allowedInstances: string[];
  tables: { allow?: RegExp[]; deny?: RegExp[] };
  /** table -> forbidden field names stripped from request AND response. */
  fieldMasks: Record<string, string[]>;
  maxMode: Mode;
  maxRowsPerRun: number;
  maxBytesPerRun: number;
  /** table -> mandatory encoded-query AND-ed into every read. */
  rowFilters?: Record<string, string>;
}

/** A permissive policy for a single trusted operator (integration_user, §0.9). */
export function permissivePolicy(allowedInstances: string[]): ActorPolicy {
  return {
    allowedInstances,
    tables: {},
    fieldMasks: {},
    maxMode: "admin_script",
    maxRowsPerRun: Number.MAX_SAFE_INTEGER,
    maxBytesPerRun: Number.MAX_SAFE_INTEGER,
  };
}

/**
 * Validate a policy's mandatory `rowFilters` at load time (P1): a mandatory filter that
 * itself contains a structural operator (`^NQ`/`^OR`/`^EQ`) is self-defeating, since the
 * caller query is AND-ed AFTER it and such an operator would let rows escape the filter.
 * Call when a (restrictive) policy is constructed from config (wired in P6b's loader).
 */
export function assertPolicyRowFiltersSafe(policy: ActorPolicy): void {
  for (const [table, filter] of Object.entries(policy.rowFilters ?? {})) {
    assertMandatoryRowFilterSafe(table, filter);
  }
}

function tableAllowed(policy: ActorPolicy, table: string): boolean {
  if (policy.tables.deny?.some((re) => re.test(table))) return false;
  if (policy.tables.allow && policy.tables.allow.length > 0) {
    return policy.tables.allow.some((re) => re.test(table));
  }
  return true; // no allowlist => allow unless denied
}

/** Throw `actor_policy_denied` if this actor may not touch (instance, table) in `mode`. */
export function assertActorPolicy(
  policy: ActorPolicy,
  ctx: { instance: string; table: string; mode: Mode },
): void {
  if (!policy.allowedInstances.includes(ctx.instance)) {
    throw new McpToolError("actor_policy_denied", `Instance "${ctx.instance}" is not allowed for this actor.`, {
      instance: ctx.instance,
    });
  }
  if (!tableAllowed(policy, ctx.table)) {
    throw new McpToolError("actor_policy_denied", `Table "${ctx.table}" is not allowed for this actor.`, {
      table: ctx.table,
    });
  }
  // FAIL-CLOSED (plan §P6a): modeRisk scores any non-Mode value as +Infinity, so an unknown
  // requested `ctx.mode` exceeds any valid maxMode and is DENIED (never fails open to
  // admin_script via an `undefined > undefined === false` comparison).
  if (modeRisk(ctx.mode) > modeRisk(policy.maxMode)) {
    throw new McpToolError("actor_policy_denied", `Mode "${ctx.mode}" exceeds this actor's maxMode "${policy.maxMode}".`);
  }
}

/** Compose the actor's mandatory row filter with the caller's encoded query (AND). */
export function applyRowFilter(policy: ActorPolicy, table: string, userQuery: string): string {
  const mandatory = policy.rowFilters?.[table];
  if (!mandatory) return userQuery;
  return userQuery ? `${mandatory}^${userQuery}` : mandatory;
}

/** True if a field reference `f` is covered by a mask `m`: exact match OR a dot-walk
 *  descendant (mask `caller_id` also covers `caller_id.value`, `caller_id.name`). */
function isMaskedBy(field: string, mask: string): boolean {
  return field === mask || field.startsWith(`${mask}.`);
}

/** Strip masked fields from a record (response filtering, §2.12). Dot-aware: a mask on
 *  `caller_id` also strips dot-walked keys like `caller_id.value`. */
export function maskRow(policy: ActorPolicy, table: string, row: Record<string, unknown>): Record<string, unknown> {
  const masked = policy.fieldMasks[table];
  if (!masked || masked.length === 0) return row;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(row)) {
    if (!masked.some((m) => isMaskedBy(k, m))) out[k] = v;
  }
  return out;
}

/** Reject requested fields that are masked (request filtering, §2.12). Dot-aware: a
 *  request for `caller_id.name` is denied when `caller_id` is masked. */
export function assertRequestedFieldsAllowed(policy: ActorPolicy, table: string, fields: string[] | undefined): void {
  if (!fields) return;
  const masked = policy.fieldMasks[table];
  if (!masked || masked.length === 0) return;
  const violating = fields.filter((f) => masked.some((m) => isMaskedBy(f, m)));
  if (violating.length > 0) {
    throw new McpToolError("actor_policy_denied", `Fields not permitted for this actor on "${table}": ${violating.join(", ")}.`);
  }
}
