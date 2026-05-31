// Per-actor authorization, enforced host-side before every RPC (plan §2.12; gate B5).
//
// In integration_user mode ServiceNow ACLs do NOT bound a given MCP user — the broad
// identity can read anything — so the Worker must. Pure host logic, unit-verified
// locally. (per_user_oauth mode can use a permissive policy: ServiceNow ACLs bound
// access natively.)

import { McpToolError } from "../sn/errors.js";
import { assertMandatoryRowFilterSafe } from "../sn/validate.js";
import { isValidMode, modeRisk, type Mode } from "@servicenow-codemode/shared";

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

/** The env slice the policy loader reads (narrow + unit-testable in isolation). */
export interface PolicyEnv {
  /** Comma-separated table names this actor may touch (each anchored to a whole-name match). */
  ACTOR_POLICY_TABLE_ALLOWLIST?: string;
  /** `table:field,field;table:field` — fields stripped from reads AND rejected on writes. */
  ACTOR_POLICY_FIELD_MASKS?: string;
  /** `table:encoded^query;table:encoded^query` — mandatory filter AND-ed into every read. */
  ACTOR_POLICY_ROW_FILTERS?: string;
  /** Per-run row ceiling (positive integer). */
  ACTOR_POLICY_MAX_ROWS_PER_RUN?: string;
  /** Per-run byte ceiling (positive integer). */
  ACTOR_POLICY_MAX_BYTES_PER_RUN?: string;
  /** Highest mode this actor may request (read_only | write | admin_script). */
  ACTOR_POLICY_MAX_MODE?: Mode;
}

/** Escape a table name into an anchored whole-name RegExp (substring matches would let
 *  `incident` admit `incident_extra`). Names are lowercase alnum + underscore; we anchor
 *  defensively in case a config value carries regex metacharacters. */
function tableNameRegExp(name: string): RegExp {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^${escaped}$`);
}

function parseList(value: string | undefined): string[] {
  return (value ?? "").split(",").map((s) => s.trim()).filter(Boolean);
}

/** Parse `table:a,b;table2:c` into `{ table: [a,b], table2: [c] }`. */
function parseTableMap(value: string | undefined): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const entry of (value ?? "").split(";").map((s) => s.trim()).filter(Boolean)) {
    const idx = entry.indexOf(":");
    if (idx < 0) continue;
    const table = entry.slice(0, idx).trim();
    const fields = parseList(entry.slice(idx + 1));
    if (table && fields.length > 0) out[table] = fields;
  }
  return out;
}

/** Parse `table:encoded^query;table2:other^query` into `{ table: "encoded^query" }`. The value
 *  is everything after the FIRST colon (a filter may itself contain `:` in date/time literals). */
function parseRowFilters(value: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const entry of (value ?? "").split(";").map((s) => s.trim()).filter(Boolean)) {
    const idx = entry.indexOf(":");
    if (idx < 0) continue;
    const table = entry.slice(0, idx).trim();
    const filter = entry.slice(idx + 1).trim();
    if (table && filter) out[table] = filter;
  }
  return out;
}

function parsePositiveInt(value: string | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1) {
    throw new Error(`ActorPolicy ceiling must be a positive integer, got: ${value}`);
  }
  return n;
}

/**
 * Load the host-side ActorPolicy from env config (P6b).
 *
 * DEFAULT DECISION (preserve the live single-operator deployment; mirror P4/P5's opt-in gates):
 * when NO policy config var is set, FALL BACK to the existing `permissivePolicy` so today's
 * deployment keeps working — we do NOT flip the runtime default to deny-all. When ANY policy var
 * IS provided, build a RESTRICTIVE policy from it (table allowlist + field masks + row filters +
 * per-run row/byte ceilings + max mode) and VALIDATE the configured rowFilters at load
 * (`assertPolicyRowFiltersSafe` → throws on a self-defeating `^NQ`/`^OR`/`^EQ` filter = fail-closed).
 * The recommended restrictive config ships as a DOCUMENTED EXAMPLE (.dev.vars.example), not as the
 * hardcoded runtime default.
 */
export function loadActorPolicy(env: PolicyEnv, instanceHost: string): ActorPolicy {
  const allowlist = parseList(env.ACTOR_POLICY_TABLE_ALLOWLIST);
  const fieldMasks = parseTableMap(env.ACTOR_POLICY_FIELD_MASKS);
  const rowFilters = parseRowFilters(env.ACTOR_POLICY_ROW_FILTERS);
  const configured =
    allowlist.length > 0 ||
    Object.keys(fieldMasks).length > 0 ||
    Object.keys(rowFilters).length > 0 ||
    env.ACTOR_POLICY_MAX_ROWS_PER_RUN !== undefined ||
    env.ACTOR_POLICY_MAX_BYTES_PER_RUN !== undefined ||
    env.ACTOR_POLICY_MAX_MODE !== undefined;

  if (!configured) return permissivePolicy([instanceHost]); // live single-operator default, unchanged.

  // FAIL-CLOSED on the mode ceiling (P6b-2): validate the configured maxMode BEFORE building
  // the policy. assertActorPolicy compares `modeRisk(ctx.mode) > modeRisk(policy.maxMode)`, and
  // modeRisk(non-Mode) is +Infinity. Because maxMode is the CEILING (right) operand, a SET-but-
  // INVALID value (operator typo: "readonly"/"Read_Only"/"read-only") would make every finite
  // requested risk `< +Infinity` and silently DISABLE the ceiling — a fail-OPEN that admits
  // admin_script. So coerce a set-but-invalid value to "read_only" (the most restrictive ceiling),
  // mirroring handlers.ts:parseMaxMode for the sibling tenant/instance ceilings. Unset stays
  // "read_only" too (restrictive default). isValidMode collapses both cases.
  const maxMode: Mode = isValidMode(env.ACTOR_POLICY_MAX_MODE) ? env.ACTOR_POLICY_MAX_MODE : "read_only";

  const policy: ActorPolicy = {
    allowedInstances: [instanceHost],
    tables: allowlist.length > 0 ? { allow: allowlist.map(tableNameRegExp) } : {},
    fieldMasks,
    maxMode, // restrictive default: read_only unless raised (set-but-invalid coerced to read_only).
    maxRowsPerRun: parsePositiveInt(env.ACTOR_POLICY_MAX_ROWS_PER_RUN, 10_000),
    maxBytesPerRun: parsePositiveInt(env.ACTOR_POLICY_MAX_BYTES_PER_RUN, 5_000_000),
    ...(Object.keys(rowFilters).length > 0 ? { rowFilters } : {}),
  };
  // Fail-closed: a self-defeating mandatory filter (one that itself contains a structural
  // operator) is rejected at LOAD, before it can ever let a caller escape the AND-ed filter.
  assertPolicyRowFiltersSafe(policy);
  return policy;
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

// Leading clause-operator keywords in a ServiceNow encoded query (longest-first so ORDERBYDESC
// is stripped before ORDERBY, and ORDERBY before OR). Used to reach the field token in a clause
// like `^ORsalary>5` / `^ORDERBYsalary` / `^GROUPBYdept`.
const QUERY_OP_PREFIX = /^(ORDERBYDESC|ORDERBY|GROUPBY|NQ|OR|EQ)/i;

/** The leading ServiceNow field token of a clause: the initial run of lowercase field chars.
 *  SN field names are lowercase `[a-z0-9_.]` (see validate.ts FIELD_NAME), so an UPPERCASE
 *  operator (LIKE/IN/STARTSWITH/ISEMPTY/BETWEEN/…) or a symbol (`=`,`>`,`<`) terminates the run
 *  cleanly — `salaryLIKE5` and `salary>5` both yield `salary`. */
function leadingFieldToken(clause: string): string {
  const m = clause.match(/^[a-z0-9_.]+/);
  return m ? m[0] : "";
}

/**
 * M-6: reject a caller-supplied encoded query whose PREDICATE / ordering / grouping references a
 * masked field. `fieldMasks` already strips masked fields from requested `fields` and from
 * returned rows, but a caller could still filter ON a masked column without REQUESTING it
 * (`tableQuery({table:'sys_user', query:'salary>500000', fields:['name']})` is a row-selection
 * oracle; `aggregate({query:'ssn=…'})` is an equality oracle) and reconstruct the masked value.
 *
 * Fail-safe: split on `^` clause boundaries; for each clause extract the field token both raw and
 * after stripping one leading operator keyword (so `^ORsalary>5` and `^ORDERBYsalary` are caught),
 * and deny (`actor_policy_denied`) if either is masked (dot-aware via isMaskedBy). This errs toward
 * over-rejection, the correct direction for a confidentiality control. Residual edge: a rare
 * lowercase-operator form (`salarylike5`) is not detected — SN-canonical queries use UPPERCASE
 * operators; this mirrors validate.ts's documented P8 case-sensitivity caveat.
 */
export function assertQueryFieldsAllowed(policy: ActorPolicy, table: string, userQuery: string): void {
  const masked = policy.fieldMasks[table];
  if (!masked || masked.length === 0 || !userQuery) return;
  for (const clause of userQuery.split("^")) {
    const candidates = [leadingFieldToken(clause), leadingFieldToken(clause.replace(QUERY_OP_PREFIX, ""))];
    for (const f of candidates) {
      if (f && masked.some((m) => isMaskedBy(f, m))) {
        throw new McpToolError("actor_policy_denied", `Query references a field not permitted for this actor on "${table}": ${f}.`);
      }
    }
  }
}
