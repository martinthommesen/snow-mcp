// Per-actor authorization, enforced host-side before every RPC (plan §2.12; gate B5).
//
// In integration_user mode ServiceNow ACLs do NOT bound a given MCP user — the broad
// identity can read anything — so the Worker must. Pure host logic, unit-verified
// locally. (per_user_oauth mode can use a permissive policy: ServiceNow ACLs bound
// access natively.)

import { McpToolError } from "../sn/errors.js";
import { assertMandatoryRowFilterSafe } from "../sn/validate.js";
import { isValidMode, modeRisk, type Mode } from "@servicenow-codemode/shared";

export type TableRule = string | RegExp;

export interface ActorPolicy {
  /** Instance hosts this actor may reach. Empty = none. */
  allowedInstances: string[];
  tables: { allow?: TableRule[]; deny?: TableRule[] };
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

const TABLE_NAME_RE = /^[a-z0-9_]{1,80}$/;
const FIELD_NAME_RE = /^[a-z0-9_.]{1,80}$/;

function parseList(value: string | undefined): string[] {
  return (value ?? "").split(",").map((s) => s.trim()).filter(Boolean);
}

function hasNonEmptyConfig(value: string | undefined): boolean {
  return value !== undefined && value.trim() !== "";
}

function assertConfiguredTableName(label: string, table: string, entry: string): void {
  if (!TABLE_NAME_RE.test(table)) {
    throw new Error(`${label} contains invalid table name "${table}" in entry "${entry}".`);
  }
}

function assertConfiguredFieldName(label: string, field: string, entry: string): void {
  if (!FIELD_NAME_RE.test(field)) {
    throw new Error(`${label} contains invalid field name "${field}" in entry "${entry}".`);
  }
}

function assertUniqueTableEntry(label: string, out: Record<string, unknown>, table: string, entry: string): void {
  if (Object.hasOwn(out, table)) {
    throw new Error(`${label} contains duplicate table entry "${table}" in entry "${entry}".`);
  }
}

function parseTableAllowlist(value: string | undefined): string[] {
  const tables = parseList(value);
  if (hasNonEmptyConfig(value) && tables.length === 0) {
    throw new Error("ACTOR_POLICY_TABLE_ALLOWLIST is set but contains no table names.");
  }
  for (const table of tables) {
    assertConfiguredTableName("ACTOR_POLICY_TABLE_ALLOWLIST", table, table);
  }
  return tables;
}

/** Parse `table:a,b;table2:c` into `{ table: [a,b], table2: [c] }`. */
function parseTableMap(value: string | undefined, label: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  const entries = (value ?? "").split(";").map((s) => s.trim()).filter(Boolean);
  if (hasNonEmptyConfig(value) && entries.length === 0) throw new Error(`${label} is set but contains no entries.`);
  for (const entry of entries) {
    const idx = entry.indexOf(":");
    if (idx <= 0) throw new Error(`${label} entry must be "table:field,field", got "${entry}".`);
    const table = entry.slice(0, idx).trim();
    assertConfiguredTableName(label, table, entry);
    assertUniqueTableEntry(label, out, table, entry);
    const fields = parseList(entry.slice(idx + 1));
    if (fields.length === 0) throw new Error(`${label} entry must include at least one field, got "${entry}".`);
    for (const field of fields) assertConfiguredFieldName(label, field, entry);
    out[table] = fields;
  }
  return out;
}

/** Parse `table:encoded^query;table2:other^query` into `{ table: "encoded^query" }`. The value
 *  is everything after the FIRST colon (a filter may itself contain `:` in date/time literals). */
function parseRowFilters(value: string | undefined, label: string): Record<string, string> {
  const out: Record<string, string> = {};
  const entries = (value ?? "").split(";").map((s) => s.trim()).filter(Boolean);
  if (hasNonEmptyConfig(value) && entries.length === 0) throw new Error(`${label} is set but contains no entries.`);
  for (const entry of entries) {
    const idx = entry.indexOf(":");
    if (idx <= 0) throw new Error(`${label} entry must be "table:encoded_query", got "${entry}".`);
    const table = entry.slice(0, idx).trim();
    assertConfiguredTableName(label, table, entry);
    assertUniqueTableEntry(label, out, table, entry);
    const filter = entry.slice(idx + 1).trim();
    if (!filter) throw new Error(`${label} entry must include a non-empty encoded query, got "${entry}".`);
    out[table] = filter;
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
  const allowlist = parseTableAllowlist(env.ACTOR_POLICY_TABLE_ALLOWLIST);
  const fieldMasks = parseTableMap(env.ACTOR_POLICY_FIELD_MASKS, "ACTOR_POLICY_FIELD_MASKS");
  const rowFilters = parseRowFilters(env.ACTOR_POLICY_ROW_FILTERS, "ACTOR_POLICY_ROW_FILTERS");
  const configured =
    hasNonEmptyConfig(env.ACTOR_POLICY_TABLE_ALLOWLIST) ||
    hasNonEmptyConfig(env.ACTOR_POLICY_FIELD_MASKS) ||
    hasNonEmptyConfig(env.ACTOR_POLICY_ROW_FILTERS) ||
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
  // mirroring effective-mode.ts:parseMaxMode for the sibling tenant/instance ceilings. Unset stays
  // "read_only" too (restrictive default). isValidMode collapses both cases.
  const maxMode: Mode = isValidMode(env.ACTOR_POLICY_MAX_MODE) ? env.ACTOR_POLICY_MAX_MODE : "read_only";

  const policy: ActorPolicy = {
    allowedInstances: [instanceHost],
    tables: allowlist.length > 0 ? { allow: allowlist } : {},
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

interface CompiledTableRules {
  exact: ReadonlySet<string>;
  patterns: readonly RegExp[];
}

interface MaskIndex {
  readonly fields: ReadonlySet<string>;
}

interface CompiledPolicy {
  allowedInstances: ReadonlySet<string>;
  deny: CompiledTableRules;
  allow: CompiledTableRules;
  hasAllowRules: boolean;
  masks: ReadonlyMap<string, MaskIndex>;
}

// ActorPolicy is constructed once per request/config path. Cache derived lookup structures so
// every read/write/discovery gate does not rescan raw arrays for instances, tables, and masks.
const compiledPolicies = new WeakMap<ActorPolicy, CompiledPolicy>();

function compileTableRules(rules: readonly TableRule[] | undefined): CompiledTableRules {
  const exact = new Set<string>();
  const patterns: RegExp[] = [];
  for (const rule of rules ?? []) {
    if (typeof rule === "string") exact.add(rule);
    else patterns.push(rule);
  }
  return { exact, patterns };
}

function compilePolicy(policy: ActorPolicy): CompiledPolicy {
  let compiled = compiledPolicies.get(policy);
  if (compiled) return compiled;
  const masks = new Map<string, MaskIndex>();
  for (const [table, fields] of Object.entries(policy.fieldMasks)) {
    masks.set(table, { fields: new Set(fields) });
  }
  compiled = {
    allowedInstances: new Set(policy.allowedInstances),
    deny: compileTableRules(policy.tables.deny),
    allow: compileTableRules(policy.tables.allow),
    hasAllowRules: Boolean(policy.tables.allow && policy.tables.allow.length > 0),
    masks,
  };
  compiledPolicies.set(policy, compiled);
  return compiled;
}

function matchesTable(rules: CompiledTableRules, table: string): boolean {
  return rules.exact.has(table) || rules.patterns.some((re) => re.test(table));
}

export function isTableAllowed(policy: ActorPolicy, table: string): boolean {
  const compiled = compilePolicy(policy);
  if (matchesTable(compiled.deny, table)) return false;
  if (compiled.hasAllowRules) {
    return matchesTable(compiled.allow, table);
  }
  return true; // no allowlist => allow unless denied
}

/** Throw `actor_policy_denied` if this actor may not touch (instance, table) in `mode`. */
export function assertActorPolicy(
  policy: ActorPolicy,
  ctx: { instance: string; table: string; mode: Mode },
): void {
  const compiled = compilePolicy(policy);
  if (!compiled.allowedInstances.has(ctx.instance)) {
    throw new McpToolError("actor_policy_denied", `Instance "${ctx.instance}" is not allowed for this actor.`, {
      instance: ctx.instance,
    });
  }
  if (!isTableAllowed(policy, ctx.table)) {
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

function maskIndex(policy: ActorPolicy, table: string): MaskIndex | undefined {
  return compilePolicy(policy).masks.get(table);
}

/** True if a field reference is covered by this actor's masks: exact match OR a dot-walk
 *  descendant (mask `caller_id` also covers `caller_id.value`, `caller_id.name`). */
export function isFieldMasked(policy: ActorPolicy, table: string, field: string): boolean {
  return isFieldMaskedByIndex(maskIndex(policy, table), field);
}

function isFieldMaskedByIndex(masked: MaskIndex | undefined, field: string): boolean {
  if (!masked) return false;
  if (masked.fields.has(field)) return true;
  let dot = field.indexOf(".");
  while (dot !== -1) {
    if (masked.fields.has(field.slice(0, dot))) return true;
    dot = field.indexOf(".", dot + 1);
  }
  return false;
}

/** Strip masked fields from a record (response filtering, §2.12). Dot-aware: a mask on
 *  `caller_id` also strips dot-walked keys like `caller_id.value`. */
export function maskRow(policy: ActorPolicy, table: string, row: Record<string, unknown>): Record<string, unknown> {
  const masked = maskIndex(policy, table);
  if (!masked || masked.fields.size === 0) return row;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(row)) {
    if (!isFieldMaskedByIndex(masked, k)) out[k] = v;
  }
  return out;
}

/** Reject requested fields that are masked (request filtering, §2.12). Dot-aware: a
 *  request for `caller_id.name` is denied when `caller_id` is masked. */
export function assertRequestedFieldsAllowed(policy: ActorPolicy, table: string, fields: string[] | undefined): void {
  if (!fields) return;
  const masked = maskIndex(policy, table);
  if (!masked || masked.fields.size === 0) return;
  const violating = fields.filter((f) => isFieldMaskedByIndex(masked, f));
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

// LOWERCASE SN encoded-query word-operators. Their UPPERCASE/symbol forms already terminate the
// leadingFieldToken run; only a LOWERCASE operator glued to a masked field name evades it
// (`salarylike5` reads as one token). We detect that residual by matching a MASKED field followed
// by one of these — so a legit UNMASKED field with an operator-looking name (`incident_statelike1`
// when `incident_state` is not masked) is untouched. List is best-effort; an exotic operator not
// here is the documented residual, gated on the P8 SN operator case-sensitivity confirmation.
const LOWERCASE_QUERY_OPERATORS = [
  "startswith", "endswith", "notlike", "like", "isnotempty", "isempty", "notin", "in",
  "between", "nsameas", "sameas", "anything", "instanceof", "noton", "on",
  "dynamic", "valchanges", "changesfrom", "changesto", "changes",
];

/** If `token` is a masked field immediately followed by a lowercase operator (the
 *  leadingFieldToken-evasion case), return that masked field; else undefined. */
function maskedFieldWithLowercaseOperator(masked: MaskIndex, token: string): string | undefined {
  for (const m of masked.fields) {
    if (token.length > m.length && token.startsWith(m)) {
      const suffix = token.slice(m.length);
      if (LOWERCASE_QUERY_OPERATORS.some((op) => suffix.startsWith(op))) return m;
    }
  }
  return undefined;
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
 * and deny (`actor_policy_denied`) if either is masked (dot-aware via isFieldMasked). This errs toward
 * over-rejection, the correct direction for a confidentiality control. L-3: the lowercase-operator
 * form (`salarylike5`), which the lowercase-only leadingFieldToken would otherwise swallow whole, is
 * now caught via maskedFieldWithLowercaseOperator (masked-prefix + known lowercase operator), so a
 * legit unmasked field with an operator-looking name still passes. Residual: an operator outside that
 * list, or SN case-folding of FIELD names themselves — gated on the P8 case-sensitivity confirmation.
 */
export function assertQueryFieldsAllowed(policy: ActorPolicy, table: string, userQuery: string): void {
  const masked = maskIndex(policy, table);
  if (!masked || masked.fields.size === 0 || !userQuery) return;
  for (const clause of userQuery.split("^")) {
    const candidates = [leadingFieldToken(clause), leadingFieldToken(clause.replace(QUERY_OP_PREFIX, ""))];
    for (const f of candidates) {
      if (!f) continue;
      if (isFieldMaskedByIndex(masked, f)) {
        throw new McpToolError("actor_policy_denied", `Query references a field not permitted for this actor on "${table}": ${f}.`);
      }
      const gluedMask = maskedFieldWithLowercaseOperator(masked, f);
      if (gluedMask) {
        throw new McpToolError("actor_policy_denied", `Query references a field not permitted for this actor on "${table}": ${gluedMask}.`);
      }
    }
  }
}
