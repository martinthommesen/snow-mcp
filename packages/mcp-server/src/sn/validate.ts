// Runtime input validation at the ServiceNowRPC boundary (plan P1; closes the
// "unvalidated identifier boundary" findings 7/8/9 + the discovery comma-injection
// sibling). transpileTs() strips types without type-checking and the sandbox hands the
// RPC `unknown` values, so `table`, `sys_id`, `limit`, `fields`, update keys,
// `idempotencyKey`, and `reason` are an untrusted trust boundary. These validators run
// at the TOP of each async RPC method body (so a rejection flows through `coded()` and
// the typed `path_denied` code survives the sandbox boundary, §3.5) and BEFORE the
// TypeScript `as` cast — which is a compile-time fiction with no runtime effect.
//
// Pure host logic, fully verifiable locally. P1 adds NO new ErrorCode; rejections reuse
// the existing `path_denied` member with a descriptive message + structured detail.

import { McpToolError } from "./errors.js";
import { TABLE_PAGE_CAP } from "../config.js";

// Identifier grammars (ServiceNow names are lowercase alnum + underscore).
const TABLE_NAME = /^[a-z0-9_]{1,80}$/;
const SYS_ID = /^[0-9a-f]{32}$/;
const FIELD_NAME = /^[a-z0-9_.]{1,80}$/; // dot-walk allowed for reads (e.g. caller_id.name)
const UPDATE_KEY = /^[a-z0-9_]{1,80}$/; // write targets: no dot-walk
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{1,128}$/;

const REASON_MAX = 1024;
// Encoded-query structural operators a snippet must not smuggle into a value when a
// restrictive mandatory row filter is AND-ed in (would let a caller OR/NQ past it).
// TOKEN-BOUNDARY (P6b): `^OR` is a PREFIX of the benign `^ORDERBY`/`^ORDERBYDESC` ordering
// clauses, so a naive `^OR` over-rejected ordering once a restrictive rowFilter became active.
// The `OR(?!DERBY)` negative lookahead matches the genuine `^OR` escape (which is followed by a
// field name, e.g. `^ORpriority=2`) but NOT `^ORDERBY`/`^ORDERBYDESC` (ORDERBYDESC begins with
// ORDERBY, so one lookahead covers both). `^NQ`/`^EQ` have no benign longer forms (confirmed
// against the ServiceNow encoded-query operator set: the only `^OR`-prefixed keywords are
// ORDERBY/ORDERBYDESC).
//
// CASE: matched case-INSENSITIVELY (`/i`), the REJECT-NOT-BYPASS direction. If ServiceNow parses
// these operators case-insensitively (P8-unconfirmed), a lowercase `^or`/`^nq`/`^eq` would be a
// real row-filter escape, so we REJECT it in ANY case rather than risk passing it through. The
// `(?!DERBY)` lookahead is likewise case-insensitive under `/i`, so `^ORDERBY`/`^ORDERBYDESC` stay
// ALLOWED in any case (`^orderby...`, `^ORDERBYDESC...`). This errs toward rejecting escapes.
// One residual ambiguity: a MIXED-CASE `^ORderby<field>=<value>` (real `^OR` escape whose field
// happens to start with the letters "derby") resolves to ALLOWED here, because the lookahead reads
// "derby" as ORDERBY under `/i`. The precise SN case-sensitivity that disambiguates this rare case
// is a P8 LIVE-CONFIRMATION GATE; until then we accept that one edge in exchange for rejecting all
// lowercase `^or`/`^nq`/`^eq` escapes.
const STRUCTURAL_OP = /\^(NQ|EQ|OR(?!DERBY))/i;

function isControlChar(code: number): boolean {
  return code <= 0x1f || code === 0x7f;
}

function deny(message: string, detail?: Record<string, unknown>): never {
  throw new McpToolError("path_denied", message, detail);
}

export function validateTableName(table: unknown): string {
  if (typeof table !== "string" || !TABLE_NAME.test(table)) {
    deny(`Invalid table name.`, { table: String(table) });
  }
  return table as string;
}

export function validateSysId(sysId: unknown): string {
  if (typeof sysId !== "string" || !SYS_ID.test(sysId)) {
    deny(`Invalid sys_id (expected 32 hex chars).`, { sys_id: String(sysId) });
  }
  return sysId as string;
}

/** Coerce to an integer in 1..TABLE_PAGE_CAP; reject NaN / negative / non-number. */
export function validateLimit(limit: unknown): number | undefined {
  if (limit === undefined) return undefined;
  if (typeof limit !== "number" || !Number.isFinite(limit) || !Number.isInteger(limit) || limit < 1) {
    deny(`Invalid limit (expected a positive integer).`, { limit: String(limit) });
  }
  return Math.min(limit as number, TABLE_PAGE_CAP);
}

export function validateFields(fields: unknown): string[] | undefined {
  if (fields === undefined) return undefined;
  if (!Array.isArray(fields)) deny(`Invalid fields (expected an array of field names).`);
  for (const f of fields) {
    if (typeof f !== "string" || !FIELD_NAME.test(f)) {
      deny(`Invalid field name.`, { field: String(f) });
    }
  }
  return fields as string[];
}

/** Validate an update body: keys are strict field names (no dot-walk) and present. */
export function validateUpdateFields(fields: unknown): Record<string, unknown> {
  if (typeof fields !== "object" || fields === null || Array.isArray(fields)) {
    deny(`Invalid update fields (expected an object).`);
  }
  const obj = fields as Record<string, unknown>;
  const keys = Object.keys(obj);
  if (keys.length === 0) deny(`Update fields must not be empty.`);
  for (const k of keys) {
    if (!UPDATE_KEY.test(k)) deny(`Invalid update field name.`, { field: k });
  }
  return obj;
}

export function validateIdempotencyKey(key: unknown): string {
  if (typeof key !== "string" || !IDEMPOTENCY_KEY.test(key)) {
    deny(`Invalid idempotencyKey.`);
  }
  return key as string;
}

export function validateReason(reason: unknown): string {
  if (typeof reason !== "string" || reason.length === 0 || reason.length > REASON_MAX) {
    deny(`Invalid reason (1..${REASON_MAX} chars required).`);
  }
  const s = reason as string;
  // Printable: reject ASCII control characters (0x00-0x1F, 0x7F).
  for (let i = 0; i < s.length; i++) {
    if (isControlChar(s.charCodeAt(i))) deny(`Reason contains control characters.`);
  }
  return s;
}

/**
 * Reject a caller-supplied encoded query that smuggles a structural operator
 * (`^NQ`/`^OR`/`^EQ`) when a restrictive mandatory `rowFilters[table]` is active — such
 * an operator would let the caller break out of the AND-ed mandatory filter. When no
 * mandatory filter applies (e.g. the permissive single-operator policy), the query is
 * left untouched.
 */
export function validateUserQuery(query: unknown, hasMandatoryFilter: boolean): string {
  if (query === undefined) return "";
  if (typeof query !== "string") deny(`Invalid query (expected a string).`);
  if (hasMandatoryFilter && STRUCTURAL_OP.test(query as string)) {
    deny(`Query may not contain a structural operator (^NQ/^OR/^EQ) under a restrictive row filter.`);
  }
  return query as string;
}

/**
 * Validate a configured mandatory row filter at load time: a filter that itself begins
 * with / contains a structural operator is self-defeating (it would not constrain rows).
 */
export function assertMandatoryRowFilterSafe(table: string, filter: string): void {
  if (STRUCTURAL_OP.test(filter)) {
    throw new Error(`Mandatory rowFilter for "${table}" must not contain a structural operator (^NQ/^OR/^EQ): ${filter}`);
  }
}
