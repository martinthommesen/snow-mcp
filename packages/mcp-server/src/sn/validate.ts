// Runtime input validation at the ServiceNowRPC boundary (plan P1; closes the
// "unvalidated identifier boundary" findings 7/8/9 + the discovery comma-injection
// sibling). transpileTs() strips types without type-checking and the sandbox hands the
// RPC `unknown` values, so `table`, `sys_id`, `limit`, `fields`, and update keys are an
// untrusted trust boundary. Tool-level `idempotencyKey` and `reason` are validated before
// building the host-authoritative run context. RPC validators run at the TOP of each async
// method body (so a rejection flows through `coded()` and the typed `path_denied` code
// survives the sandbox boundary, §3.5) and BEFORE the TypeScript `as` cast — which is a
// compile-time fiction with no runtime effect.
//
// Pure host logic, fully verifiable locally. P1 adds NO new ErrorCode; rejections reuse
// the existing `path_denied` member with a descriptive message + structured detail.

import { McpToolError } from "./errors.js";
import { SN_REQUEST_LIMITS, TABLE_PAGE_CAP } from "../config.js";

// Identifier grammars (ServiceNow names are lowercase alnum + underscore).
const TABLE_NAME = /^[a-z0-9_]{1,80}$/;
const SYS_ID = /^[0-9a-f]{32}$/;
const FIELD_NAME = /^[a-z0-9_.]{1,80}$/; // dot-walk allowed for reads (e.g. caller_id.name)
const UPDATE_KEY = /^[a-z0-9_]{1,80}$/; // write targets: no dot-walk
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{1,128}$/;

const REASON_MAX = 1024;
// Encoded-query structural operators a snippet must not smuggle into a value when a
// restrictive mandatory row filter is AND-ed in (would let a caller OR/NQ past it).
// Exact uppercase ORDERBY/ORDERBYDESC are allowed ordering clauses; all OR/NQ/EQ case
// variants are denied. This deliberately rejects ambiguous mixed/lower-case ordering tokens
// such as ^ORderby... because they can also parse as a ^OR escape with a derby... field.
function hasStructuralOperator(query: string): boolean {
  for (let i = 0; i < query.length; i++) {
    const atStart = i === 0;
    const afterCaret = query.charCodeAt(i) === 94; // ^
    if (!atStart && !afterCaret) continue;
    const tokenStart = afterCaret ? i + 1 : i;
    if (query.startsWith("ORDERBYDESC", tokenStart) || query.startsWith("ORDERBY", tokenStart)) continue;
    const op = query.slice(tokenStart, tokenStart + 2).toUpperCase();
    if (op === "OR" || op === "NQ" || op === "EQ") return true;
  }
  return false;
}

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

export function validateFields(
  fields: unknown,
  opts: { maxFields?: number; label?: string } = {},
): string[] | undefined {
  if (fields === undefined) return undefined;
  const label = opts.label ?? "fields";
  const maxFields = opts.maxFields ?? SN_REQUEST_LIMITS.maxFields;
  if (!Array.isArray(fields)) deny(`Invalid ${label} (expected an array of field names).`);
  if (fields.length > maxFields) {
    deny(`${label} exceeds the maximum of ${maxFields} field names.`, { count: fields.length, maxFields });
  }
  for (const f of fields) {
    if (typeof f !== "string" || !FIELD_NAME.test(f)) {
      deny(`Invalid field name.`, { field: String(f) });
    }
  }
  return fields as string[];
}

export function validateGroupByFields(fields: unknown): string[] | undefined {
  return validateFields(fields, { maxFields: SN_REQUEST_LIMITS.maxGroupByFields, label: "groupBy" });
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

export function validateApprovalToken(token: unknown): string {
  if (typeof token !== "string" || token.length === 0 || token.length > SN_REQUEST_LIMITS.maxApprovalTokenChars) {
    deny(`Invalid approvalToken (1..${SN_REQUEST_LIMITS.maxApprovalTokenChars} chars required).`);
  }
  return token;
}

export function validateDiscoveryFilter(filter: unknown): string | undefined {
  if (filter === undefined) return undefined;
  if (typeof filter !== "string") deny(`Invalid filter (expected a string).`);
  if (filter.length > SN_REQUEST_LIMITS.maxDiscoveryFilterChars) {
    deny(`Discovery filter exceeds ${SN_REQUEST_LIMITS.maxDiscoveryFilterChars} characters.`, {
      length: filter.length,
      maxLength: SN_REQUEST_LIMITS.maxDiscoveryFilterChars,
    });
  }
  return filter;
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
  if (query.length > SN_REQUEST_LIMITS.maxEncodedQueryChars) {
    deny(`Encoded query exceeds ${SN_REQUEST_LIMITS.maxEncodedQueryChars} characters.`, {
      length: query.length,
      maxLength: SN_REQUEST_LIMITS.maxEncodedQueryChars,
    });
  }
  if (hasMandatoryFilter && hasStructuralOperator(query as string)) {
    deny(`Query may not contain a structural operator (^NQ/^OR/^EQ) under a restrictive row filter.`);
  }
  return query as string;
}

/**
 * Validate a configured mandatory row filter at load time: a filter that itself begins
 * with / contains a structural operator is self-defeating (it would not constrain rows).
 */
export function assertMandatoryRowFilterSafe(table: string, filter: string): void {
  if (hasStructuralOperator(filter)) {
    throw new Error(`Mandatory rowFilter for "${table}" must not contain a structural operator (^NQ/^OR/^EQ): ${filter}`);
  }
}
