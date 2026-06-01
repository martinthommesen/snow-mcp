// Host-side audit for mutating operations (plan §7.2, T4). Records WHO (mcp actor +
// snow effective user), WHAT (table, sys_id, op), and content HASHES (before/after) —
// never the raw values. Pure host logic; the sink (DO/KV/log) is injected.

import { redactValue } from "./redact.js";

export type MutationOp = "update" | "runServerScript";

export interface AuditActor {
  mcpActorUserId: string;
  mcpActorEmail?: string;
  snowEffectiveUser?: string;
}

export interface AuditRecord {
  ts: number;
  /** L-2: UTC date (YYYY-MM-DD) of the mutation's INTENT, stamped once and reused for the outcome
   *  row so intent + outcome share an AUDIT_KV key even across a UTC-midnight boundary (deriving it
   *  from each row's own `ts` at write time would orphan the intent row). Optional for back-compat;
   *  the sink falls back to the wall-clock date when absent. */
  dateKey?: string;
  requestId: string;
  /** Per-run mutation ordinal (plan §P4): identifies the audit-event key within a run, so
   *  the intent row and its result row share a key (result supersedes intent) while
   *  distinct mutations / denials never overwrite each other. */
  ordinal?: number;
  instance: string;
  actor: AuditActor;
  op: MutationOp;
  table?: string;
  sysId?: string;
  beforeHash?: string;
  afterHash?: string;
  /** The human-supplied justification (admin_script mandatory). Stored verbatim — it is
   *  attribution, never a secret or the script body (§P4). Redacted of stray secrets on emit. */
  reason?: string;
  /** "intent" is the audit-before-effect row (effect not yet attempted); it is superseded
   *  at the same ordinal key by "ok" (success) or "error" (effect threw). A durable trail
   *  left at "intent" reads as an UNRESOLVED intent — never a false success (plan §P4). */
  status: "intent" | "ok" | "error" | "denied";
  errorClass?: string;
}

const enc = new TextEncoder();

/** SHA-256(base64) of a JSON-serialized value (stable enough for change detection). */
export async function hashValue(value: unknown): Promise<string> {
  const json = JSON.stringify(value ?? null);
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(json));
  let s = "";
  for (const b of new Uint8Array(digest)) s += String.fromCharCode(b);
  return btoa(s);
}

export interface BuildAuditInput {
  ts: number;
  dateKey?: string;
  requestId: string;
  ordinal?: number;
  instance: string;
  actor: AuditActor;
  op: MutationOp;
  table?: string;
  sysId?: string;
  before?: unknown;
  after?: unknown;
  reason?: string;
  status: AuditRecord["status"];
  errorClass?: string;
}

/** Build an audit record, hashing before/after (no raw content stored). */
export async function buildAuditRecord(input: BuildAuditInput): Promise<AuditRecord> {
  const rec: AuditRecord = {
    ts: input.ts,
    requestId: input.requestId,
    instance: input.instance,
    actor: input.actor,
    op: input.op,
    status: input.status,
  };
  if (input.dateKey !== undefined) rec.dateKey = input.dateKey;
  if (input.ordinal !== undefined) rec.ordinal = input.ordinal;
  if (input.table !== undefined) rec.table = input.table;
  if (input.sysId !== undefined) rec.sysId = input.sysId;
  if (input.before !== undefined) rec.beforeHash = await hashValue(input.before);
  if (input.after !== undefined) rec.afterHash = await hashValue(input.after);
  if (input.reason !== undefined) rec.reason = input.reason;
  if (input.errorClass !== undefined) rec.errorClass = input.errorClass;
  return rec;
}

export type AuditSink = (record: AuditRecord) => void | Promise<void>;

/** Emit an audit record through the sink, redacting any stray sensitive strings. */
export async function emitAudit(sink: AuditSink, record: AuditRecord): Promise<void> {
  await sink(redactValue(record) as AuditRecord);
}
