// Host-side audit for mutating operations (plan §7.2, T4). Records WHO (mcp actor +
// snow effective user), WHAT (table, sys_id, op), and content HASHES (before/after) —
// never the raw values. Pure host logic; the sink (DO/KV/log) is injected.

import { redactValue } from "./redact.js";

export type MutationOp = "create" | "update" | "delete" | "importSet" | "runServerScript" | "attachmentWrite";

export interface AuditActor {
  mcpActorUserId: string;
  mcpActorEmail?: string;
  snowEffectiveUser?: string;
}

export interface AuditRecord {
  ts: number;
  requestId: string;
  instance: string;
  actor: AuditActor;
  op: MutationOp;
  table?: string;
  sysId?: string;
  beforeHash?: string;
  afterHash?: string;
  status: "ok" | "error" | "denied";
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
  requestId: string;
  instance: string;
  actor: AuditActor;
  op: MutationOp;
  table?: string;
  sysId?: string;
  before?: unknown;
  after?: unknown;
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
  if (input.table !== undefined) rec.table = input.table;
  if (input.sysId !== undefined) rec.sysId = input.sysId;
  if (input.before !== undefined) rec.beforeHash = await hashValue(input.before);
  if (input.after !== undefined) rec.afterHash = await hashValue(input.after);
  if (input.errorClass !== undefined) rec.errorClass = input.errorClass;
  return rec;
}

export type AuditSink = (record: AuditRecord) => void | Promise<void>;

/** Emit an audit record through the sink, redacting any stray sensitive strings. */
export async function emitAudit(sink: AuditSink, record: AuditRecord): Promise<void> {
  await sink(redactValue(record) as AuditRecord);
}
