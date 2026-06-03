// Discovery tools: describe_table + list_tables (plan §3.2, §2.6). Read-only Table API
// reads against sys_dictionary / sys_db_object, gated by ActorPolicy + capability +
// per-run budget like every other read. Schema is discoverability-only — record ops
// still rely on ServiceNow ACL enforcement (§2.6). User-aware KV caching is layered on
// top via SchemaCache (optional); these functions do the fetch + shaping.

import type { SnHttpClient } from "./http.js";
import { McpToolError, throwMappedServiceNowError } from "./errors.js";
import { requireCapability, TABLE_PAGE_CAP } from "../config.js";
import { assertActorPolicy, isFieldMasked, isTableAllowed, type ActorPolicy } from "../authz/actor-policy.js";
import { validateTableName } from "./validate.js";
import { utf8Len } from "../sandbox/serialize.js";
import type { RunBudget } from "./run-budget.js";
import type { Mode } from "@servicenow-codemode/shared";

export interface FieldInfo {
  name: string;
  label: string;
  type: string;
  mandatory: boolean;
  maxLength?: number;
  referenceTable?: string;
}
export interface TableInfo {
  name: string;
  label: string;
}

export interface DiscoveryDeps {
  http: SnHttpClient;
  instanceHost: string;
  effectiveMode: Mode;
  actorPolicy: ActorPolicy;
  runBudget: RunBudget;
  credentialMode?: "integration_user" | "per_user_oauth";
}

export interface ListTablesResult {
  tables: TableInfo[];
  partial: boolean;
  total?: number;
}

// Mirror of the validate.ts table-name grammar; used to gate hierarchy parents so a
// malformed super_class.name never reaches the `nameIN` join.
const TABLE_NAME_RE = /^[a-z0-9_]{1,80}$/;

function esc(v: string): string {
  // Encoded-query value sanitation: strip ^ and = which would break the query grammar.
  return v.replace(/[\^=]/g, "");
}

/** Resolve a table's inheritance chain (incident -> task -> ...) so describe_table
 *  includes inherited fields. Bounded loop; each hop is one ServiceNow request. The
 *  root is a validated table name; each super_class name is re-validated before it
 *  enters the chain so the `nameIN` join cannot be comma-injected. */
async function tableHierarchy(deps: DiscoveryDeps, table: string): Promise<{ chain: string[]; rootExists: boolean }> {
  const chain: string[] = [];
  let current: string | undefined = table;
  let rootExists = false;
  for (let i = 0; i < 10 && current; i++) {
    if (chain.includes(current)) break;
    chain.push(current);
    deps.runBudget.countServiceNowRequest();
    const res = await deps.http.request({
      method: "GET",
      path: "/api/now/table/sys_db_object",
      query: {
        sysparm_query: `name=${esc(current)}`,
        sysparm_fields: "super_class.name",
        sysparm_exclude_reference_link: "true",
        sysparm_limit: "1",
      },
    });
    throwMappedServiceNowError(res);
    const row = (res.json as { result?: Record<string, unknown>[] }).result?.[0];
    if (i === 0) rootExists = Boolean(row);
    const superName = row ? String(row["super_class.name"] ?? "") : "";
    // Only continue if the parent name is itself a valid table identifier (defense in
    // depth: a malformed super_class.name never reaches the nameIN join).
    current = superName && TABLE_NAME_RE.test(superName) ? superName : undefined;
  }
  return { chain, rootExists };
}

/** Field schema for one table (sys_dictionary), INCLUDING inherited fields. Enforces ActorPolicy. */
export async function describeTable(deps: DiscoveryDeps, table: string): Promise<FieldInfo[]> {
  const validTable = validateTableName(table); // rejects "incident,sys_user" comma-injection (P1)
  assertActorPolicy(deps.actorPolicy, { instance: deps.instanceHost, table: validTable, mode: deps.effectiveMode });
  requireCapability(deps.effectiveMode, "readTables");
  deps.runBudget.countRpcCall();

  const { chain, rootExists } = await tableHierarchy(deps, validTable);
  if (!rootExists) {
    throw new McpToolError("table_not_found", `Table "${validTable}" was not found.`, { table: validTable });
  }
  const nameIn = chain.map(esc).join(",");

  deps.runBudget.countServiceNowRequest();
  const res = await deps.http.request({
    method: "GET",
    path: "/api/now/table/sys_dictionary",
    query: {
      sysparm_query: `nameIN${nameIn}^elementISNOTEMPTY`,
      sysparm_fields: "element,column_label,internal_type,mandatory,max_length,reference,reference.name",
      sysparm_exclude_reference_link: "true",
      sysparm_limit: String(TABLE_PAGE_CAP),
    },
  });
  throwMappedServiceNowError(res);

  const rows = ((res.json as { result?: Record<string, unknown>[] }).result ?? []);
  deps.runBudget.countRows(rows.length);
  const byName = new Map<string, FieldInfo>();
  for (const r of rows) {
    const name = String(r.element ?? "");
    if (!name || isFieldMasked(deps.actorPolicy, validTable, name) || byName.has(name)) continue; // dedupe across hierarchy; hide masked
    const internalType = r.internal_type;
    const type = typeof internalType === "object" && internalType
      ? String((internalType as { value?: unknown }).value ?? "")
      : String(internalType ?? "");
    const out: FieldInfo = { name, label: String(r.column_label ?? ""), type, mandatory: String(r.mandatory ?? "false") === "true" };
    const ml = Number(r.max_length);
    if (Number.isFinite(ml) && ml > 0) out.maxLength = ml;
    if (type === "reference") {
      const ref = String(r["reference.name"] ?? r.reference ?? "");
      if (ref) out.referenceTable = ref;
    }
    byName.set(name, out);
  }
  const fields = [...byName.values()];
  // L-5: meter the returned bytes against the per-run/daily byte ceiling, matching rpc.ts reads
  // (discovery previously counted rows but not bytes, leaving a byte-budget accounting gap).
  deps.runBudget.countBytes(utf8Len(JSON.stringify(fields)));
  return fields;
}

/** List tables (sys_db_object), optionally filtered. Drops tables denied by ActorPolicy. */
export async function listTables(deps: DiscoveryDeps, filter?: string): Promise<ListTablesResult> {
  requireCapability(deps.effectiveMode, "readTables");
  deps.runBudget.countRpcCall();
  deps.runBudget.countServiceNowRequest();

  const query = filter
    ? `nameLIKE${esc(filter)}^ORlabelLIKE${esc(filter)}`
    : "ORDERBYname";
  const res = await deps.http.request({
    method: "GET",
    path: "/api/now/table/sys_db_object",
    query: {
      sysparm_query: query,
      sysparm_fields: "name,label",
      sysparm_exclude_reference_link: "true",
      sysparm_limit: String(TABLE_PAGE_CAP),
    },
  });
  throwMappedServiceNowError(res);

  const rows = ((res.json as { result?: Record<string, unknown>[] }).result ?? []);
  deps.runBudget.countRows(rows.length);
  const tables = rows
    .map((r) => ({ name: String(r.name ?? ""), label: String(r.label ?? "") }))
    .filter((t) => t.name && isTableAllowed(deps.actorPolicy, t.name));
  // L-5: meter returned bytes (see describeTable note).
  deps.runBudget.countBytes(utf8Len(JSON.stringify(tables)));
  const tablePolicyFilters = (deps.actorPolicy.tables.allow?.length ?? 0) > 0 || (deps.actorPolicy.tables.deny?.length ?? 0) > 0;
  const totalHeader = res.headers?.["x-total-count"];
  const total = !tablePolicyFilters && totalHeader !== undefined && /^\d+$/.test(totalHeader) ? Number(totalHeader) : undefined;
  const partial = total !== undefined ? rows.length < total : rows.length >= TABLE_PAGE_CAP;
  return {
    tables,
    partial,
    ...(total !== undefined ? { total } : {}),
  };
}
