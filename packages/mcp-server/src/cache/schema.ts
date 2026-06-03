// User-aware schema cache (plan §2.6, S6). Discoverability ONLY — record operations
// still rely on ServiceNow ACL enforcement. The key includes the ServiceNow principal sys_id
// + a role hash, because ACL-filtered field visibility is per user: caching by role alone
// could leak a field that user A can see but user B (same role, failing a field/scripted ACL)
// cannot. ~24h TTL.

import type { FieldInfo, TableInfo } from "../sn/discovery.js";

export const SCHEMA_VERSION = "v1";
export const DEFAULT_SCHEMA_TTL_SEC = 24 * 60 * 60;

const inFlightMisses = new Map<string, Promise<unknown>>();

export interface SchemaCachePrincipalIdentity {
  /** ServiceNow sys_id in per_user_oauth; authenticated MCP actor in integration_user. */
  principalId: string;
  /** Hash of the user's roles (so a role change busts the cache). */
  roleHash: string;
  /** Hash of the host ActorPolicy that shaped the cached schema. */
  policyHash?: string;
  domainId?: string;
  scope?: string;
}

export interface SchemaCacheIdentity extends SchemaCachePrincipalIdentity {
  instanceHost: string;
}

export class SchemaCache {
  constructor(
    private readonly kv: KVNamespace,
    private readonly id: SchemaCacheIdentity,
    private readonly ttlSec: number = DEFAULT_SCHEMA_TTL_SEC,
  ) {}

  private key(kind: "table" | "list", suffix: string): string {
    const { instanceHost, principalId, roleHash, policyHash, domainId, scope } = this.id;
    return `schema:${SCHEMA_VERSION}:${instanceHost}:${principalId}:${roleHash}:${policyHash ?? ""}:${domainId ?? ""}:${scope ?? ""}:${kind}:${suffix}`;
  }

  private async fillMiss<T>(key: string, fetcher: () => Promise<T>, write: (value: T) => Promise<void>): Promise<T> {
    const existing = inFlightMisses.get(key) as Promise<T> | undefined;
    if (existing) return existing;
    const pending = (async () => {
      const value = await fetcher();
      await write(value);
      return value;
    })();
    inFlightMisses.set(key, pending);
    try {
      return await pending;
    } finally {
      if (inFlightMisses.get(key) === pending) inFlightMisses.delete(key);
    }
  }

  /** Cache-through for a table's field schema (user-aware). */
  async describeTable(table: string, fetcher: () => Promise<FieldInfo[]>): Promise<{ fields: FieldInfo[]; cached: boolean }> {
    const k = this.key("table", table);
    const hit = await this.kv.get<FieldInfo[]>(k, "json");
    if (hit) return { fields: hit, cached: true };
    const fields = await this.fillMiss(k, fetcher, (value) => this.kv.put(k, JSON.stringify(value), { expirationTtl: this.ttlSec }));
    return { fields, cached: false };
  }

  /** Cache-through for a table listing (user-aware; keyed by filter). */
  async listTables(filter: string | undefined, fetcher: () => Promise<TableInfo[]>): Promise<{ tables: TableInfo[]; cached: boolean }> {
    // Collision-proof key: a literal `"*"` filter must NOT alias the no-filter case. Encode
    // PRESENCE structurally — absent is the single char `"0"`, present always starts `"1:"` —
    // so no real filter value can ever collide with the no-filter marker (the old `filter ?? "*"`
    // let `listTables("*")` and `listTables(undefined)` share a key).
    const k = this.key("list", filter === undefined ? "0" : `1:${filter}`);
    const hit = await this.kv.get<TableInfo[]>(k, "json");
    if (hit) return { tables: hit, cached: true };
    const tables = await this.fillMiss(k, fetcher, (value) => this.kv.put(k, JSON.stringify(value), { expirationTtl: this.ttlSec }));
    return { tables, cached: false };
  }
}

/** Stable role hash for the cache key (order-independent). */
export async function roleHash(roles: string[]): Promise<string> {
  const canonical = [...roles].sort().join(",");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  const bytes = new Uint8Array(digest).subarray(0, 8);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}
