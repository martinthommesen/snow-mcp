// User-aware schema cache (plan §2.6, S6). Discoverability ONLY — record operations
// still rely on ServiceNow ACL enforcement. The key includes the user sys_id + a role
// hash, because ACL-filtered field visibility is per user: caching by role alone could
// leak a field that user A can see but user B (same role, failing a field/scripted ACL)
// cannot. ~24h TTL; explicit invalidation supported.

import type { FieldInfo, TableInfo } from "../sn/discovery.js";

export const SCHEMA_VERSION = "v1";
export const DEFAULT_SCHEMA_TTL_SEC = 24 * 60 * 60;

export interface SchemaCacheIdentity {
  instanceHost: string;
  userId: string;
  /** Hash of the user's roles (so a role change busts the cache). */
  roleHash: string;
  domainId?: string;
  scope?: string;
}

export class SchemaCache {
  constructor(
    private readonly kv: KVNamespace,
    private readonly id: SchemaCacheIdentity,
    private readonly ttlSec: number = DEFAULT_SCHEMA_TTL_SEC,
  ) {}

  private key(kind: "table" | "list", suffix: string): string {
    const { instanceHost, userId, roleHash, domainId, scope } = this.id;
    return `schema:${SCHEMA_VERSION}:${instanceHost}:${userId}:${roleHash}:${domainId ?? ""}:${scope ?? ""}:${kind}:${suffix}`;
  }

  /** Cache-through for a table's field schema (user-aware). */
  async describeTable(table: string, fetcher: () => Promise<FieldInfo[]>): Promise<{ fields: FieldInfo[]; cached: boolean }> {
    const k = this.key("table", table);
    const hit = await this.kv.get<FieldInfo[]>(k, "json");
    if (hit) return { fields: hit, cached: true };
    const fields = await fetcher();
    await this.kv.put(k, JSON.stringify(fields), { expirationTtl: this.ttlSec });
    return { fields, cached: false };
  }

  /** Cache-through for a table listing (user-aware; keyed by filter). */
  async listTables(filter: string | undefined, fetcher: () => Promise<TableInfo[]>): Promise<{ tables: TableInfo[]; cached: boolean }> {
    const k = this.key("list", filter ?? "*");
    const hit = await this.kv.get<TableInfo[]>(k, "json");
    if (hit) return { tables: hit, cached: true };
    const tables = await fetcher();
    await this.kv.put(k, JSON.stringify(tables), { expirationTtl: this.ttlSec });
    return { tables, cached: false };
  }

  async invalidateTable(table: string): Promise<void> {
    await this.kv.delete(this.key("table", table));
  }
}

/** Stable role hash for the cache key (order-independent). */
export async function roleHash(roles: string[]): Promise<string> {
  const canonical = [...roles].sort().join(",");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  const bytes = new Uint8Array(digest).subarray(0, 8);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}
