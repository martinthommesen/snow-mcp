import { DurableObject } from "cloudflare:workers";

// AuthCorrelationDO (plan §2.10, §6b) — short-lived PKCE-verifier / nonce correlation for
// the upstream ServiceNow Authorization-Code flow. The OAuth `state` is the opaque DO record
// key (a high-entropy random value); the record is the SOLE authority at /servicenow/callback
// (which has no ctx.props). A record is created at /servicenow/authorize and CONSUMED-ONCE at
// /servicenow/callback: the consume is an atomic read-then-delete inside the DO input gate, so
// a replayed (second) callback for the same state sees the deletion and gets null (fail closed).
//
// The record carries the identity the callback must trust (userId, instanceHost) — these come
// from the host-HMAC ticket verified at /authorize, NEVER from a callback request param.

export interface AuthCorrelationRecord {
  /** MCP user the upstream token will be stored under (from the verified host-HMAC ticket). */
  userId: string;
  /** Canonical instance host the token is for; the callback re-checks this matches config. */
  instanceHost: string;
  /** PKCE code_verifier; exchanged with the code at oauth_token.do (S256). */
  pkceVerifier: string;
  // I-2: the former `nonce` field was write-only — never read at the callback, so it provided no
  // CSRF protection. CSRF/replay defense is the opaque, single-use `state` (atomic
  // read-then-delete in this DO). Removed to avoid implying a second correlation check exists.
  /** Optional post-auth return target (unused by the worker today; reserved for the UI). */
  returnTarget?: string;
  /** epoch ms after which the record is expired (TTL check at the callback). */
  expiresAt: number;
}

export class AuthCorrelationDO extends DurableObject {
  /** Create the single-use correlation record keyed by the opaque OAuth `state`. */
  async createRecord(state: string, record: AuthCorrelationRecord): Promise<void> {
    await this.ctx.storage.put(`corr:${state}`, record);
  }

  /**
   * ATOMIC single-use consume: read the record, DELETE it, and return it — all inside the DO
   * input gate, which serializes calls to this object. A second (replayed) consume for the
   * same `state` therefore sees the deletion and returns null. TTL is NOT enforced here (the
   * record is still consumed/deleted on a late callback); the caller checks `expiresAt`.
   */
  async consumeRecord(state: string): Promise<AuthCorrelationRecord | null> {
    const record = await this.ctx.storage.get<AuthCorrelationRecord>(`corr:${state}`);
    if (!record) return null;
    await this.ctx.storage.delete(`corr:${state}`);
    return record;
  }
}
