import { DurableObject } from "cloudflare:workers";

// TokenStoreDO (plan §2.7, §2.10) — encrypted ServiceNow tokens, isolated per
// (userId, instanceHost). Addressed by `idFromName("<userId>|<instanceHost>")`, so
// partitioning is inherent in the stub address.
//
// SKELETON: stores opaque values to prove per-(user,instance) isolation (Phase 0.12).
// The AES-GCM versioned envelope + AAD + KEK rotation is Phase 1.3 — NOT built here.
// Until then this MUST NOT be used for real tokens (no encryption yet).
export class TokenStoreDO extends DurableObject {
  /** Store an opaque token record under a token_type slot. */
  async putToken(tokenType: string, opaque: string): Promise<void> {
    await this.ctx.storage.put(`tok:${tokenType}`, opaque);
  }
  async getToken(tokenType: string): Promise<string | undefined> {
    return this.ctx.storage.get(`tok:${tokenType}`);
  }
  /** Revoke all tokens held by THIS (user,instance) instance only. */
  async revokeAll(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}
