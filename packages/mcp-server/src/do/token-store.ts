import { DurableObject } from "cloudflare:workers";

// TokenStoreDO (plan §2.7, §2.10) — ServiceNow tokens, isolated per (userId, instanceHost).
// Addressed by `idFromName("<userId>|<instanceHost>")`, so partitioning is inherent in the
// stub address.
//
// This DO stores OPAQUE values only. The AES-GCM versioned envelope + AAD + KEK rotation that
// makes those values real tokens lives in the TokenStore ADAPTER (auth/token-store.ts), which
// seals before putToken() and opens after getToken(): the plaintext token never reaches DO
// storage. This object therefore needs no crypto of its own — it provides per-(user,instance)
// isolation + revoke, and the adapter provides confidentiality + tamper-evidence.
export class TokenStoreDO extends DurableObject {
  /** Store an opaque (already-sealed) token record under a token_type slot. */
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
