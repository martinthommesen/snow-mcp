// Per-(user, instance) ServiceNow token store (plan §2.7, §1.3, §7.5). Ties TokenStoreDO
// (isolation) to the AES-GCM AAD-bound envelope (confidentiality + tamper-evidence).
// Tokens are encrypted before they touch DO storage; a refresh rotates them; revoke
// clears them; AAD mismatch fails closed. Host logic — unit-verified against a real DO.

import { seal, open, tokenAad, type KekRing } from "./crypto.js";

export interface SnTokens {
  access_token: string;
  refresh_token?: string;
  /** epoch ms when the access token expires. */
  expires_at?: number;
  /** ServiceNow principal resolved after the code exchange/refresh (§6b). The per-user sys_id
   *  feeds the signed actor's `snow_effective_user_sys_id`; roles seed 6b-2's roleHash. They
   *  ride the same AAD-bound encrypted envelope as the tokens (tamper-evident, no extra store). */
  sys_id?: string;
  roles?: string[];
}

/** Minimal slice of TokenStoreDO this adapter needs (keeps it test-injectable). */
export interface TokenStoreBackend {
  putToken(tokenType: string, opaque: string): Promise<void>;
  getToken(tokenType: string): Promise<string | undefined>;
  revokeAll(): Promise<void>;
}

export class TokenStore {
  constructor(
    private readonly backend: TokenStoreBackend,
    private readonly ring: KekRing,
    private readonly userId: string,
    private readonly instanceHost: string,
  ) {}

  private aad(tokenType: string): string {
    return tokenAad(this.userId, this.instanceHost, tokenType);
  }

  /** Encrypt + store the token bundle under `tokenType` (e.g. "servicenow"). */
  async put(tokenType: string, tokens: SnTokens): Promise<void> {
    const envelope = await seal(JSON.stringify(tokens), this.aad(tokenType), this.ring);
    await this.backend.putToken(tokenType, JSON.stringify(envelope));
  }

  /** Decrypt + return the token bundle, or null if absent. Fails closed on tamper/AAD. */
  async get(tokenType: string): Promise<SnTokens | null> {
    const raw = await this.backend.getToken(tokenType);
    if (!raw) return null;
    const plaintext = await open(JSON.parse(raw), this.aad(tokenType), this.ring);
    return JSON.parse(plaintext) as SnTokens;
  }

  /** Replace tokens after a refresh (rotation). */
  async rotate(tokenType: string, tokens: SnTokens): Promise<void> {
    await this.put(tokenType, tokens);
  }

  /** Revoke ALL tokens for this (user, instance) — used on logout (§7.5). */
  async revoke(): Promise<void> {
    await this.backend.revokeAll();
  }
}
