import { DurableObject } from "cloudflare:workers";

// AuthCorrelationDO (plan §2.10) — short-lived PKCE verifier / state / nonce for the
// upstream ServiceNow OAuth correlation. Keyed by oauth_state.
//
// SKELETON: minimal keyed storage to prove partitioning (Phase 0.12). The full
// short-TTL correlation logic lands with the auth flow (Phase 1.2).
export class AuthCorrelationDO extends DurableObject {
  async putState(key: string, value: string): Promise<void> {
    await this.ctx.storage.put(`state:${key}`, value);
  }
  async getState(key: string): Promise<string | undefined> {
    return this.ctx.storage.get(`state:${key}`);
  }
}
