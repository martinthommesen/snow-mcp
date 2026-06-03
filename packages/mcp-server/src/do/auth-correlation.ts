import { DurableObject } from "cloudflare:workers";
import type { TokenEnvelope } from "../auth/crypto.js";

// AuthCorrelationDO (plan §2.10, §6b) — short-lived PKCE-verifier / nonce correlation for
// the upstream ServiceNow Authorization-Code flow. The OAuth `state` is the opaque DO record
// key (a high-entropy random value); the record is the SOLE authority at /servicenow/callback
// (which has no ctx.props). A record is created at /servicenow/authorize and CONSUMED-ONCE at
// /servicenow/callback: the consume is an atomic read-then-delete inside the DO input gate, so
// a replayed (second) callback for the same state sees the deletion and gets null (fail closed).
//
// The record carries the identity the callback must trust (userId, actorEmail when present,
// instanceHost) — these come from the host-HMAC ticket verified at /authorize, NEVER from a
// callback request param.

export interface AuthCorrelationRecord {
  /** MCP user the upstream token will be stored under (from the verified host-HMAC ticket). */
  userId: string;
  /** Normalized MCP actor email from the verified host-HMAC ticket, when the IdP provided one. */
  actorEmail?: string;
  /** Previously-bound ServiceNow sys_id, when one exists, for continuity on reauth. */
  expectedSnSysId?: string;
  /** Canonical instance host the token is for; the callback re-checks this matches config. */
  instanceHost: string;
  /** PKCE code_verifier; exchanged with the code at oauth_token.do (S256). */
  pkceVerifier: string;
  // I-2: the former `nonce` field was write-only — never read at the callback, so it provided no
  // CSRF protection. CSRF/replay defense is the opaque, single-use `state` (atomic
  // read-then-delete in this DO). Removed to avoid implying a second correlation check exists.
  /** epoch ms after which the record is expired (TTL check at the callback). */
  expiresAt: number;
}

export interface OidcAuthRequestInfo {
  responseType: string;
  clientId: string;
  redirectUri: string;
  scope: string[];
  state: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  resource?: string | string[];
}

export interface OidcCorrelationRecord {
  /** Original MCP OAuth authorization request parsed by workers-oauth-provider. */
  authRequest: OidcAuthRequestInfo;
  /** Requested ∩ supported MCP scopes granted after OIDC login. */
  grantedScopes: string[];
  /** OIDC nonce expected inside the signed ID token. */
  nonce: string;
  /** RP PKCE verifier for the IdP code exchange. */
  pkceVerifier: string;
  expiresAt: number;
}

export interface OidcConsentRecord {
  /** Original MCP OAuth authorization request parsed by workers-oauth-provider. */
  authRequest: OidcAuthRequestInfo;
  /** Requested ∩ supported MCP scopes granted after OIDC login. */
  grantedScopes: string[];
  /** OIDC-derived grant props to pass to completeAuthorization after local consent. */
  grantProps: Record<string, unknown>;
  /** Encrypted IdP refresh token, when present; never store it inside plaintext grantProps. */
  sealedOidcRefreshToken?: TokenEnvelope;
  /** Stable provider userId derived from the OIDC subject. */
  userId: string;
  /** Display-only MCP client name captured before rendering consent. */
  clientName?: string;
  expiresAt: number;
}

const CORRELATION_KEY = "corr";
const OIDC_CORRELATION_KEY = "oidc_corr";
const OIDC_CONSENT_KEY = "oidc_consent";
const TICKET_NONCE_KEY = "ticket_nonce";

interface StoredAuthCorrelationRecord extends AuthCorrelationRecord {
  state: string;
}

interface StoredOidcCorrelationRecord extends OidcCorrelationRecord {
  state: string;
}

interface StoredOidcConsentRecord extends OidcConsentRecord {
  nonce: string;
}

interface StoredTicketNonce {
  nonce: string;
  expiresAt: number;
}

export class AuthCorrelationDO extends DurableObject {
  /** Create the single-use correlation record keyed by the opaque OAuth `state`. */
  async createRecord(state: string, record: AuthCorrelationRecord): Promise<void> {
    await this.cleanupExpired(Date.now());
    await this.ctx.storage.put(CORRELATION_KEY, { ...record, state } satisfies StoredAuthCorrelationRecord);
    await this.ctx.storage.setAlarm(record.expiresAt);
  }

  /**
   * ATOMIC single-use consume: read the record, DELETE it, and return it — all inside the DO
   * input gate, which serializes calls to this object. A second (replayed) consume for the
   * same `state` therefore sees the deletion and returns null. TTL is NOT enforced here (the
   * record is still consumed/deleted on a late callback); the caller checks `expiresAt`.
   */
  async consumeRecord(state: string): Promise<AuthCorrelationRecord | null> {
    const record = await this.ctx.storage.get<StoredAuthCorrelationRecord>(CORRELATION_KEY);
    if (!record || record.state !== state) return null;
    await this.ctx.storage.delete(CORRELATION_KEY);
    await this.ctx.storage.deleteAlarm();
    return {
      userId: record.userId,
      ...(record.actorEmail ? { actorEmail: record.actorEmail } : {}),
      ...(record.expectedSnSysId ? { expectedSnSysId: record.expectedSnSysId } : {}),
      instanceHost: record.instanceHost,
      pkceVerifier: record.pkceVerifier,
      expiresAt: record.expiresAt,
    };
  }

  async createOidcRecord(state: string, record: OidcCorrelationRecord): Promise<void> {
    await this.cleanupExpired(Date.now());
    await this.ctx.storage.put(OIDC_CORRELATION_KEY, { ...record, state } satisfies StoredOidcCorrelationRecord);
    await this.ctx.storage.setAlarm(record.expiresAt);
  }

  async consumeOidcRecord(state: string): Promise<OidcCorrelationRecord | null> {
    const record = await this.ctx.storage.get<StoredOidcCorrelationRecord>(OIDC_CORRELATION_KEY);
    if (!record || record.state !== state) return null;
    await this.ctx.storage.delete(OIDC_CORRELATION_KEY);
    await this.ctx.storage.deleteAlarm();
    return {
      authRequest: record.authRequest,
      grantedScopes: record.grantedScopes,
      nonce: record.nonce,
      pkceVerifier: record.pkceVerifier,
      expiresAt: record.expiresAt,
    };
  }

  async createOidcConsentRecord(nonce: string, record: OidcConsentRecord): Promise<void> {
    await this.cleanupExpired(Date.now());
    await this.ctx.storage.put(OIDC_CONSENT_KEY, { ...record, nonce } satisfies StoredOidcConsentRecord);
    await this.ctx.storage.setAlarm(record.expiresAt);
  }

  async consumeOidcConsentRecord(nonce: string): Promise<OidcConsentRecord | null> {
    const record = await this.ctx.storage.get<StoredOidcConsentRecord>(OIDC_CONSENT_KEY);
    if (!record || record.nonce !== nonce) return null;
    await this.ctx.storage.delete(OIDC_CONSENT_KEY);
    await this.ctx.storage.deleteAlarm();
    return {
      authRequest: record.authRequest,
      grantedScopes: record.grantedScopes,
      grantProps: record.grantProps,
      ...(record.sealedOidcRefreshToken ? { sealedOidcRefreshToken: record.sealedOidcRefreshToken } : {}),
      userId: record.userId,
      ...(record.clientName ? { clientName: record.clientName } : {}),
      expiresAt: record.expiresAt,
    };
  }

  /**
   * ATOMIC one-shot ticket nonce claim for /servicenow/authorize. The ticket is signed and
   * short-lived, but a leaked authorize URL must not mint multiple OAuth states before expiry.
   */
  async consumeTicketNonce(nonce: string, expiresAt: number, now: number = Date.now()): Promise<boolean> {
    await this.cleanupExpired(now);
    const existing = await this.ctx.storage.get<StoredTicketNonce>(TICKET_NONCE_KEY);
    if (existing) return false;
    await this.ctx.storage.put(TICKET_NONCE_KEY, { nonce, expiresAt } satisfies StoredTicketNonce);
    await this.ctx.storage.setAlarm(expiresAt);
    return true;
  }

  /** Storage-alarm entry point: purge abandoned, expired OAuth states. */
  override async alarm(): Promise<void> {
    await this.cleanupExpired(Date.now());
  }

  /** Deterministic cleanup seam for tests plus the alarm implementation. */
  async cleanupExpired(now: number = Date.now()): Promise<void> {
    const [record, oidcRecord, oidcConsent, ticketNonce] = await Promise.all([
      this.ctx.storage.get<StoredAuthCorrelationRecord>(CORRELATION_KEY),
      this.ctx.storage.get<StoredOidcCorrelationRecord>(OIDC_CORRELATION_KEY),
      this.ctx.storage.get<StoredOidcConsentRecord>(OIDC_CONSENT_KEY),
      this.ctx.storage.get<StoredTicketNonce>(TICKET_NONCE_KEY),
    ]);
    let nextExpiresAt: number | undefined;
    if (record) {
      if (record.expiresAt <= now) {
        await this.ctx.storage.delete(CORRELATION_KEY);
      } else {
        nextExpiresAt = record.expiresAt;
      }
    }
    if (ticketNonce) {
      if (ticketNonce.expiresAt <= now) {
        await this.ctx.storage.delete(TICKET_NONCE_KEY);
      } else {
        nextExpiresAt = Math.min(nextExpiresAt ?? ticketNonce.expiresAt, ticketNonce.expiresAt);
      }
    }
    if (oidcRecord) {
      if (oidcRecord.expiresAt <= now) {
        await this.ctx.storage.delete(OIDC_CORRELATION_KEY);
      } else {
        nextExpiresAt = Math.min(nextExpiresAt ?? oidcRecord.expiresAt, oidcRecord.expiresAt);
      }
    }
    if (oidcConsent) {
      if (oidcConsent.expiresAt <= now) {
        await this.ctx.storage.delete(OIDC_CONSENT_KEY);
      } else {
        nextExpiresAt = Math.min(nextExpiresAt ?? oidcConsent.expiresAt, oidcConsent.expiresAt);
      }
    }
    if (nextExpiresAt === undefined) {
      await this.ctx.storage.deleteAlarm();
    } else {
      await this.ctx.storage.setAlarm(nextExpiresAt);
    }
  }
}
