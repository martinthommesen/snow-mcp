// OAUTH_KV binding guard (plan §2.4, §2.11; gate B8).
//
// @cloudflare/workers-oauth-provider persists clients, grants, and its own tokens in
// a KV namespace bound as OAUTH_KV. It MUST exist — a missing binding fails closed
// (B8) rather than silently degrading. ServiceNow credentials live in TokenStoreDO
// (a Durable Object, §2.7), NEVER in OAUTH_KV — keeping the two stores separate is a
// threat-model requirement (§11 T1/T2). This module enforces presence and documents
// the isolation in one place.

export class MissingOAuthKvError extends Error {
  constructor() {
    super(
      "OAUTH_KV binding is not configured. The MCP OAuth provider requires a KV " +
        "namespace bound as OAUTH_KV (separate from ServiceNow TokenStoreDO). " +
        "Declare it in wrangler.jsonc / alchemy.run.ts. (gate B8)",
    );
    this.name = "MissingOAuthKvError";
  }
}

/** Return the OAUTH_KV namespace or throw MissingOAuthKvError (fail closed). */
export function requireOAuthKv(env: { OAUTH_KV?: KVNamespace }): KVNamespace {
  const kv = env.OAUTH_KV;
  if (kv === undefined || kv === null) {
    throw new MissingOAuthKvError();
  }
  return kv;
}

/**
 * Structural isolation invariant (B8): the OAuth provider store and the ServiceNow
 * token store are DISTINCT bindings of DISTINCT types. ServiceNow tokens must never
 * be written to OAUTH_KV. Asserted at the type/name level here; enforced in code by
 * routing ServiceNow tokens only through TokenStoreDO (Phase 1.3).
 */
export const OAUTH_KV_BINDING = "OAUTH_KV" as const;
export const SERVICENOW_TOKEN_BINDING = "TOKEN_DO" as const; // Durable Object, not KV
