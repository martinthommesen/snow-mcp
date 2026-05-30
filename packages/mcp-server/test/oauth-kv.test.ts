import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  requireOAuthKv,
  MissingOAuthKvError,
  OAUTH_KV_BINDING,
  SERVICENOW_TOKEN_BINDING,
} from "../src/auth/oauth-kv.js";

// ─── Phase 0.13d — OAUTH_KV presence + isolation (gate B8) ────────────────────

describe("Phase 0.13d — OAUTH_KV binding (B8)", () => {
  it("resolves the OAUTH_KV namespace when bound (present in wrangler.jsonc)", () => {
    const kv = requireOAuthKv(env as unknown as { OAUTH_KV?: KVNamespace });
    expect(kv).toBeDefined();
    expect(typeof kv.get).toBe("function");
  });

  it("fails closed (throws) when OAUTH_KV is absent", () => {
    expect(() => requireOAuthKv({})).toThrow(MissingOAuthKvError);
  });

  it("OAuth store and ServiceNow token store are distinct bindings (isolation)", () => {
    expect(OAUTH_KV_BINDING).not.toBe(SERVICENOW_TOKEN_BINDING);
  });
});
