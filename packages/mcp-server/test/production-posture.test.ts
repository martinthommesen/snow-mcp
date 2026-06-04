import { describe, expect, it, vi } from "vitest";
import type { Mode } from "@servicenow-codemode/shared";
import {
  ProductionPostureError,
  assertProductionPosture,
  assertProductionPostureOnce,
  collectPostureViolations,
  parseDeploymentProfile,
  type PostureEnv,
} from "../src/authz/production-posture-core.js";
import { bytesToBase64 } from "../src/auth/encoding.js";

const STRONG_SECRET = bytesToBase64(new Uint8Array(32).fill(7));

function binding(): never {
  return {} as never;
}

function productionEnv(overrides: Partial<PostureEnv> = {}): PostureEnv {
  return {
    DEPLOYMENT_PROFILE: "production",
    AUTH_MODE: "oidc",
    SERVICENOW_CREDENTIAL_MODE: "per_user_oauth",
    SNOW_OAUTH_CLIENT_ID: "sn-client",
    SNOW_OAUTH_CLIENT_SECRET: "sn-secret",
    WORKER_PUBLIC_ORIGIN: "https://worker.example.com",
    OIDC_ISSUER: "https://idp.example.com",
    OIDC_CLIENT_ID: "mcp-client",
    OIDC_CLIENT_SECRET: "client-secret",
    OIDC_GROUP_POLICY_MAP: "{\"admins\":\"write\"}",
    TOKEN_KEK_CURRENT: STRONG_SECRET,
    OAUTH_PROVIDER_SECRET: STRONG_SECRET,
    X_MCP_EXECUTOR_HMAC_KEY: STRONG_SECRET,
    TENANT_MAX_MODE: "write" as Mode,
    INSTANCE_MAX_MODE: "write" as Mode,
    ALLOWED_ORIGINS: "https://app.example.com",
    SNOW_INSTANCE_HOST: "prod123.service-now.com",
    SNOW_EXECUTOR_PATH: "/api/x_acme_mcp/x_mcp/executor/run",
    ACTOR_POLICY_TABLE_ALLOWLIST: "incident",
    ACTOR_POLICY_MAX_MODE: "write" as Mode,
    LOADER: binding(),
    AUDIT_KV: binding(),
    OAUTH_KV: binding(),
    AUTH_DO: binding(),
    TOKEN_DO: binding(),
    BUDGET_DO: binding(),
    LEDGER_DO: binding(),
    CONSENT_RATE_DO: binding(),
    ...overrides,
  };
}

describe("Phase 1B production posture", () => {
  it("parses only explicit deployment profiles", () => {
    expect(parseDeploymentProfile("pilot")).toBe("pilot");
    expect(parseDeploymentProfile("production")).toBe("production");
    expect(parseDeploymentProfile("")).toBeUndefined();
    expect(parseDeploymentProfile("prod")).toBeUndefined();
  });

  it("pilot preserves permissive behavior and emits one loud warning", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      assertProductionPostureOnce({ DEPLOYMENT_PROFILE: "pilot" });
      assertProductionPostureOnce({ DEPLOYMENT_PROFILE: "pilot" });
      expect(warn).toHaveBeenCalledTimes(1);
      expect(JSON.parse(String(warn.mock.calls[0]![0]))).toMatchObject({
        event: "production_posture_pilot",
        profile: "pilot",
      });
    } finally {
      warn.mockRestore();
    }
  });

  it("unset profile fails closed and still reports the production violations", () => {
    let err: unknown;
    try {
      assertProductionPosture({});
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ProductionPostureError);
    expect((err as ProductionPostureError).violations).toEqual(expect.arrayContaining([
      'DEPLOYMENT_PROFILE must be set to "pilot" or "production".',
      'SERVICENOW_CREDENTIAL_MODE must be "per_user_oauth" in production.',
    ]));
  });

  it("a fully configured production posture passes", () => {
    expect(() => assertProductionPosture(productionEnv())).not.toThrow();
    expect(collectPostureViolations(productionEnv())).toEqual([]);
  });

  it("requires a restrictive default ActorPolicy table allowlist in production", () => {
    expect(collectPostureViolations(productionEnv({
      ACTOR_POLICY_TABLE_ALLOWLIST: undefined,
      ACTOR_POLICIES_JSON: JSON.stringify({
        admin: { ACTOR_POLICY_TABLE_ALLOWLIST: "incident", ACTOR_POLICY_MAX_MODE: "write" },
      }),
    }))).toContain("ActorPolicy default table allowlist must be set in production.");
  });

  it("accepts an explicit restrictive JSON default ActorPolicy in production", () => {
    expect(collectPostureViolations(productionEnv({
      ACTOR_POLICY_TABLE_ALLOWLIST: undefined,
      ACTOR_POLICY_MAX_MODE: undefined,
      ACTOR_POLICIES_JSON: JSON.stringify({
        default: { ACTOR_POLICY_TABLE_ALLOWLIST: "incident", ACTOR_POLICY_MAX_MODE: "read_only" },
        admin: { ACTOR_POLICY_TABLE_ALLOWLIST: "incident,problem", ACTOR_POLICY_MAX_MODE: "write" },
      }),
    }))).toEqual([]);
  });

  it("rejects named JSON ActorPolicies that the runtime loader would reject", () => {
    expect(collectPostureViolations(productionEnv({
      ACTOR_POLICIES_JSON: JSON.stringify({
        admin: { ACTOR_POLICY_TABLE_ALLOWLIST: "Incident", ACTOR_POLICY_MAX_MODE: "write" },
      }),
    })).join("\n")).toMatch(/invalid table name/i);

    expect(collectPostureViolations(productionEnv({
      ACTOR_POLICIES_JSON: JSON.stringify({
        admin: { ACTOR_POLICY_TABLE_ALLOWLIST: "incident", ACTOR_POLICY_MAX_ROWS_PER_RUN: "0" },
      }),
    })).join("\n")).toMatch(/positive integer/i);

    expect(collectPostureViolations(productionEnv({
      ACTOR_POLICIES_JSON: JSON.stringify({
        admin: { ACTOR_POLICY_TABLE_ALLOWLIST: "incident", ACTOR_POLICY_ROW_FILTERS: "incident:active=true^ORpriority=1" },
      }),
    })).join("\n")).toMatch(/self-defeating structural operator/i);
  });

  it("allows exact ORDERBY row-filter clauses in production posture like the runtime loader", () => {
    expect(collectPostureViolations(productionEnv({
      ACTOR_POLICIES_JSON: JSON.stringify({
        admin: { ACTOR_POLICY_TABLE_ALLOWLIST: "incident", ACTOR_POLICY_ROW_FILTERS: "incident:active=true^ORDERBYnumber" },
      }),
    }))).toEqual([]);
  });

  it("collects all high-signal violations at once", () => {
    const err = (() => {
      try {
        assertProductionPosture({ DEPLOYMENT_PROFILE: "production" });
      } catch (e) {
        return e as ProductionPostureError;
      }
    })();
    expect(err).toBeInstanceOf(ProductionPostureError);
    expect(err.violations.length).toBeGreaterThan(10);
    expect(err.violations).toEqual(expect.arrayContaining([
      "ActorPolicy default table allowlist must be set in production.",
      "ALLOWED_ORIGINS must include at least one origin in production.",
      "BUDGET_DO binding is required in production.",
      "SNOW_INSTANCE_HOST must be pinned in production.",
    ]));
  });

  it("rejects weak secrets and malformed executor HMAC keys", () => {
    expect(collectPostureViolations(productionEnv({
      TOKEN_KEK_CURRENT: "password",
      OAUTH_PROVIDER_SECRET: "also-password",
      X_MCP_EXECUTOR_HMAC_KEY: "not-base64",
    }))).toEqual(expect.arrayContaining([
      "TOKEN_KEK_CURRENT must be a strong CSPRNG secret.",
      "OAUTH_PROVIDER_SECRET must be a strong CSPRNG secret.",
      "X_MCP_EXECUTOR_HMAC_KEY must decode to exactly 32 bytes.",
    ]));
  });

  it("rejects unsafe transport and credential shortcuts", () => {
    expect(collectPostureViolations(productionEnv({
      ALLOW_LOCALHOST: "true",
      SNOW_DEV_ROPC: "1",
      SERVICENOW_CREDENTIAL_MODE: "integration_user",
    }))).toEqual(expect.arrayContaining([
      'ALLOW_LOCALHOST must not be "true" in production.',
      "SNOW_DEV_ROPC must be disabled in production.",
      'SERVICENOW_CREDENTIAL_MODE must be "per_user_oauth" in production.',
    ]));
  });

  it("rejects malformed production OAuth origins", () => {
    expect(collectPostureViolations(productionEnv({
      WORKER_PUBLIC_ORIGIN: "worker.example.com",
    }))).toContain("WORKER_PUBLIC_ORIGIN must be a canonical HTTPS origin in production.");
    expect(collectPostureViolations(productionEnv({
      WORKER_PUBLIC_ORIGIN: "https://worker.example.com/callback",
    }))).toContain("WORKER_PUBLIC_ORIGIN must be a canonical HTTPS origin in production.");
  });

  it("rejects loopback/private allowed origins in production", () => {
    expect(collectPostureViolations(productionEnv({
      ALLOWED_ORIGINS: "https://app.example.com,https://localhost",
    }))).toContain("ALLOWED_ORIGINS entries must be canonical public HTTPS origins in production.");
    expect(collectPostureViolations(productionEnv({
      ALLOWED_ORIGINS: "https://192.168.1.10",
    }))).toContain("ALLOWED_ORIGINS entries must be canonical public HTTPS origins in production.");
  });

  it("requires configured admin_script approval tokens to be strong CSPRNG secrets", () => {
    expect(collectPostureViolations(productionEnv({
      ADMIN_SCRIPT_APPROVAL_TOKENS: "token-1",
    }))).toContain("ADMIN_SCRIPT_APPROVAL_TOKENS entries must be strong CSPRNG secrets.");
    expect(collectPostureViolations(productionEnv({
      ADMIN_SCRIPT_APPROVAL_TOKENS: STRONG_SECRET,
    }))).toEqual([]);
  });

  it("requires OIDC enterprise identity and rejects the shared operator secret in production", () => {
    expect(collectPostureViolations(productionEnv({
      AUTH_MODE: "operator_secret",
      MCP_OPERATOR_SECRET: STRONG_SECRET,
      MCP_OPERATOR_USER_ID: "operator-1",
      OIDC_ISSUER: undefined,
      OIDC_CLIENT_ID: undefined,
      OIDC_CLIENT_SECRET: undefined,
      OIDC_GROUP_POLICY_MAP: undefined,
    }))).toEqual(expect.arrayContaining([
      'AUTH_MODE must be "oidc" in production.',
      "MCP_OPERATOR_SECRET must be unset in production; use AUTH_MODE=oidc.",
      "OIDC_ISSUER is required when AUTH_MODE=oidc.",
      "OIDC_CLIENT_ID is required when AUTH_MODE=oidc.",
      "OIDC_CLIENT_SECRET is required when AUTH_MODE=oidc.",
      "OIDC_GROUP_POLICY_MAP is required when AUTH_MODE=oidc.",
    ]));

    expect(collectPostureViolations(productionEnv({
      AUTH_MODE: "oidc ",
      OIDC_ISSUER: "https://idp.example.com",
      OIDC_CLIENT_ID: "mcp-client",
      OIDC_CLIENT_SECRET: "client-secret",
      OIDC_GROUP_POLICY_MAP: "{\"admins\":{\"maxMode\":\"write\",\"policy\":\"admin\"}}",
      ACTOR_POLICIES_JSON: "{\"admin\":{\"ACTOR_POLICY_TABLE_ALLOWLIST\":\"incident\",\"ACTOR_POLICY_MAX_MODE\":\"write\"}}",
    }))).toEqual([]);
  });

  it("rejects invalid AUTH_MODE values instead of applying operator-secret defaults", () => {
    expect(collectPostureViolations(productionEnv({
      AUTH_MODE: "oidcish",
    }))).toContain('AUTH_MODE must be "operator_secret" or "oidc".');
  });

  it("validates OIDC group policy references against named ActorPolicies", () => {
    expect(collectPostureViolations(productionEnv({
      AUTH_MODE: "oidc",
      OIDC_ISSUER: "https://idp.example.com",
      OIDC_CLIENT_ID: "mcp-client",
      OIDC_CLIENT_SECRET: "client-secret",
      OIDC_GROUP_POLICY_MAP: "{\"admins\":{\"maxMode\":\"write\",\"policy\":\"missing\"}}",
    }))).toContain('OIDC_GROUP_POLICY_MAP references unknown ActorPolicy "missing".');
  });

  it("rejects malformed OIDC issuer URLs in production", () => {
    expect(collectPostureViolations(productionEnv({
      AUTH_MODE: "oidc",
      OIDC_ISSUER: "http://idp.example.com",
      OIDC_CLIENT_ID: "mcp-client",
      OIDC_CLIENT_SECRET: "client-secret",
      OIDC_GROUP_POLICY_MAP: "{\"admins\":{\"maxMode\":\"write\",\"policy\":\"admin\"}}",
      ACTOR_POLICIES_JSON: "{\"admin\":{\"ACTOR_POLICY_TABLE_ALLOWLIST\":\"incident\",\"ACTOR_POLICY_MAX_MODE\":\"write\"}}",
    }))).toContain("OIDC_ISSUER must be an HTTPS URL when AUTH_MODE=oidc.");
  });

  it("requires explicit non-admin tenant and instance ceilings unless break-glass is opted in", () => {
    expect(collectPostureViolations(productionEnv({
      TENANT_MAX_MODE: "admin_script" as Mode,
      INSTANCE_MAX_MODE: "admin_script" as Mode,
    }))).toEqual(expect.arrayContaining([
      "TENANT_MAX_MODE must be set below admin_script unless ALLOW_ADMIN_SCRIPT_CEILING=true.",
      "INSTANCE_MAX_MODE must be set below admin_script unless ALLOW_ADMIN_SCRIPT_CEILING=true.",
    ]));
    expect(collectPostureViolations(productionEnv({
      TENANT_MAX_MODE: "admin_script" as Mode,
      INSTANCE_MAX_MODE: "admin_script" as Mode,
      ALLOW_ADMIN_SCRIPT_CEILING: "true",
    }))).toContain('SNOW_EXECUTOR_VERIFIER_ATTESTED must be "true" before ALLOW_ADMIN_SCRIPT_CEILING=true in production.');
    expect(collectPostureViolations(productionEnv({
      TENANT_MAX_MODE: "admin_script" as Mode,
      INSTANCE_MAX_MODE: "admin_script" as Mode,
      ALLOW_ADMIN_SCRIPT_CEILING: "true",
      SNOW_EXECUTOR_VERIFIER_ATTESTED: "true",
    }))).toEqual([]);
  });

  it("requires snapshot storage and a strong snapshot KEK when recovery snapshots are enabled", () => {
    expect(collectPostureViolations(productionEnv({
      SNAPSHOT_ENABLED_TABLES: "incident",
      SNAPSHOT_KV: undefined,
      SNAPSHOT_KEK_CURRENT: "",
    }))).toEqual(expect.arrayContaining([
      "SNAPSHOT_KV binding is required when SNAPSHOT_ENABLED_TABLES is set.",
      "SNAPSHOT_KEK_CURRENT must be a strong CSPRNG secret when SNAPSHOT_ENABLED_TABLES is set.",
    ]));
  });

  it("rejects legacy or malformed executor endpoint paths", () => {
    expect(collectPostureViolations(productionEnv({
      SNOW_EXECUTOR_PATH: undefined,
    }))).toContain("SNOW_EXECUTOR_PATH must be /api/(x|sn)_<scope>/x_mcp/executor/run in production.");
    expect(collectPostureViolations(productionEnv({
      SNOW_EXECUTOR_PATH: "/api/1793136/x_mcp/executor/run",
    }))).toContain("SNOW_EXECUTOR_PATH must be /api/(x|sn)_<scope>/x_mcp/executor/run in production.");
    expect(collectPostureViolations(productionEnv({
      SNOW_EXECUTOR_PATH: "/api/x_mcp/executor/run",
    }))).toContain("SNOW_EXECUTOR_PATH must be /api/(x|sn)_<scope>/x_mcp/executor/run in production.");
    expect(collectPostureViolations(productionEnv({
      SNOW_EXECUTOR_PATH: "/api/x_acme_mcp/x_mcp/executor/run",
    }))).toEqual([]);
  });

  it("memoizes boot posture failures per env object", () => {
    const env = { DEPLOYMENT_PROFILE: "production" };
    let first: unknown;
    try {
      assertProductionPostureOnce(env);
    } catch (e) {
      first = e;
    }
    try {
      assertProductionPostureOnce(env);
    } catch (e) {
      expect(e).toBe(first);
    }
  });
});
