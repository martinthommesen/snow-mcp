/// <reference types="vite/client" />
import { describe, expect, it } from "vitest";
import alchemySource from "../../../alchemy.run.ts?raw";
import { operatorSecretBindings, parseDevVarLine, tokenKekBindings } from "../../../alchemy.bindings";

describe("Alchemy deploy bindings", () => {
  it("forwards origin config required by auth-surface and per-user OAuth", () => {
    for (const name of ["ALLOWED_ORIGINS", "WORKER_PUBLIC_ORIGIN"]) {
      expect(alchemySource).toContain(`process.env.${name}`);
      expect(alchemySource).toContain(`${name}: process.env.${name}`);
    }
  });

  it("forwards the admin_script second-approval policy into Worker bindings", () => {
    for (const name of [
      "ADMIN_SCRIPT_ALLOWLIST",
      "ADMIN_SCRIPT_APPROVAL_TOKENS",
      "ADMIN_SCRIPT_REQUIRED_GROUP",
      "SNOW_EXECUTOR_VERIFIER_ATTESTED",
    ]) {
      expect(alchemySource).toContain(`process.env.${name}`);
    }
    expect(alchemySource).toMatch(
      /ADMIN_SCRIPT_APPROVAL_TOKENS:\s*alchemy\.secret\(process\.env\.ADMIN_SCRIPT_APPROVAL_TOKENS\)/,
    );
  });

  it("declares authenticated MCP admission and incident/audit posture bindings", () => {
    expect(alchemySource).toContain('MCP_ADMISSION_DO: DurableObjectNamespace("MCP_ADMISSION_DO"');
    for (const name of ["AUDIT_SIEM_ATTESTED", "MUTATION_FREEZE"]) {
      expect(alchemySource).toContain(`process.env.${name}`);
      expect(alchemySource).toContain(`${name}: process.env.${name}`);
    }
  });

  it("forwards snapshot and restrictive ActorPolicy config as plain bindings", () => {
    for (const name of [
      "SNAPSHOT_ENABLED_TABLES",
      "ACTOR_POLICY_TABLE_ALLOWLIST",
      "ACTOR_POLICY_FIELD_MASKS",
      "ACTOR_POLICY_ROW_FILTERS",
      "ACTOR_POLICY_MAX_ROWS_PER_RUN",
      "ACTOR_POLICY_MAX_BYTES_PER_RUN",
      "ACTOR_POLICY_MAX_MODE",
      "ACTOR_POLICIES_JSON",
    ]) {
      expect(alchemySource).toContain(`process.env.${name}`);
      expect(alchemySource).toContain(`${name}: process.env.${name}`);
    }
  });

  it("forwards OIDC identity-provider config and keeps the client secret secret", () => {
    for (const name of [
      "AUTH_MODE",
      "OIDC_ISSUER",
      "OIDC_CLIENT_ID",
      "OIDC_SCOPES",
      "OIDC_GROUP_CLAIM",
      "OIDC_GROUP_POLICY_MAP",
      "OIDC_DEFAULT_POLICY_NAME",
    ]) {
      expect(alchemySource).toContain(`process.env.${name}`);
      expect(alchemySource).toContain(`${name}: process.env.${name}`);
    }
    expect(alchemySource).toMatch(/OIDC_CLIENT_SECRET:\s*alchemy\.secret\(process\.env\.OIDC_CLIENT_SECRET\)/);
  });

  it("does not unconditionally require the operator secret for OIDC deployments", () => {
    expect(alchemySource).toContain("operatorSecretBindings(process.env");
    expect(alchemySource).not.toMatch(/MCP_OPERATOR_SECRET:\s*alchemy\.secret\(reqEnv\("MCP_OPERATOR_SECRET"\)\)/);
  });

  it("forwards optional build metadata for /health/version", () => {
    for (const name of ["GIT_COMMIT_SHA", "BUILD_TIMESTAMP"]) {
      expect(alchemySource).toContain(`process.env.${name}`);
      expect(alchemySource).toContain(`${name}: process.env.${name}`);
    }
  });

  it("forwards SNOW_DEV_ROPC as an explicit plain toggle and only binds ROPC secrets behind it", () => {
    expect(alchemySource).toContain("process.env.SNOW_DEV_ROPC");
    expect(alchemySource).toContain('process.env.SNOW_DEV_ROPC === "1"');
    expect(alchemySource).toMatch(/SNOW_DEV_ROPC_USERNAME:\s*alchemy\.secret\(reqEnv\("SNOW_DEV_ROPC_USERNAME"\)\)/);
    expect(alchemySource).toMatch(/SNOW_DEV_ROPC_PASSWORD:\s*alchemy\.secret\(reqEnv\("SNOW_DEV_ROPC_PASSWORD"\)\)/);
  });

  it("decouples destroy from production deploy posture and Worker secret assembly", () => {
    expect(alchemySource).toContain('process.env.ALCHEMY_DESTROY === "1" || process.argv.includes("--destroy")');
    expect(alchemySource).toContain("ALCHEMY_STATE_PASSWORD");
    expect(alchemySource).toContain("if (isDestroyMode)");
    expect(alchemySource).toContain("process.exit(0)");
    expect(alchemySource).toContain('Alchemy deploy requires DEPLOYMENT_PROFILE="production".');
  });
});

// P2b: the token-KEK binding requires the versioned current key. These exercise the EXTRACTED
// helper directly — a raw-text
// assertion on alchemy.run.ts cannot prove deploy-time behavior because the module has a
// top-level `await alchemy(...)` and would attempt to provision on import.
describe("tokenKekBindings (P2b)", () => {
  const tag = (v: string) => `secret(${v})`; // stand-in for alchemy.secret

  it("requires and binds TOKEN_KEK_CURRENT", () => {
    const b = tokenKekBindings({ TOKEN_KEK_CURRENT: "cur" }, tag);
    expect(b).toEqual({ TOKEN_KEK_CURRENT: "secret(cur)" });
  });

  it("binds PREV only alongside CURRENT during a rotation window", () => {
    expect(tokenKekBindings({ TOKEN_KEK_CURRENT: "cur", TOKEN_KEK_PREV: "prev" }, tag)).toEqual({
      TOKEN_KEK_CURRENT: "secret(cur)",
      TOKEN_KEK_PREV: "secret(prev)",
    });
  });

  it("throws when current is unset", () => {
    expect(() => tokenKekBindings({}, tag)).toThrow(/TOKEN_KEK_CURRENT/);
    // Whitespace-only values are treated as unset.
    expect(() => tokenKekBindings({ TOKEN_KEK_CURRENT: "" }, tag)).toThrow(/Missing token KEK/);
  });
});

describe("operatorSecretBindings", () => {
  const tag = (v: string) => `secret(${v})`;

  it("does not require or bind MCP_OPERATOR_SECRET when AUTH_MODE=oidc", () => {
    expect(operatorSecretBindings({ AUTH_MODE: "oidc" }, tag)).toEqual({});
    expect(operatorSecretBindings({ AUTH_MODE: "oidc " }, tag)).toEqual({});
  });

  it("does not require or bind MCP_OPERATOR_SECRET for production deployments", () => {
    expect(operatorSecretBindings({ DEPLOYMENT_PROFILE: "production" }, tag)).toEqual({});
    expect(operatorSecretBindings({ DEPLOYMENT_PROFILE: "production", MCP_OPERATOR_SECRET: "leftover" }, tag)).toEqual({});
  });

  it("requires MCP_OPERATOR_SECRET for operator-secret mode", () => {
    expect(() => operatorSecretBindings({ AUTH_MODE: "operator_secret" }, tag)).toThrow(/MCP_OPERATOR_SECRET/);
    expect(operatorSecretBindings({ MCP_OPERATOR_SECRET: "operator-secret" }, tag)).toEqual({
      MCP_OPERATOR_SECRET: "secret(operator-secret)",
    });
  });

  it("rejects invalid AUTH_MODE values instead of falling back to operator-secret deploys", () => {
    expect(() => operatorSecretBindings({ AUTH_MODE: "oidcish" }, tag)).toThrow(/AUTH_MODE/);
  });
});

describe("parseDevVarLine", () => {
  it("parses quoted values with shell-style inline comments", () => {
    expect(parseDevVarLine('DEPLOYMENT_PROFILE="pilot" # documented default')).toEqual(["DEPLOYMENT_PROFILE", "pilot"]);
    expect(parseDevVarLine('OIDC_SCOPES="openid profile email offline_access" # keep refresh')).toEqual([
      "OIDC_SCOPES",
      "openid profile email offline_access",
    ]);
  });

  it("preserves hashes inside quoted values", () => {
    expect(parseDevVarLine('VALUE="keep # this" # strip this')).toEqual(["VALUE", "keep # this"]);
  });

  it("skips comments and malformed lines", () => {
    expect(parseDevVarLine("# comment")).toBeUndefined();
    expect(parseDevVarLine("not-a-binding")).toBeUndefined();
  });
});
