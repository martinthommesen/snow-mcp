/// <reference types="vite/client" />
import { describe, expect, it } from "vitest";
import alchemySource from "../../../alchemy.run.ts?raw";
import { tokenKekBindings } from "../../../alchemy.bindings";

describe("Alchemy deploy bindings", () => {
  it("forwards origin config required by auth-surface and per-user OAuth", () => {
    for (const name of ["ALLOWED_ORIGINS", "WORKER_PUBLIC_ORIGIN"]) {
      expect(alchemySource).toContain(`process.env.${name}`);
      expect(alchemySource).toContain(`${name}: process.env.${name}`);
    }
  });

  it("forwards the admin_script second-approval policy into Worker bindings", () => {
    for (const name of ["ADMIN_SCRIPT_ALLOWLIST", "ADMIN_SCRIPT_APPROVAL_TOKENS", "ADMIN_SCRIPT_REQUIRED_GROUP"]) {
      expect(alchemySource).toContain(`process.env.${name}`);
    }
    expect(alchemySource).toMatch(
      /ADMIN_SCRIPT_APPROVAL_TOKENS:\s*alchemy\.secret\(process\.env\.ADMIN_SCRIPT_APPROVAL_TOKENS\)/,
    );
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
    ]) {
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
});

// P2b: the token-KEK binding must accept the versioned key alone (the host reads
// TOKEN_KEK_CURRENT ?? TOKEN_KEK). These exercise the EXTRACTED helper directly — a raw-text
// assertion on alchemy.run.ts cannot prove deploy-time behavior because the module has a
// top-level `await alchemy(...)` and would attempt to provision on import.
describe("tokenKekBindings (P2b)", () => {
  const tag = (v: string) => `secret(${v})`; // stand-in for alchemy.secret

  it("accepts TOKEN_KEK_CURRENT alone (versioned-only config deploys)", () => {
    const b = tokenKekBindings({ TOKEN_KEK_CURRENT: "cur" }, tag);
    expect(b).toEqual({ TOKEN_KEK_CURRENT: "secret(cur)" });
    expect(b).not.toHaveProperty("TOKEN_KEK");
  });

  it("accepts legacy TOKEN_KEK alone (existing single-key deployments still deploy)", () => {
    const b = tokenKekBindings({ TOKEN_KEK: "leg" }, tag);
    expect(b).toEqual({ TOKEN_KEK: "secret(leg)" });
    expect(b).not.toHaveProperty("TOKEN_KEK_CURRENT");
  });

  it("binds both + PREV when all present", () => {
    expect(tokenKekBindings({ TOKEN_KEK: "leg", TOKEN_KEK_CURRENT: "cur", TOKEN_KEK_PREV: "prev" }, tag)).toEqual({
      TOKEN_KEK: "secret(leg)",
      TOKEN_KEK_CURRENT: "secret(cur)",
      TOKEN_KEK_PREV: "secret(prev)",
    });
  });

  it("throws when NEITHER current nor legacy is set (fail-closed, naming both keys)", () => {
    expect(() => tokenKekBindings({}, tag)).toThrow(/TOKEN_KEK_CURRENT.*TOKEN_KEK|TOKEN_KEK.*TOKEN_KEK_CURRENT/);
    // Whitespace-only values are treated as unset.
    expect(() => tokenKekBindings({ TOKEN_KEK: "   ", TOKEN_KEK_CURRENT: "" }, tag)).toThrow(/Missing token KEK/);
  });
});
