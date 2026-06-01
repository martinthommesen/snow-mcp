/// <reference types="vite/client" />
import { describe, expect, it } from "vitest";
import alchemySource from "../../../alchemy.run.ts?raw";

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
