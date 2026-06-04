/// <reference types="vite/client" />
import { describe, expect, it } from "vitest";
import fluentSource from "../../../sn-executor-app/fluent/src/fluent/x_mcp.now.ts?raw";
import executorSource from "../../../sn-executor-app/fluent/src/server/x_mcp_executor.js?raw";
import installerSource from "../../../scripts/executor-install.mjs?raw";
import verifierSource from "../../../scripts/executor-scoped-verify.mjs?raw";

describe("Phase 2 — admin_script executor defaults", () => {
  it("creates fresh scoped Fluent kill-switch properties disabled on first install only", () => {
    for (const name of [
      "x_1793136_mcp.executor.enabled",
      "x_1793136_mcp.executor.run_server_script_enabled",
    ]) {
      const start = fluentSource.indexOf(`name: '${name}'`);
      expect(start).toBeGreaterThan(-1);
      const block = fluentSource.slice(start, fluentSource.indexOf("})", start));
      expect(block).toContain("$meta: { installMethod: 'first install' }");
      expect(block).toContain("value: false");
    }
  });

  it("the scoped runtime defaults fail closed while legacy compatibility remains neutral", () => {
    expect(executorSource).toContain("gs.getProperty('x_1793136_mcp.executor.enabled', 'false')");
    expect(executorSource).toContain("gs.getProperty('x_1793136_mcp.executor.run_server_script_enabled', 'false')");
    expect(executorSource).toContain("gs.getProperty('x_mcp.executor.enabled', 'true')");
    expect(executorSource).toContain("gs.getProperty('x_mcp.executor.run_server_script_enabled', 'true')");
  });

  it("the live helper installer creates disabled defaults without overwriting existing operator choices", () => {
    expect(installerSource).toContain("async function ensurePropertyDefault");
    expect(installerSource).toContain('ensurePropertyDefault("x_1793136_mcp.executor.enabled", "false", "true|false")');
    expect(installerSource).toContain('ensurePropertyDefault("x_1793136_mcp.executor.run_server_script_enabled", "false", "true|false")');
    expect(installerSource).not.toContain('setProperty("x_1793136_mcp.executor.enabled", "true"');
    expect(installerSource).not.toContain('setProperty("x_1793136_mcp.executor.run_server_script_enabled", "true"');
  });

  it("the live verifier temporarily enables disabled executor toggles and restores them", () => {
    expect(verifierSource).toContain('"x_1793136_mcp.executor.enabled"');
    expect(verifierSource).toContain('"x_1793136_mcp.executor.run_server_script_enabled"');
    expect(verifierSource).toContain("enableExecutorTogglesForVerify");
    expect(verifierSource).toContain("restoreExecutorToggles");
    expect(verifierSource).toContain("FAILED to restore executor kill-switch properties");
  });

  it("defines table-level admin-only CRUD ACLs for the scoped audit log", () => {
    for (const [id, operation] of [
      ["acl_audit_table_create", "create"],
      ["acl_audit_table_read", "read"],
      ["acl_audit_table_write", "write"],
      ["acl_audit_table_delete", "delete"],
    ]) {
      const start = fluentSource.indexOf(`$id: Now.ID['${id}']`);
      expect(start).toBeGreaterThan(-1);
      const block = fluentSource.slice(start, fluentSource.indexOf("})", start));
      expect(block).toContain(`operation: '${operation}'`);
      expect(block).toContain("type: 'record'");
      expect(block).toContain("table: 'x_1793136_mcp_audit_log'");
      expect(block).toContain("adminOverrides: false");
      expect(block).toContain("roles: [adminRole]");
      expect(block).not.toContain("field:");
    }
  });
});
