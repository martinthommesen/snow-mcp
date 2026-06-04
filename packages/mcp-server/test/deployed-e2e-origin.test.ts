import { describe, expect, it } from "vitest";
import {
  canonicalHttpsOrigin,
  readDevVarFromText,
  resolveDeployedE2eConfig,
} from "../../../scripts/deployed-e2e-origin.mjs";

describe("deployed E2E origin validation", () => {
  it("accepts the configured canonical worker origin and then reads the operator secret", () => {
    const devVarCalls: string[] = [];
    const out = resolveDeployedE2eConfig({
      argvBase: undefined,
      env: { AUTH_MODE: "operator_secret", DEPLOYMENT_PROFILE: "pilot" },
      devVar: (key: string) => {
        devVarCalls.push(key);
        return key === "WORKER_PUBLIC_ORIGIN" ? "https://worker.example.com" : "secret-value";
      },
    });
    expect(out).toEqual({ base: "https://worker.example.com", operatorSecret: "secret-value" });
    expect(devVarCalls).toEqual(["WORKER_PUBLIC_ORIGIN", "MCP_OPERATOR_SECRET"]);
  });

  it("refuses production or OIDC profiles before reading MCP_OPERATOR_SECRET", () => {
    const devVarCalls: string[] = [];
    expect(() => resolveDeployedE2eConfig({
      argvBase: undefined,
      env: { WORKER_PUBLIC_ORIGIN: "https://worker.example.com", AUTH_MODE: "oidc", DEPLOYMENT_PROFILE: "production" },
      devVar: (key: string) => {
        devVarCalls.push(key);
        return "secret-value";
      },
    })).toThrow(/pilot-only/);
    expect(devVarCalls).toEqual([]);
  });

  it("refuses an argv base that differs from WORKER_PUBLIC_ORIGIN before reading MCP_OPERATOR_SECRET", () => {
    const devVarCalls: string[] = [];
    expect(() => resolveDeployedE2eConfig({
      argvBase: "https://evil.example.com",
      env: { WORKER_PUBLIC_ORIGIN: "https://worker.example.com", AUTH_MODE: "operator_secret", DEPLOYMENT_PROFILE: "pilot" },
      devVar: (key: string) => {
        devVarCalls.push(key);
        return "secret-value";
      },
    })).toThrow(/does not match WORKER_PUBLIC_ORIGIN/);
    expect(devVarCalls).toEqual([]);
  });

  it("rejects cleartext, pathful, and userinfo base URLs", () => {
    for (const raw of [
      "http://worker.example.com",
      "https://worker.example.com/mcp",
      "https://user:pass@worker.example.com",
    ]) {
      expect(() => canonicalHttpsOrigin(raw, "worker base URL")).toThrow(/canonical HTTPS origin/);
    }
  });

  it("parses quoted and unquoted .dev.vars values without inline comments", () => {
    const text = [
      'WORKER_PUBLIC_ORIGIN="https://worker.example.com" # keep',
      "MCP_OPERATOR_SECRET=secret-value # keep out of value",
    ].join("\n");
    expect(readDevVarFromText(text, "WORKER_PUBLIC_ORIGIN")).toBe("https://worker.example.com");
    expect(readDevVarFromText(text, "MCP_OPERATOR_SECRET")).toBe("secret-value");
  });
});
