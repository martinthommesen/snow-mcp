/// <reference types="vite/client" />
import { describe, expect, it } from "vitest";
import scriptText from "../../../scripts/deployed-oidc-e2e.mjs?raw";

describe("production deployed OIDC E2E script", () => {
  it("uses a real Playwright browser context for OIDC state-cookie checks", () => {
    expect(scriptText).toContain('import { chromium } from "playwright"');
    expect(scriptText).toContain("context.cookies(config.base)");
    expect(scriptText).toContain("__Host-oidc_state_");
    expect(scriptText).toContain("Secure/HttpOnly/SameSite=Lax");
    expect(scriptText).not.toContain('headers: { cookie: "__Host-oidc_state_');
  });

  it("covers deployed OIDC success, code-injection rejection, and refresh-policy re-evaluation", () => {
    expect(scriptText).toContain("negative OIDC code-injection attempt is rejected");
    expect(scriptText).toContain("OIDC auth-code + MCP PKCE exchange issues an access token");
    expect(scriptText).toContain("MCP refresh-token exchange reissues an access token");
    expect(scriptText).toContain("refreshed token denies write under current OIDC policy");
  });

  it("does not auto-click a generic No button by default", () => {
    expect(scriptText).not.toContain('button:has-text("No")');
  });

  it("fails closed if the operator-secret path is accidentally configured", () => {
    expect(scriptText).toContain("MCP_OPERATOR_SECRET must not be set");
    expect(scriptText).not.toContain("operator_secret");
  });

  it("treats empty OIDC_E2E_SCOPES as the documented default scope", () => {
    expect(scriptText).toContain("parseScopes(process.env.OIDC_E2E_SCOPES)");
    expect(scriptText).not.toContain('process.env.OIDC_E2E_SCOPES ?? "servicenow:write"');
  });

  it("makes the refresh downgrade assertion default-on", () => {
    expect(scriptText).toContain('expectRefreshWriteDenied: boolEnv("OIDC_E2E_EXPECT_REFRESH_WRITE_DENIED", true)');
  });
});
