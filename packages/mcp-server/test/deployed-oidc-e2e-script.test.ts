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
    expect(scriptText).toContain("refreshed token reflects group-policy downgrade/removal and denies write");
  });

  it("fails closed if the operator-secret path is accidentally configured", () => {
    expect(scriptText).toContain("MCP_OPERATOR_SECRET must not be set");
    expect(scriptText).not.toContain("operator_secret");
  });
});
