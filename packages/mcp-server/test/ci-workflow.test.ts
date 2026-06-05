import { existsSync } from "node:fs";
import { describe, expect, it } from "vitest";
import ciText from "../../../.github/workflows/ci.yml?raw";
import dependabotText from "../../../.github/dependabot.yml?raw";
import packageJsonText from "../../../package.json?raw";

describe("ci workflow security posture", () => {
  it("uses the lockfile-pinned CycloneDX CLI instead of remote npx resolution", () => {
    expect(ciText).toContain("npm exec --no -- cyclonedx-npm --output-file sbom.json");
    expect(ciText).not.toMatch(/npx\s+--yes\s+@cyclonedx\/cyclonedx-npm/);
  });

  it("enforces the checked-in license policy in CI", () => {
    expect(ciText).toContain("node scripts/license-report.mjs --policy license-policy.json --enforce");
    expect(ciText).toContain("license-report.json");
  });

  it("keeps Dependabot enabled for root npm, Fluent npm, and GitHub Actions", () => {
    expect(dependabotText).toContain("package-ecosystem: npm");
    expect(dependabotText).toContain("directory: /sn-executor-app/fluent");
    expect(dependabotText).toContain("package-ecosystem: github-actions");
  });

  it("only runs live sub-prod gates from the trusted main ref", () => {
    expect(ciText).toContain("github.ref == 'refs/heads/main'");
  });

  it("passes optional executor-only verifier credentials to the live scoped-executor gate", () => {
    expect(ciText).toContain("SNOW_EXECUTOR_TEST_USERNAME");
    expect(ciText).toContain("SNOW_EXECUTOR_TEST_PASSWORD");
  });

  it("does not add an advanced CodeQL workflow while GitHub default setup is enabled", () => {
    const advancedCodeqlWorkflow = new URL("../../../.github/workflows/codeql.yml", import.meta.url);
    expect(existsSync(advancedCodeqlWorkflow)).toBe(false);
    expect(ciText).not.toContain("github/codeql-action/analyze");
  });

  it("makes production the only deploy path", () => {
    const scripts = (JSON.parse(packageJsonText) as { scripts: Record<string, string> }).scripts;
    expect(scripts.deploy).toContain("DEPLOYMENT_PROFILE=production");
    expect(scripts).not.toHaveProperty("deploy:pilot");
    expect(scripts).not.toHaveProperty("deploy:e2e");
    expect(scripts.deploy).not.toContain("ALLOW_PILOT_DEPLOY=1");
    expect(scripts["deploy:destroy"]).toContain("ALCHEMY_DESTROY=1");
    expect(scripts["deploy:destroy"]).not.toContain("DEPLOYMENT_PROFILE=production");
  });

  it("does not run the operator-secret pilot e2e as a production live gate", () => {
    expect(ciText).not.toContain("npm run deploy:e2e");
    expect(ciText).not.toContain("MCP_OPERATOR_SECRET");
  });

  it("exposes a manual production OIDC deployed MCP e2e gate", () => {
    const scripts = (JSON.parse(packageJsonText) as { scripts: Record<string, string> }).scripts;
    expect(scripts["production:oidc:e2e"]).toBe("node scripts/deployed-oidc-e2e.mjs");
    expect(ciText).toContain("run_production_oidc_e2e");
    expect(ciText).toContain("production-oidc-deployed-e2e");
    expect(ciText).toContain("npx playwright install --with-deps chromium");
    expect(ciText).toContain("npm run production:oidc:e2e");
    expect(ciText).toContain("github.ref == 'refs/heads/main'");
  });
});
