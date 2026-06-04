import { describe, expect, it } from "vitest";
import ciText from "../../../.github/workflows/ci.yml?raw";
import codeqlText from "../../../.github/workflows/codeql.yml?raw";
import packageJsonText from "../../../package.json?raw";

describe("ci workflow security posture", () => {
  it("uses the lockfile-pinned CycloneDX CLI instead of remote npx resolution", () => {
    expect(ciText).toContain("npm exec --no -- cyclonedx-npm --output-file sbom.json");
    expect(ciText).not.toMatch(/npx\s+--yes\s+@cyclonedx\/cyclonedx-npm/);
  });

  it("only runs live sub-prod gates from the trusted main ref", () => {
    expect(ciText).toContain("github.ref == 'refs/heads/main'");
  });

  it("has a checked-in CodeQL JavaScript/TypeScript analysis workflow", () => {
    expect(codeqlText).toContain("github/codeql-action/init");
    expect(codeqlText).toContain("languages: javascript-typescript");
    expect(codeqlText).toContain("security-events: write");
  });

  it("makes production the only deploy path", () => {
    const scripts = (JSON.parse(packageJsonText) as { scripts: Record<string, string> }).scripts;
    expect(scripts.deploy).toContain("DEPLOYMENT_PROFILE=production");
    expect(scripts).not.toHaveProperty("deploy:pilot");
    expect(scripts).not.toHaveProperty("deploy:e2e");
    expect(scripts.deploy).not.toContain("ALLOW_PILOT_DEPLOY=1");
    expect(scripts["deploy:destroy"]).toContain("DEPLOYMENT_PROFILE=production");
  });

  it("does not run the operator-secret pilot e2e as a production live gate", () => {
    expect(ciText).not.toContain("npm run deploy:e2e");
    expect(ciText).not.toContain("MCP_OPERATOR_SECRET");
  });
});
