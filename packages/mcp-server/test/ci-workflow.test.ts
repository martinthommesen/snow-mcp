import { describe, expect, it } from "vitest";
import ciText from "../../../.github/workflows/ci.yml?raw";
import packageJsonText from "../../../package.json?raw";

describe("ci workflow security posture", () => {
  it("uses the lockfile-pinned CycloneDX CLI instead of remote npx resolution", () => {
    expect(ciText).toContain("npm exec --no -- cyclonedx-npm --output-file sbom.json");
    expect(ciText).not.toMatch(/npx\s+--yes\s+@cyclonedx\/cyclonedx-npm/);
  });

  it("only runs live sub-prod gates from the trusted main ref", () => {
    expect(ciText).toContain("github.ref == 'refs/heads/main'");
  });

  it("makes production the default deploy path and keeps pilot explicit", () => {
    const scripts = (JSON.parse(packageJsonText) as { scripts: Record<string, string> }).scripts;
    expect(scripts.deploy).toContain("DEPLOYMENT_PROFILE=production");
    expect(scripts["deploy:pilot"]).toContain("ALLOW_PILOT_DEPLOY=1");
    expect(scripts["deploy:pilot"]).toContain("DEPLOYMENT_PROFILE=pilot");
    expect(scripts.deploy).not.toContain("ALLOW_PILOT_DEPLOY=1");
  });
});
