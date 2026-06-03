import { describe, expect, it } from "vitest";
import ciText from "../../../.github/workflows/ci.yml?raw";

describe("ci workflow security posture", () => {
  it("uses the lockfile-pinned CycloneDX CLI instead of remote npx resolution", () => {
    expect(ciText).toContain("npm exec --no -- cyclonedx-npm --output-file sbom.json");
    expect(ciText).not.toMatch(/npx\s+--yes\s+@cyclonedx\/cyclonedx-npm/);
  });

  it("only runs live sub-prod gates from the trusted main ref", () => {
    expect(ciText).toContain("github.ref == 'refs/heads/main'");
  });
});
