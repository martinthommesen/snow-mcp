import { describe, expect, it } from "vitest";
import { canonicalServiceNowHost } from "../../../scripts/servicenow-host-guard.mjs";

describe("oauth-verify ServiceNow host guard", () => {
  it("accepts bare or HTTPS ServiceNow hosts and canonicalizes them", () => {
    expect(canonicalServiceNowHost("Dev123.Service-Now.com")).toBe("dev123.service-now.com");
    expect(canonicalServiceNowHost("https://dev123.service-now.com")).toBe("dev123.service-now.com");
  });

  it("rejects non-ServiceNow, pathful, userinfo, cleartext, and loopback hosts", () => {
    for (const raw of [
      "evil.example.com",
      "evilservice-now.com",
      "https://dev123.service-now.com/api/now/table",
      "https://user:pass@dev123.service-now.com",
      "http://dev123.service-now.com",
      "localhost",
      "127.0.0.1",
      "10.0.0.1",
    ]) {
      expect(() => canonicalServiceNowHost(raw)).toThrow(/SNOW_INSTANCE_HOST rejected/);
    }
  });
});
