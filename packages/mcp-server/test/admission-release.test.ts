/// <reference types="vite/client" />
import { describe, expect, it } from "vitest";
import indexSource from "../src/index.ts?raw";

describe("authenticated /mcp admission lease lifetime", () => {
  it("releases admitted leases when the response body closes or is canceled", () => {
    expect(indexSource).toContain("function responseWithAdmissionRelease");
    expect(indexSource).toContain(".pipeTo(writable)");
    expect(indexSource).toContain(".finally(() => releaseMcpAdmission(lease))");
    expect(indexSource).toContain("return responseWithAdmissionRelease(response, admission, ctx)");
    expect(indexSource).not.toContain("} finally {\n        await releaseMcpAdmission(admission)");
  });

  it("rejects missing per-user OAuth public origin before acquiring an admission lease", () => {
    const originCheck = indexSource.indexOf("const workerOrigin = canonicalPublicOrigin(env.WORKER_PUBLIC_ORIGIN)");
    const publicOriginError = indexSource.indexOf("public_origin_required");
    const admission = indexSource.indexOf("const admission = await admitMcpRequest(env, userId)");

    expect(originCheck).toBeGreaterThan(-1);
    expect(publicOriginError).toBeGreaterThan(originCheck);
    expect(publicOriginError).toBeLessThan(admission);
  });
});
