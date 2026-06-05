import { describe, expect, it, vi } from "vitest";
import { responseWithAdmissionRelease, type AdmissionLease } from "../src/index.js";

function testCtx(): ExecutionContext & { waits: Promise<unknown>[] } {
  const waits: Promise<unknown>[] = [];
  return {
    waits,
    waitUntil(promise: Promise<unknown>) {
      waits.push(Promise.resolve(promise));
    },
    passThroughOnException() {},
    props: {},
  } as unknown as ExecutionContext & { waits: Promise<unknown>[] };
}

function testLease() {
  const release = vi.fn(async () => {});
  const renew = vi.fn(async () => true);
  const lease: AdmissionLease = {
    leaseId: "lease-1",
    stub: {
      admit: vi.fn(),
      release,
      renew,
    },
  };
  return { lease, release, renew };
}

describe("authenticated /mcp admission lease lifetime", () => {
  it("releases admitted leases only after the response body closes", async () => {
    const ctx = testCtx();
    const { lease, release } = testLease();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("ok"));
        controller.close();
      },
    });

    const wrapped = responseWithAdmissionRelease(new Response(stream), lease, ctx);
    expect(release).not.toHaveBeenCalled();
    await wrapped.text();
    await Promise.all(ctx.waits);

    expect(release).toHaveBeenCalledTimes(1);
    expect(release).toHaveBeenCalledWith("lease-1");
  });

  it("releases admitted leases when the response body is canceled", async () => {
    const ctx = testCtx();
    const { lease, release } = testLease();
    const wrapped = responseWithAdmissionRelease(new Response(new ReadableStream<Uint8Array>()), lease, ctx);

    await wrapped.body?.cancel();
    await Promise.all(ctx.waits);

    expect(release).toHaveBeenCalledTimes(1);
    expect(release).toHaveBeenCalledWith("lease-1");
  });

  it("renews admitted leases while the response body remains open", async () => {
    vi.useFakeTimers();
    try {
      const ctx = testCtx();
      const { lease, release, renew } = testLease();
      const wrapped = responseWithAdmissionRelease(new Response(new ReadableStream<Uint8Array>()), lease, ctx);

      await vi.advanceTimersByTimeAsync(30_000);
      expect(renew).toHaveBeenCalledTimes(1);
      expect(renew).toHaveBeenCalledWith("lease-1", expect.any(Number));
      expect(release).not.toHaveBeenCalled();

      await wrapped.body?.cancel();
      await Promise.all(ctx.waits);
      const renewCountAfterCancel = renew.mock.calls.length;
      await vi.advanceTimersByTimeAsync(60_000);

      expect(release).toHaveBeenCalledTimes(1);
      expect(renew).toHaveBeenCalledTimes(renewCountAfterCancel);
    } finally {
      vi.useRealTimers();
    }
  });

  it("releases admitted leases through waitUntil when the response has no body", async () => {
    const ctx = testCtx();
    const { lease, release } = testLease();

    responseWithAdmissionRelease(new Response(null), lease, ctx);
    await Promise.all(ctx.waits);

    expect(release).toHaveBeenCalledTimes(1);
    expect(release).toHaveBeenCalledWith("lease-1");
  });
});
