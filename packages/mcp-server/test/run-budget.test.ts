import { describe, expect, it } from "vitest";
import { RunBudget } from "../src/sn/run-budget.js";
import { BUDGETS } from "../src/config.js";
import { McpToolError } from "../src/sn/errors.js";

// ─── Phase P5 — per-run row/byte ENFORCEMENT (CODE_REVIEW findings 11, 12) ─────
// maxRowsPerRun / maxBytesPerRun were DEAD policy fields (set, never read). RunBudget now
// receives them as caps and ENFORCES via countRows/countBytes (formerly observability-only;
// bytesReturned was never even incremented). The throw carries the dimension the P2
// `budgetExceeded` host signal attests.

describe("Phase P5 — RunBudget row/byte cap enforcement", () => {
  it("countRows throws budget_exceeded {dimension:rowsReturned} when over the cap", () => {
    const b = new RunBudget(BUDGETS.perRun, { maxRows: 3 });
    b.countRows(2); // under cap — ok
    expect(b.rowsReturned).toBe(2);
    try {
      b.countRows(2); // 4 > 3 — trips
      throw new Error("expected budget_exceeded");
    } catch (e) {
      expect(e).toBeInstanceOf(McpToolError);
      expect((e as McpToolError).code).toBe("budget_exceeded");
      expect((e as McpToolError).detail?.dimension).toBe("rowsReturned");
    }
  });

  it("countBytes increments bytesReturned and throws {dimension:bytesReturned} over the cap", () => {
    const b = new RunBudget(BUDGETS.perRun, { maxBytes: 10 });
    b.countBytes(6);
    expect(b.bytesReturned).toBe(6); // formerly never incremented
    try {
      b.countBytes(6); // 12 > 10 — trips
      throw new Error("expected budget_exceeded");
    } catch (e) {
      expect(e).toBeInstanceOf(McpToolError);
      expect((e as McpToolError).code).toBe("budget_exceeded");
      expect((e as McpToolError).detail?.dimension).toBe("bytesReturned");
    }
  });

  it("an uncapped RunBudget (no caps) never trips on rows/bytes", () => {
    const b = new RunBudget(); // permissive default — observability-only
    b.countRows(1_000_000);
    b.countBytes(1_000_000_000);
    expect(b.rowsReturned).toBe(1_000_000);
    expect(b.bytesReturned).toBe(1_000_000_000);
  });

  it("countOutboundBytes enforces the per-run outbound body cap with its own dimension", () => {
    const b = new RunBudget({ ...BUDGETS.perRun, maxOutboundBytes: 10 });
    b.countOutboundBytes(6);
    expect(b.outboundBytesSent).toBe(6);
    try {
      b.countOutboundBytes(5);
      throw new Error("expected budget_exceeded");
    } catch (e) {
      expect(e).toBeInstanceOf(McpToolError);
      expect((e as McpToolError).code).toBe("budget_exceeded");
      expect((e as McpToolError).detail?.dimension).toBe("outboundBytesSent");
    }
  });
});
