import { describe, expect, it } from "vitest";
import { resolveEffectiveMode, DEFAULT_MODE } from "../src/authz/effective-mode.js";
import type { Mode } from "@servicenow-codemode/shared";

// ─── Phase 0.13b — effective-mode proof (hard-stop gate; B3/B4) ───────────────
// Pure host logic; real verification is local. Proves a requested mode can only
// narrow, never grant (plan §2.0.1).

const ALL: Mode = "admin_script";
const allCeilings = { scopeMaxMode: ALL, tenantMaxMode: ALL, instanceMaxMode: ALL } as const;

describe("Phase 0.13b — effective mode is min(requested, scope, tenant, instance)", () => {
  it("default mode is read_only (the floor)", () => {
    expect(DEFAULT_MODE).toBe("read_only");
    const r = resolveEffectiveMode(undefined, allCeilings);
    expect(r).toEqual({ ok: true, effective: "read_only" });
  });

  it("B3 — requesting admin_script WITHOUT the scope is denied (mode_not_permitted)", () => {
    const r = resolveEffectiveMode("admin_script", {
      scopeMaxMode: "read_only", // client lacks servicenow:admin_script
      tenantMaxMode: "admin_script",
      instanceMaxMode: "admin_script",
    });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.code).toBe("mode_not_permitted");
      expect(r.ceiling).toBe("read_only");
    }
  });

  it("B3b — a tenant or instance ceiling alone is enough to deny", () => {
    const tenantBlocks = resolveEffectiveMode("write", {
      scopeMaxMode: "admin_script",
      tenantMaxMode: "read_only",
      instanceMaxMode: "admin_script",
    });
    expect(tenantBlocks.ok).toBe(false);
  });

  it("B4 — a read_only-scoped client cannot self-escalate by passing mode in the input", () => {
    for (const asked of ["write", "admin_script"] as Mode[]) {
      const r = resolveEffectiveMode(asked, {
        scopeMaxMode: "read_only",
        tenantMaxMode: "admin_script",
        instanceMaxMode: "admin_script",
      });
      expect(r.ok).toBe(false);
    }
  });

  it("grants when requested is within every ceiling, narrowing to the lowest", () => {
    const r = resolveEffectiveMode("admin_script", {
      scopeMaxMode: "admin_script",
      tenantMaxMode: "write", // tenant caps at write
      instanceMaxMode: "admin_script",
    });
    // requested(2) > ceiling(write=1) -> deny, since requested only narrows.
    expect(r.ok).toBe(false);

    const ok = resolveEffectiveMode("write", {
      scopeMaxMode: "admin_script",
      tenantMaxMode: "write",
      instanceMaxMode: "admin_script",
    });
    expect(ok).toEqual({ ok: true, effective: "write" });
  });

  it("omitted request defaults to read_only even when everything is permitted", () => {
    const r = resolveEffectiveMode(undefined, allCeilings);
    expect(r).toEqual({ ok: true, effective: "read_only" });
  });
});

// ─── Phase P6a — fail-closed on a non-Mode value (closes the latent fail-open) ──
// Pre-P6a: MODE_RISK[unknown] === undefined, and `undefined > undefined` is false, so an
// unknown requested mode slipped past the cap check and resolved up to admin_script. Now an
// unknown mode scores +Infinity (modeRisk), so the cap check actively DENIES.
describe("Phase P6a — unknown mode fails CLOSED (denied, never widened)", () => {
  it("a non-Mode requested value is denied even when all ceilings are admin_script", () => {
    const r = resolveEffectiveMode("super_admin" as unknown as Mode, allCeilings);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("mode_not_permitted");
  });

  it("a prototype-pollution-style key ('constructor') is denied, not resolved", () => {
    const r = resolveEffectiveMode("constructor" as unknown as Mode, allCeilings);
    expect(r.ok).toBe(false);
  });

  it("an unknown ceiling cannot widen the effective mode (treated as max risk)", () => {
    // An unknown tenant ceiling must NOT become the (lowest) effective mode; a valid
    // read_only request still resolves to read_only.
    const r = resolveEffectiveMode("read_only", {
      scopeMaxMode: "admin_script",
      tenantMaxMode: "bogus" as unknown as Mode,
      instanceMaxMode: "admin_script",
    });
    expect(r).toEqual({ ok: true, effective: "read_only" });
  });

  it("still resolves valid admin_script (no regression)", () => {
    expect(resolveEffectiveMode("admin_script", allCeilings)).toEqual({ ok: true, effective: "admin_script" });
  });
});
