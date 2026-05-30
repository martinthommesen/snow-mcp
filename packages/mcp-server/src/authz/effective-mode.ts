// Effective-mode resolution (plan §2.0.1, §3.5) — the authorization cap that makes
// "read-only default" real: a REQUESTED mode can only NARROW, never grant.
//
//   effectiveMode = min(requested ?? DEFAULT_MODE, scope, tenant, instance)
//   if risk(requested) > risk(effective)  ->  deny "mode_not_permitted"
//
// This is pure host logic and is verified locally (B3/B4). It does NOT, by itself,
// approve `admin_script`: that additionally needs the allowlist + second-approval
// gate (§3.5, Phase 7.9), layered on top of a successful resolution here.

import { MODE_RISK, type Mode } from "@servicenow-codemode/shared";

/** Plan §0.9 Decision 1 — default floor. Flip to widen for private/internal demos. */
export const DEFAULT_MODE: Mode = "read_only";

/** Lowest-risk (most restrictive) of the given modes. */
export function minByRisk(first: Mode, ...rest: Mode[]): Mode {
  let lowest = first;
  for (const m of rest) {
    if (MODE_RISK[m] < MODE_RISK[lowest]) lowest = m;
  }
  return lowest;
}

export interface ModeCeilings {
  /** Highest mode the MCP-client OAuth scope permits (auth.props.maxMode, §2.4). */
  scopeMaxMode: Mode;
  /** Per-tenant ceiling. */
  tenantMaxMode: Mode;
  /** Per-instance ceiling. */
  instanceMaxMode: Mode;
}

export type EffectiveModeResult =
  | { ok: true; effective: Mode }
  | { ok: false; code: "mode_not_permitted"; requested: Mode; ceiling: Mode };

/**
 * Resolve the effective mode for a run_code call. `requestedMode` is what the tool
 * input asked for (undefined → DEFAULT_MODE floor).
 */
export function resolveEffectiveMode(
  requestedMode: Mode | undefined,
  ceilings: ModeCeilings,
): EffectiveModeResult {
  const requested = requestedMode ?? DEFAULT_MODE;
  const ceiling = minByRisk(ceilings.scopeMaxMode, ceilings.tenantMaxMode, ceilings.instanceMaxMode);

  // requested may only narrow: if it asks for more risk than the ceiling allows, deny.
  if (MODE_RISK[requested] > MODE_RISK[ceiling]) {
    return { ok: false, code: "mode_not_permitted", requested, ceiling };
  }
  return { ok: true, effective: minByRisk(requested, ceiling) };
}
