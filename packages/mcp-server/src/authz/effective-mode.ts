// Effective-mode resolution (plan §2.0.1, §3.5) — the authorization cap that makes
// "read-only default" real: a REQUESTED mode can only NARROW, never grant.
//
//   effectiveMode = min(requested ?? DEFAULT_MODE, scope, tenant, instance)
//   if risk(requested) > risk(effective)  ->  deny "mode_not_permitted"
//
// This is pure host logic and is verified locally (B3/B4). It does NOT, by itself,
// approve `admin_script`: that additionally needs the allowlist + second-approval
// gate (§3.5, Phase 7.9), layered on top of a successful resolution here.

import { MODE_RISK, modeRisk, type Mode } from "@servicenow-codemode/shared";

/** Plan §0.9 Decision 1 — default floor. Flip to widen for private/internal demos. */
export const DEFAULT_MODE: Mode = "read_only";

/**
 * Lowest-risk (most restrictive) of the given modes. FAIL-CLOSED: `modeRisk` scores any
 * non-{@link Mode} value as +Infinity (plan §P6a), so an unknown mode is treated as the
 * HIGHEST risk and can never be selected as the (lower) effective mode — it would instead
 * be rejected by `resolveEffectiveMode`'s cap check below.
 */
export function minByRisk(first: Mode, ...rest: Mode[]): Mode {
  let lowest = first;
  for (const m of rest) {
    if (modeRisk(m) < modeRisk(lowest)) lowest = m;
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

/**
 * Parse an env-supplied mode ceiling (§P5). An UNSET var defaults to `admin_script`
 * to preserve "scope is the cap" when no tenant/instance ceiling is configured. A
 * value that IS SET yet is not a valid Mode fails closed to `read_only`; an operator
 * typo on a security ceiling must never silently grant the widest access.
 */
export function parseMaxMode(value: string | undefined): Mode {
  if (value === undefined) return "admin_script";
  return Object.prototype.hasOwnProperty.call(MODE_RISK, value) ? (value as Mode) : "read_only";
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
  // FAIL-CLOSED (plan §P6a): an unknown `requested` mode scores +Infinity via modeRisk, so
  // this comparison is true and the call is DENIED — never silently capped to admin_script.
  if (modeRisk(requested) > modeRisk(ceiling)) {
    return { ok: false, code: "mode_not_permitted", requested, ceiling };
  }
  return { ok: true, effective: minByRisk(requested, ceiling) };
}
