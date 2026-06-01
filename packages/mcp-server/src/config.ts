// Central configuration & the ENFORCED mode→capability map (plan §3.5, §4.1, §2.5).
// Pure constants + gating helpers — unit-verified locally.

import { McpToolError } from "./sn/errors.js";
import type { Mode } from "@servicenow-codemode/shared";

export { DEFAULT_MODE } from "./authz/effective-mode.js";

/** Capabilities a sandbox snippet may exercise via ServiceNowRPC. */
export type Capability =
  | "readTables"
  | "writeTables"
  | "runServerScript";

/** Enforced mode→capability map (plan §3.5). The requested mode is already capped
 *  by §2.0.1 before this is consulted; this gates which RPC methods may run. */
export const MODE_CAPABILITIES: Readonly<Record<Mode, readonly Capability[]>> = {
  read_only: ["readTables"],
  write: ["readTables", "writeTables"],
  admin_script: ["readTables", "writeTables", "runServerScript"],
} as const;

export function hasCapability(mode: Mode, cap: Capability): boolean {
  return MODE_CAPABILITIES[mode].includes(cap);
}

/** Throw `capability_denied` if `mode` does not grant `cap` (out-of-mode RPC call). */
export function requireCapability(mode: Mode, cap: Capability): void {
  if (!hasCapability(mode, cap)) {
    throw new McpToolError("capability_denied", `Capability "${cap}" is not permitted in mode "${mode}".`, {
      mode,
      capability: cap,
    });
  }
}

/** Size caps (plan §10, §4.6). UTF-8 bytes. */
export const SIZE_LIMITS = {
  maxCodeBytes: 64 * 1024, // reject oversize snippets pre-transpile
  maxOutputBytes: 256 * 1024, // truncate run_code result beyond this
  // M-3: cap snippet console.log output too — the result value is capped at maxOutputBytes, but
  // exec.logs was spliced into the tool result verbatim (a `for(;;)console.log("x".repeat(1e6))`
  // loop inflated the payload to ~sandbox-memory size, uncapped/unmetered). Truncate to these.
  maxLogBytes: 64 * 1024, // total UTF-8 bytes across all captured log entries
  maxLogEntries: 1000, // max number of log entries retained
} as const;

/** Multi-dimensional budgets (plan §2.5). Per-run trips mid-snippet; daily is the hard breaker. */
export const BUDGETS = {
  perRun: {
    rpcCallLimit: 200,
    serviceNowRequestLimit: 200,
    wallClockMs: 30_000,
  },
  daily: {
    uniqueWorkers: 1000,
    sandboxRpcCalls: 100_000,
    serviceNowRequests: 100_000,
    rowsReturned: 5_000_000,
    bytesReturned: 1024 * 1024 * 1024,
  },
} as const;

/** Host-side Table API safety cap over ServiceNow's documented default of 10000 (§2.13). */
export const TABLE_PAGE_CAP = 1000;

/** Default instance allowlist suffix (PDI/dev). Narrow per tenant in production (§1.5). */
export const DEFAULT_ALLOWED_HOST_SUFFIXES = ["service-now.com"] as const;
