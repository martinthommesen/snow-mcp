import type { Mode } from "@servicenow-codemode/shared";

// Stable MCP OAuth contract. Do not rename or remove an existing scope without a versioned
// migration note and client compatibility window.
export const SUPPORTED_SCOPES = ["servicenow:read", "servicenow:write", "servicenow:admin_script"] as const;

export function maxModeFromScopes(scopes: readonly string[]): Mode {
  if (scopes.includes("servicenow:admin_script")) return "admin_script";
  if (scopes.includes("servicenow:write")) return "write";
  return "read_only";
}

export function grantScopes(requested: readonly string[]): string[] {
  return requested.filter((s) => (SUPPORTED_SCOPES as readonly string[]).includes(s));
}
