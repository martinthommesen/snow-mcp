// Destructive-operation approval gate (plan §3.5, §7.9). A declared mode:"admin_script"
// (already authorized by effective-mode, §2.0.1) is NOT the same as approval. This adds
// the tenant allowlist + a SECOND approval (access-group membership OR an approval token;
// dry-run→approve→execute and elicitation are stateful-only). Pure host logic — verified
// locally (extends B3/B4). The stateless createMcpHandler shape cannot elicit (§3.5).

import { McpToolError } from "../sn/errors.js";
import type { Mode } from "@servicenow-codemode/shared";

export interface ApprovalContext {
  mode: Mode;
  actorUserId: string;
  /** Mandatory reason for admin_script (§3.5). */
  reason?: string;
  /** Tenant allowlist of actors permitted to request admin_script at all. */
  adminScriptAllowlist: readonly string[];
  /** Second-approval option A: a tenant-configured approval token supplied in the call. */
  approvalToken?: string;
  validApprovalTokens?: ReadonlySet<string>;
  /** Second-approval option B: the actor's access groups vs a required group. */
  actorAccessGroups?: readonly string[];
  requiredAccessGroup?: string;
}

/**
 * Throws `capability_denied` unless an admin_script request is (a) allowlisted for the
 * actor, (b) accompanied by a non-empty reason, and (c) backed by a valid second
 * approval (token OR access-group). No-ops for non-admin_script modes.
 */
export function assertAdminScriptApproved(ctx: ApprovalContext): void {
  if (ctx.mode !== "admin_script") return;

  if (!ctx.reason?.trim()) {
    throw new McpToolError("capability_denied", "admin_script requires a non-empty `reason`.");
  }
  if (!ctx.adminScriptAllowlist.includes(ctx.actorUserId)) {
    throw new McpToolError("capability_denied", "admin_script is not allowlisted for this actor (tenant policy).", {
      actor: ctx.actorUserId,
    });
  }

  const tokenOk = Boolean(ctx.approvalToken) && (ctx.validApprovalTokens?.has(ctx.approvalToken!) ?? false);
  const groupOk =
    Boolean(ctx.requiredAccessGroup) && (ctx.actorAccessGroups?.includes(ctx.requiredAccessGroup!) ?? false);

  if (!tokenOk && !groupOk) {
    throw new McpToolError(
      "capability_denied",
      "admin_script requires a second approval (valid approval token or access-group membership).",
    );
  }
}
