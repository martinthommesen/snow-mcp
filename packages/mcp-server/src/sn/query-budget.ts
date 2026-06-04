import { SN_REQUEST_LIMITS } from "../config.js";
import { utf8Len } from "../sandbox/serialize.js";
import { McpToolError } from "./errors.js";
import type { RunBudget } from "./run-budget.js";

export function serviceNowQueryStringBytes(query: Record<string, string> | undefined): number {
  if (!query || Object.keys(query).length === 0) return 0;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) params.set(key, value);
  return utf8Len(params.toString());
}

export function countServiceNowQueryBytes(runBudget: RunBudget, query: Record<string, string> | undefined): void {
  const bytes = serviceNowQueryStringBytes(query);
  if (bytes === 0) return;
  if (bytes > SN_REQUEST_LIMITS.maxQueryStringBytes) {
    throw new McpToolError("path_denied", `ServiceNow query string exceeds ${SN_REQUEST_LIMITS.maxQueryStringBytes} bytes.`, {
      dimension: "queryStringBytes",
      bytes,
    });
  }
  runBudget.countOutboundBytes(bytes);
}
