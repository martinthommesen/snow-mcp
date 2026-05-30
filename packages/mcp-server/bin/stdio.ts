#!/usr/bin/env node
// Optional local stdio shim (plan §8). Shares createServer(). describe_table/list_tables
// run directly in Node (plain HTTPS to ServiceNow). run_code needs the Worker Loader
// sandbox (workerd), which Node lacks — so it returns a clear "use the HTTP endpoint"
// message rather than pretending. Run a local Worker with `wrangler dev --port 8787`
// for full run_code.
//
// Env: SNOW_INSTANCE_HOST, SNOW_DEV_ROPC_USERNAME, SNOW_DEV_ROPC_PASSWORD (dev Basic Auth).
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createServer, type ServerHandlers, type ToolTextResult } from "../src/server.js";
import { SnFetchClient, type SnHttpClient } from "../src/sn/http.js";
import { describeTable, listTables, type DiscoveryDeps } from "../src/sn/discovery.js";
import { permissivePolicy } from "../src/authz/actor-policy.js";
import { RunBudget } from "../src/sn/run-budget.js";
import { DEFAULT_ALLOWED_HOST_SUFFIXES } from "../src/config.js";
import { McpToolError, toToolResult } from "../src/sn/errors.js";

const host = process.env.SNOW_INSTANCE_HOST;
const user = process.env.SNOW_DEV_ROPC_USERNAME;
const pass = process.env.SNOW_DEV_ROPC_PASSWORD;

function http(): SnHttpClient {
  if (!host || !user || !pass) {
    return { request: async () => { throw new McpToolError("reauth_required", "Set SNOW_INSTANCE_HOST/USERNAME/PASSWORD for the stdio dev path."); } };
  }
  return new SnFetchClient({
    instanceHost: host,
    allowlist: { allowedHostSuffixes: [...DEFAULT_ALLOWED_HOST_SUFFIXES] },
    getAuthorization: async () => "Basic " + Buffer.from(`${user}:${pass}`).toString("base64"),
  });
}

function discoveryDeps(): DiscoveryDeps {
  const instanceHost = host ?? "unconfigured.invalid";
  return { http: http(), instanceHost, effectiveMode: "read_only", actorPolicy: permissivePolicy([instanceHost]), runBudget: new RunBudget() };
}

const handlers: ServerHandlers = {
  runCode: async (): Promise<ToolTextResult> =>
    toToolResult(new McpToolError("internal_error", "run_code needs the Worker Loader sandbox — use the HTTP endpoint (wrangler dev --port 8787, POST /mcp).")),
  describeTable: async ({ table }): Promise<ToolTextResult> => {
    try {
      const fields = await describeTable(discoveryDeps(), table);
      return { content: [{ type: "text", text: JSON.stringify({ table, fields }) }], isError: false };
    } catch (e) { return toToolResult(e); }
  },
  listTables: async ({ filter }): Promise<ToolTextResult> => {
    try {
      const tables = await listTables(discoveryDeps(), filter);
      return { content: [{ type: "text", text: JSON.stringify({ tables }) }], isError: false };
    } catch (e) { return toToolResult(e); }
  },
};

const server = createServer(handlers);
await server.connect(new StdioServerTransport());
