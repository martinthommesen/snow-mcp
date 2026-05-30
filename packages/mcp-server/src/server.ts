import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Mode } from "@servicenow-codemode/shared";

export const SERVER_NAME = "servicenow-codemode";
export const SERVER_VERSION = "0.1.0";

export interface ToolTextResult {
  // Index signature matches the SDK's CallToolResult (which is open-ended).
  [key: string]: unknown;
  content: { type: "text"; text: string }[];
  isError: boolean;
  structuredContent?: Record<string, unknown>;
}

/**
 * Handlers are injected so the server is testable without the (ServiceNow-gated) auth
 * stack. index.ts wires real handlers; tests can pass fakes. The `servicenow.*` typed
 * surface (ADR-0001) is injected into the run_code description at wiring time.
 */
export interface ServerHandlers {
  runCode: (input: { code: string; mode?: Mode; reason?: string; idempotencyKey?: string }) => Promise<ToolTextResult>;
  describeTable: (input: { table: string }) => Promise<ToolTextResult>;
  listTables: (input: { filter?: string }) => Promise<ToolTextResult>;
  /** Typed surface text appended to run_code's description (the `declare const servicenow…`). */
  surfaceDescription?: string;
}

const RUN_CODE_BASE_DESC =
  "Author an async-arrow TypeScript snippet that calls the typed `servicenow.*` RPC " +
  "surface and returns a result. The snippet runs in an isolated, network-less sandbox " +
  "with no credentials. Default mode is read_only; pass mode:'write'/'admin_script' to " +
  "declare destructive intent (capped by your OAuth scope/tenant/instance). admin_script " +
  "requires a `reason`. Shape: `async () => { const r = await servicenow.tableQuery({ table: 'incident', limit: 10 }); return r.rows; }`";

export function createServer(handlers: ServerHandlers): McpServer {
  const server = new McpServer({ name: SERVER_NAME, version: SERVER_VERSION });

  server.registerTool(
    "run_code",
    {
      description: handlers.surfaceDescription ? `${RUN_CODE_BASE_DESC}\n\n${handlers.surfaceDescription}` : RUN_CODE_BASE_DESC,
      inputSchema: {
        code: z.string().describe("Async-arrow TypeScript calling servicenow.* (ADR-0001 shape)."),
        mode: z.enum(["read_only", "write", "admin_script"]).optional().describe("Declared intent; only narrows from your scope."),
        reason: z.string().optional().describe("Required for admin_script — why this runs."),
        idempotencyKey: z.string().optional().describe("Dedupe key for mutating/executor calls."),
      },
      // openWorldHint: reaches an external system. NOT read-only (can mutate when permitted).
      annotations: { title: "Run ServiceNow code", readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
    async (input) => handlers.runCode(input),
  );

  server.registerTool(
    "describe_table",
    {
      description: "Return the field schema for a ServiceNow table (user-aware, cached). Read-only discovery for writing run_code.",
      inputSchema: { table: z.string().describe("Table name, e.g. 'incident'.") },
      annotations: { title: "Describe table", readOnlyHint: true, openWorldHint: true },
    },
    async (input) => handlers.describeTable(input),
  );

  server.registerTool(
    "list_tables",
    {
      description: "List ServiceNow tables, optionally filtered by a name fragment. Read-only discovery.",
      inputSchema: { filter: z.string().optional().describe("Case-insensitive name fragment.") },
      annotations: { title: "List tables", readOnlyHint: true, openWorldHint: true },
    },
    async (input) => handlers.listTables(input),
  );

  return server;
}
