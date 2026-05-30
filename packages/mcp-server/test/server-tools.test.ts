import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer, type ServerHandlers } from "../src/server.js";

// ─── MCP surface — the three tools, registered with schemas + annotations ─────
// Verifies the wire-level surface a real client sees (per the build-mcp-server skill).

function fakeHandlers(): ServerHandlers {
  const ok = async () => ({ content: [{ type: "text" as const, text: "ok" }], isError: false });
  return {
    runCode: async ({ code }) => ({ content: [{ type: "text" as const, text: `ran:${code.length}` }], isError: false }),
    describeTable: ok,
    listTables: ok,
  };
}

async function connect() {
  const server = createServer(fakeHandlers());
  const client = new Client({ name: "test", version: "0" });
  const [clientT, serverT] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverT), client.connect(clientT)]);
  return client;
}

describe("MCP surface", () => {
  it("lists exactly run_code, describe_table, list_tables with annotations", async () => {
    const client = await connect();
    const { tools } = await client.listTools();
    const byName = Object.fromEntries(tools.map((t) => [t.name, t]));
    expect(Object.keys(byName).sort()).toEqual(["describe_table", "list_tables", "run_code"]);

    expect(byName.run_code!.annotations?.readOnlyHint).toBe(false);
    expect(byName.run_code!.annotations?.openWorldHint).toBe(true);
    expect(byName.describe_table!.annotations?.readOnlyHint).toBe(true);
    expect(byName.list_tables!.annotations?.readOnlyHint).toBe(true);
  });

  it("run_code accepts the documented input schema and round-trips through the handler", async () => {
    const client = await connect();
    const res = await client.callTool({ name: "run_code", arguments: { code: "async () => 1", mode: "read_only" } });
    expect((res.content as { type: string; text: string }[])[0]!.text).toBe("ran:13");
  });

  it("rejects an unknown mode enum value at the schema boundary", async () => {
    const client = await connect();
    // The SDK validates against the Zod inputSchema and returns an error result.
    const res = await client.callTool({ name: "run_code", arguments: { code: "async () => 1", mode: "root" } });
    expect(res.isError).toBe(true);
    expect((res.content as { type: string; text: string }[])[0]!.text).toMatch(/read_only|write|admin_script/);
  });
});
