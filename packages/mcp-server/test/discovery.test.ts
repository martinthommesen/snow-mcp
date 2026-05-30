import { describe, expect, it } from "vitest";
import { describeTable, listTables, type DiscoveryDeps } from "../src/sn/discovery.js";
import { permissivePolicy, type ActorPolicy } from "../src/authz/actor-policy.js";
import { RunBudget } from "../src/sn/run-budget.js";
import type { SnHttpClient, SnRequest, SnResponse } from "../src/sn/http.js";
import { McpToolError } from "../src/sn/errors.js";

const INSTANCE = "inst1.service-now.com";

class MockHttp implements SnHttpClient {
  calls: SnRequest[] = [];
  async request(req: SnRequest): Promise<SnResponse> {
    this.calls.push(req);
    if (req.path === "/api/now/table/sys_dictionary") {
      return {
        status: 200,
        json: { result: [
          { element: "number", column_label: "Number", internal_type: "string", mandatory: "true", max_length: "40" },
          { element: "caller_id", column_label: "Caller", internal_type: "reference", mandatory: "false", max_length: "32" },
        ] },
      };
    }
    if (req.path === "/api/now/table/sys_db_object") {
      return { status: 200, json: { result: [{ name: "incident", label: "Incident" }, { name: "sys_user", label: "User" }] } };
    }
    return { status: 200, json: { result: [] } };
  }
}

function deps(http: SnHttpClient, policy?: ActorPolicy): DiscoveryDeps {
  return { http, instanceHost: INSTANCE, effectiveMode: "read_only", actorPolicy: policy ?? permissivePolicy([INSTANCE]), runBudget: new RunBudget() };
}

describe("describe_table", () => {
  it("returns shaped field schema", async () => {
    const fields = await describeTable(deps(new MockHttp()), "incident");
    expect(fields).toContainEqual({ name: "number", label: "Number", type: "string", mandatory: true, maxLength: 40 });
    expect(fields.find((f) => f.name === "caller_id")?.mandatory).toBe(false);
  });

  it("hides ActorPolicy-masked fields from discovery", async () => {
    const policy: ActorPolicy = { ...permissivePolicy([INSTANCE]), fieldMasks: { incident: ["caller_id"] } };
    const fields = await describeTable(deps(new MockHttp(), policy), "incident");
    expect(fields.some((f) => f.name === "caller_id")).toBe(false);
    expect(fields.some((f) => f.name === "number")).toBe(true);
  });

  it("denies a table outside the actor's allowlist", async () => {
    const policy: ActorPolicy = { ...permissivePolicy([INSTANCE]), tables: { allow: [/^incident$/] } };
    await expect(describeTable(deps(new MockHttp(), policy), "sys_user")).rejects.toThrow(McpToolError);
  });
});

describe("list_tables", () => {
  it("returns name/label pairs and drops ActorPolicy-denied tables", async () => {
    const policy: ActorPolicy = { ...permissivePolicy([INSTANCE]), tables: { deny: [/^sys_user$/] } };
    const tables = await listTables(deps(new MockHttp(), policy), "inc");
    expect(tables).toContainEqual({ name: "incident", label: "Incident" });
    expect(tables.some((t) => t.name === "sys_user")).toBe(false);
  });

  it("sanitizes the filter value (no encoded-query injection)", async () => {
    const http = new MockHttp();
    await listTables(deps(http), "in^cident=evil");
    const q = http.calls[0]!.query!.sysparm_query;
    // The injected `^` and `=evil` are stripped from the VALUE; only our own `^OR`
    // structural separator remains.
    expect(q).not.toContain("=evil");
    expect(q).not.toContain("^cident");
    expect(q).toContain("LIKEincidentevil");
  });
});
