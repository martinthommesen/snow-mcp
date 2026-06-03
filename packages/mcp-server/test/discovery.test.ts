import { describe, expect, it } from "vitest";
import { describeTable, listTables, type DiscoveryDeps } from "../src/sn/discovery.js";
import { permissivePolicy, type ActorPolicy } from "../src/authz/actor-policy.js";
import { RunBudget } from "../src/sn/run-budget.js";
import type { SnHttpClient, SnRequest, SnResponse } from "../src/sn/http.js";
import { McpToolError } from "../src/sn/errors.js";
import { TABLE_PAGE_CAP } from "../src/config.js";

const INSTANCE = "inst1.service-now.com";

class MockHttp implements SnHttpClient {
  calls: SnRequest[] = [];
  constructor(private readonly responder?: (req: SnRequest) => SnResponse) {}
  async request(req: SnRequest): Promise<SnResponse> {
    this.calls.push(req);
    if (this.responder) return this.responder(req);
    if (req.path === "/api/now/table/sys_dictionary") {
      return {
        status: 200,
        json: { result: [
          { element: "number", column_label: "Number", internal_type: "string", mandatory: "true", max_length: "40" },
          { element: "caller_id", column_label: "Caller", internal_type: "reference", mandatory: "false", max_length: "32", "reference.name": "sys_user" },
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
    const caller = fields.find((f) => f.name === "caller_id");
    expect(caller).toMatchObject({ mandatory: false, referenceTable: "sys_user", maxLength: 32 });
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

  it("drops a malicious super_class.name from the nameIN chain (re-validation is load-bearing)", async () => {
    // tableHierarchy re-validates each parent's super_class.name before it enters the
    // `nameIN${chain.map(esc).join(",")}` join. `esc` strips ^/= but NOT commas, so a
    // malicious parent like "evil,sys_user" would comma-inject the describe query if the
    // TABLE_NAME_RE re-validation were absent.
    const http = new MockHttp((req) => {
      if (req.path === "/api/now/table/sys_db_object") {
        return { status: 200, json: { result: [{ "super_class.name": "evil,sys_user" }] } };
      }
      return { status: 200, json: { result: [] } }; // sys_dictionary describe fetch
    });
    await describeTable(deps(http), "incident");
    const describeCall = http.calls.find((c) => c.path === "/api/now/table/sys_dictionary");
    expect(describeCall).toBeDefined();
    const q = describeCall!.query!.sysparm_query;
    // The malicious parent is dropped: only the validated root remains in the chain.
    expect(q).toBe("nameINincident^elementISNOTEMPTY");
    expect(q).not.toContain("sys_user");
  });

  it("throws table_not_found for a missing table when integration_user can read sys_db_object", async () => {
    const http = new MockHttp((req) => {
      if (req.path === "/api/now/table/sys_db_object") return { status: 200, json: { result: [] } };
      return { status: 200, json: { result: [] } };
    });
    await expect(describeTable(deps(http), "incident")).rejects.toMatchObject({ code: "table_not_found" });
  });

  it("throws table_not_found consistently under per_user_oauth", async () => {
    const http = new MockHttp((req) => {
      if (req.path === "/api/now/table/sys_db_object") return { status: 200, json: { result: [] } };
      return { status: 200, json: { result: [] } };
    });
    await expect(describeTable({ ...deps(http), credentialMode: "per_user_oauth" }, "incident")).rejects.toMatchObject({
      code: "table_not_found",
    });
  });
});

describe("list_tables", () => {
  it("returns name/label pairs and drops ActorPolicy-denied tables", async () => {
    const policy: ActorPolicy = { ...permissivePolicy([INSTANCE]), tables: { deny: [/^sys_user$/] } };
    const { tables, partial, total } = await listTables(deps(new MockHttp(), policy), "inc");
    expect(tables).toContainEqual({ name: "incident", label: "Incident" });
    expect(tables.some((t) => t.name === "sys_user")).toBe(false);
    expect(partial).toBe(false);
    expect(total).toBeUndefined();
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

  it("returns precise partial metadata and non-leaking X-Total-Count when no table policy filters apply", async () => {
    const rows = Array.from({ length: TABLE_PAGE_CAP }, (_, i) => ({ name: `u_table_${i}`, label: `Table ${i}` }));
    const http = new MockHttp((req) => {
      if (req.path === "/api/now/table/sys_db_object") {
        return { status: 200, json: { result: rows }, headers: { "x-total-count": "1234" } };
      }
      return { status: 200, json: { result: [] } };
    });
    const out = await listTables(deps(http));
    expect(out.tables).toHaveLength(TABLE_PAGE_CAP);
    expect(out.partial).toBe(true);
    expect(out.total).toBe(1234);
  });

  it("does not mark the exact page boundary partial when X-Total-Count confirms there are no more rows", async () => {
    const rows = Array.from({ length: TABLE_PAGE_CAP }, (_, i) => ({ name: `u_table_${i}`, label: `Table ${i}` }));
    const http = new MockHttp((req) => {
      if (req.path === "/api/now/table/sys_db_object") {
        return { status: 200, json: { result: rows }, headers: { "x-total-count": String(TABLE_PAGE_CAP) } };
      }
      return { status: 200, json: { result: [] } };
    });
    const out = await listTables(deps(http));
    expect(out.tables).toHaveLength(TABLE_PAGE_CAP);
    expect(out.partial).toBe(false);
    expect(out.total).toBe(TABLE_PAGE_CAP);
  });

  it("omits X-Total-Count when table allow/deny policy would filter the raw ServiceNow count", async () => {
    const http = new MockHttp((req) => {
      if (req.path === "/api/now/table/sys_db_object") {
        return {
          status: 200,
          json: { result: [{ name: "incident", label: "Incident" }, { name: "sys_user", label: "User" }] },
          headers: { "x-total-count": "2" },
        };
      }
      return { status: 200, json: { result: [] } };
    });
    const out = await listTables(deps(http, { ...permissivePolicy([INSTANCE]), tables: { allow: [/^incident$/] } }));
    expect(out.tables).toEqual([{ name: "incident", label: "Incident" }]);
    expect(out.total).toBeUndefined();
  });
});
