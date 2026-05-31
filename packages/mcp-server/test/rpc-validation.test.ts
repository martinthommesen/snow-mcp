import { describe, expect, it } from "vitest";
import { ServiceNowRPC, type ServiceNowRpcDeps } from "../src/sn/rpc.js";
import { RunBudget } from "../src/sn/run-budget.js";
import {
  permissivePolicy,
  assertPolicyRowFiltersSafe,
  maskRow,
  assertRequestedFieldsAllowed,
  type ActorPolicy,
} from "../src/authz/actor-policy.js";
import { describeTable, type DiscoveryDeps } from "../src/sn/discovery.js";
import { validateReason } from "../src/sn/validate.js";
import { McpToolError } from "../src/sn/errors.js";
import type { SnHttpClient, SnRequest, SnResponse } from "../src/sn/http.js";

// ─── P1 — RPC input-validation boundary (closes findings 7/8/9 + comma-injection) ──
// transpileTs() does not type-check and the sandbox hands `unknown` values, so the RPC
// methods are the real trust boundary. These tests assert the NEW secure behavior and
// fail against the pre-P1 (unvalidated, unencoded) code.

const INSTANCE = "inst1.service-now.com";

class MockHttp implements SnHttpClient {
  calls: SnRequest[] = [];
  constructor(private readonly responder?: (req: SnRequest) => SnResponse) {}
  async request(req: SnRequest): Promise<SnResponse> {
    this.calls.push(req);
    if (this.responder) return this.responder(req);
    if (req.method === "GET" && req.path.startsWith("/api/now/table/incident")) {
      return { status: 200, json: { result: [{ sys_id: "a".repeat(32), number: "INC1" }] } };
    }
    if (req.method === "PATCH") return { status: 200, json: { result: { sys_id: "a".repeat(32) } } };
    return { status: 200, json: { result: [] } };
  }
}

function rpc(opts?: { http?: MockHttp; policy?: ActorPolicy }): { rpc: ServiceNowRPC; http: MockHttp } {
  const http = opts?.http ?? new MockHttp();
  const deps: ServiceNowRpcDeps = {
    http,
    instanceHost: INSTANCE,
    effectiveMode: "admin_script",
    actorPolicy: opts?.policy ?? permissivePolicy([INSTANCE]),
    runBudget: new RunBudget(),
  };
  return { rpc: new ServiceNowRPC(deps), http };
}

const HEX = "0".repeat(32);

describe("P1 — identifier validation rejects malformed input", () => {
  it("tableGet rejects a path-traversal sys_id (../sys_user/<id>)", async () => {
    const { rpc: r, http } = rpc();
    await expect(r.tableGet({ table: "incident", sys_id: `../sys_user/${HEX}` })).rejects.toMatchObject({
      code: "path_denied",
    });
    expect(http.calls.length).toBe(0); // rejected before any ServiceNow request
  });

  it("tableGet rejects a non-hex sys_id", async () => {
    const { rpc: r } = rpc();
    await expect(r.tableGet({ table: "incident", sys_id: "not-a-sys-id" })).rejects.toBeInstanceOf(McpToolError);
  });

  it("tableGet/tableQuery reject a table name with separators", async () => {
    const { rpc: r } = rpc();
    await expect(r.tableQuery({ table: "incident,sys_user" })).rejects.toMatchObject({ code: "path_denied" });
    await expect(r.tableGet({ table: "incident/../sys_user", sys_id: HEX })).rejects.toMatchObject({ code: "path_denied" });
  });

  it("tableQuery rejects a negative / NaN / non-integer / string limit", async () => {
    const { rpc: r } = rpc();
    for (const bad of [-1, NaN, 1.5, "10" as unknown as number]) {
      await expect(r.tableQuery({ table: "incident", limit: bad })).rejects.toMatchObject({ code: "path_denied" });
    }
  });

  it("tableQuery clamps an over-cap limit to TABLE_PAGE_CAP and still queries", async () => {
    const { rpc: r, http } = rpc();
    await r.tableQuery({ table: "incident", limit: 100_000 });
    expect(http.calls[0]!.query!.sysparm_limit).toBe("1000");
  });

  it("tableQuery rejects a malformed requested field name", async () => {
    const { rpc: r } = rpc();
    await expect(r.tableQuery({ table: "incident", fields: ["number", "bad field!"] })).rejects.toMatchObject({
      code: "path_denied",
    });
  });

  it("tableUpdate rejects update keys that are not strict field names (no dot-walk)", async () => {
    const { rpc: r } = rpc();
    await expect(
      r.tableUpdate({ table: "incident", sys_id: HEX, fields: { "caller_id.name": "x" }, idempotencyKey: "k1" }),
    ).rejects.toMatchObject({ code: "path_denied" });
    await expect(
      r.tableUpdate({ table: "incident", sys_id: HEX, fields: {}, idempotencyKey: "k1" }),
    ).rejects.toMatchObject({ code: "path_denied" });
  });

  it("tableUpdate rejects a bad idempotencyKey", async () => {
    const { rpc: r } = rpc();
    await expect(
      r.tableUpdate({ table: "incident", sys_id: HEX, fields: { state: 2 }, idempotencyKey: "bad key with spaces" }),
    ).rejects.toMatchObject({ code: "path_denied" });
  });

  it("runServerScript rejects an empty/non-string script (path_denied)", async () => {
    const { rpc: r } = rpc();
    await expect(
      r.runServerScript({ script: "", reason: "fix", idempotencyKey: "k1" }),
    ).rejects.toMatchObject({ code: "path_denied" });
    await expect(
      r.runServerScript({ script: 123 as unknown as string, reason: "fix", idempotencyKey: "k1" }),
    ).rejects.toMatchObject({ code: "path_denied" });
  });

  it("runServerScript rejects an empty reason (path_denied)", async () => {
    const { rpc: r } = rpc();
    await expect(
      r.runServerScript({ script: "gs.info('x');", reason: "", idempotencyKey: "k1" }),
    ).rejects.toMatchObject({ code: "path_denied" });
  });

  it("runServerScript rejects an over-1024-char reason (path_denied)", async () => {
    const { rpc: r } = rpc();
    await expect(
      r.runServerScript({ script: "gs.info('x');", reason: "a".repeat(1025), idempotencyKey: "k1" }),
    ).rejects.toMatchObject({ code: "path_denied" });
  });

  it("runServerScript rejects a control-char reason (path_denied)", async () => {
    const { rpc: r } = rpc();
    await expect(
      r.runServerScript({ script: "gs.info('x');", reason: "bad\u0000reason", idempotencyKey: "k1" }),
    ).rejects.toMatchObject({ code: "path_denied" });
  });

  it("runServerScript rejects a malformed idempotencyKey (path_denied)", async () => {
    const { rpc: r } = rpc();
    await expect(
      r.runServerScript({ script: "gs.info('x');", reason: "fix", idempotencyKey: "bad key with spaces" }),
    ).rejects.toMatchObject({ code: "path_denied" });
  });

  it("describeTable rejects a comma-injected table name", async () => {
    const deps: DiscoveryDeps = {
      http: new MockHttp(),
      instanceHost: INSTANCE,
      effectiveMode: "read_only",
      actorPolicy: permissivePolicy([INSTANCE]),
      runBudget: new RunBudget(),
    };
    await expect(describeTable(deps, "incident,sys_user")).rejects.toMatchObject({ code: "path_denied" });
  });

  it("happy path is unaffected: valid identifiers query the encoded canonical path", async () => {
    const { rpc: r, http } = rpc();
    const row = await r.tableGet({ table: "incident", sys_id: HEX, fields: ["number"] });
    expect(row).not.toBeNull();
    expect(http.calls[0]!.path).toBe(`/api/now/table/incident/${HEX}`);
  });
});

describe("P1 — structural-operator guard under a restrictive row filter", () => {
  const restrictive: ActorPolicy = {
    ...permissivePolicy([INSTANCE]),
    rowFilters: { incident: "active=true" },
  };

  it("rejects a caller query containing ^OR / ^NQ when a mandatory filter is active", async () => {
    const { rpc: r } = rpc({ policy: restrictive });
    await expect(r.tableQuery({ table: "incident", query: "priority=1^ORpriority=2" })).rejects.toMatchObject({
      code: "path_denied",
    });
    await expect(r.tableQuery({ table: "incident", query: "x^NQy" })).rejects.toMatchObject({ code: "path_denied" });
  });

  it("aggregate rejects a structural-operator query under a mandatory filter", async () => {
    const { rpc: r } = rpc({ policy: restrictive });
    await expect(r.aggregate({ table: "incident", query: "a=1^ORb=2" })).rejects.toMatchObject({ code: "path_denied" });
  });

  it("a benign caller query under a mandatory filter is AND-ed in, not rejected", async () => {
    const { rpc: r, http } = rpc({ policy: restrictive });
    await r.tableQuery({ table: "incident", query: "priority=1" });
    expect(http.calls[0]!.query!.sysparm_query).toBe("active=true^priority=1");
  });

  it("under the permissive policy (no rowFilters) a ^OR query is allowed", async () => {
    const { rpc: r } = rpc(); // permissive
    await expect(r.tableQuery({ table: "incident", query: "a=1^ORb=2" })).resolves.toBeDefined();
  });
});

describe("P1 — aggregate masks grouped/counted fields", () => {
  const masked: ActorPolicy = {
    ...permissivePolicy([INSTANCE]),
    fieldMasks: { incident: ["u_ssn"] },
  };

  it("rejects grouping by a masked field", async () => {
    const { rpc: r } = rpc({ policy: masked });
    await expect(r.aggregate({ table: "incident", groupBy: ["u_ssn"] })).rejects.toMatchObject({
      code: "actor_policy_denied",
    });
  });

  it("rejects counting a masked field", async () => {
    const { rpc: r } = rpc({ policy: masked });
    await expect(r.aggregate({ table: "incident", countField: "u_ssn" })).rejects.toMatchObject({
      code: "actor_policy_denied",
    });
  });
});

describe("P1 — dot-aware field masking (request AND response)", () => {
  const policy: ActorPolicy = {
    ...permissivePolicy([INSTANCE]),
    fieldMasks: { incident: ["caller_id"] },
  };

  it("maskRow strips dot-walked descendants of a masked field", () => {
    const row = { number: "INC1", caller_id: "u9", "caller_id.name": "Ada", "caller_id.value": "u9" };
    expect(maskRow(policy, "incident", row)).toEqual({ number: "INC1" });
  });

  it("assertRequestedFieldsAllowed denies a dot-walk request for a masked field", () => {
    expect(() => assertRequestedFieldsAllowed(policy, "incident", ["caller_id.name"])).toThrow(McpToolError);
    expect(() => assertRequestedFieldsAllowed(policy, "incident", ["number"])).not.toThrow();
  });

  it("tableUpdate denies writing a masked field (mask applies to writes too)", async () => {
    const { rpc: r } = rpc({ policy });
    await expect(
      r.tableUpdate({ table: "incident", sys_id: HEX, fields: { caller_id: "x" }, idempotencyKey: "k1" }),
    ).rejects.toMatchObject({ code: "actor_policy_denied" });
  });
});

describe("P1 — mandatory rowFilter load validation", () => {
  it("rejects a self-defeating mandatory filter that contains a structural operator", () => {
    const bad: ActorPolicy = { ...permissivePolicy([INSTANCE]), rowFilters: { incident: "active=true^ORactive=false" } };
    expect(() => assertPolicyRowFiltersSafe(bad)).toThrow();
  });

  it("accepts a sound mandatory filter", () => {
    const good: ActorPolicy = { ...permissivePolicy([INSTANCE]), rowFilters: { incident: "active=true" } };
    expect(() => assertPolicyRowFiltersSafe(good)).not.toThrow();
  });
});

describe("P1 — validateReason", () => {
  it("returns a valid reason unchanged", () => {
    expect(validateReason("fix incident per change ticket")).toBe("fix incident per change ticket");
    expect(validateReason("a".repeat(1024))).toBe("a".repeat(1024)); // boundary: exactly REASON_MAX
  });

  it("rejects an empty reason (path_denied)", () => {
    expect(() => validateReason("")).toThrow(McpToolError);
    try {
      validateReason("");
    } catch (e) {
      expect((e as McpToolError).code).toBe("path_denied");
    }
  });

  it("rejects an over-1024-char reason", () => {
    expect(() => validateReason("a".repeat(1025))).toThrow(McpToolError);
  });

  it("rejects a control-char reason", () => {
    expect(() => validateReason("bad\u0000reason")).toThrow(McpToolError);
    expect(() => validateReason("bad\u0007reason")).toThrow(McpToolError);
    expect(() => validateReason("bad\u007freason")).toThrow(McpToolError);
  });
});
