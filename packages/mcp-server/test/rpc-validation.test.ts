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
import { validateReason, validateUserQuery, assertMandatoryRowFilterSafe } from "../src/sn/validate.js";
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
      r.tableUpdate({ table: "incident", sys_id: HEX, fields: { "caller_id.name": "x" } }),
    ).rejects.toMatchObject({ code: "path_denied" });
    await expect(
      r.tableUpdate({ table: "incident", sys_id: HEX, fields: {} }),
    ).rejects.toMatchObject({ code: "path_denied" });
  });

  it("runServerScript rejects an empty/non-string script (path_denied)", async () => {
    const { rpc: r } = rpc();
    await expect(
      r.runServerScript({ script: "" }),
    ).rejects.toMatchObject({ code: "path_denied" });
    await expect(
      r.runServerScript({ script: 123 as unknown as string }),
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

  // ─── P6b — token-boundary tightening: exact ^ORDERBY is benign, ^OR remains structural ──
  it("allows a ^ORDERBY / ^ORDERBYDESC ordering clause under a mandatory filter (AND-ed, not rejected)", async () => {
    const { rpc: r, http } = rpc({ policy: restrictive });
    await r.tableQuery({ table: "incident", query: "priority=1^ORDERBYnumber" });
    expect(http.calls[0]!.query!.sysparm_query).toBe("active=true^priority=1^ORDERBYnumber");
    await r.tableQuery({ table: "incident", query: "priority=1^ORDERBYDESCnumber" });
    expect(http.calls[1]!.query!.sysparm_query).toBe("active=true^priority=1^ORDERBYDESCnumber");
  });

  it("still rejects a genuine ^OR escape under a mandatory filter, in any case (reject-not-bypass)", async () => {
    const { rpc: r } = rpc({ policy: restrictive });
    await expect(r.tableQuery({ table: "incident", query: "priority=1^ORpriority=2" })).rejects.toMatchObject({
      code: "path_denied",
    });
    await expect(r.tableQuery({ table: "incident", query: "priority=1^orpriority=2" })).rejects.toMatchObject({
      code: "path_denied",
    });
    await expect(r.tableQuery({ table: "incident", query: "priority=1^ORderbyfield=2" })).rejects.toMatchObject({
      code: "path_denied",
    });
  });

  it("rejects leading structural operators before the mandatory filter is prepended", async () => {
    const { rpc: r } = rpc({ policy: restrictive });
    for (const query of ["NQpriority=1", "ORpriority=1", "EQ", "nqpriority=1"]) {
      await expect(r.tableQuery({ table: "incident", query })).rejects.toMatchObject({ code: "path_denied" });
      await expect(r.aggregate({ table: "incident", query })).rejects.toMatchObject({ code: "path_denied" });
    }
  });
});

describe("P1 — aggregate masks grouped fields", () => {
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
      r.tableUpdate({ table: "incident", sys_id: HEX, fields: { caller_id: "x" } }),
    ).rejects.toMatchObject({ code: "actor_policy_denied" });
  });
});

describe("P4 — mutating RPC methods require mutation safety wiring", () => {
  it("tableUpdate fails closed after validation/capability gates when mutation deps are absent", async () => {
    const { rpc: r, http } = rpc();
    await expect(
      r.tableUpdate({ table: "incident", sys_id: HEX, fields: { state: 2 } }),
    ).rejects.toMatchObject({ code: "internal_error" });
    expect(http.calls.filter((c) => c.method === "PATCH")).toHaveLength(0);
  });

  it("runServerScript fails closed before the executor POST when mutation deps are absent", async () => {
    const http = new MockHttp();
    const r = new ServiceNowRPC({
      http,
      instanceHost: INSTANCE,
      effectiveMode: "admin_script",
      actorPolicy: permissivePolicy([INSTANCE]),
      runBudget: new RunBudget(),
      signing: {
        claims: {
          mcp_actor_user_id: "operator",
          mcp_actor_email: "op@example.com",
          snow_effective_user_sys_id: "",
          instance: INSTANCE,
          request_id: "req-1",
        },
        hmacKey: new Uint8Array(32).fill(7),
        nonce: () => crypto.randomUUID(),
        now: () => 1_700_000_000_000,
      },
      executorPath: "/api/x_mcp/executor/run",
    });

    await expect(
      r.runServerScript({ script: "gs.info('x');" }),
    ).rejects.toMatchObject({ code: "internal_error" });
    expect(http.calls.filter((c) => c.method === "POST")).toHaveLength(0);
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

  it("P6b — validateUserQuery allows exact ^ORDERBY / ^ORDERBYDESC under a mandatory filter", () => {
    expect(validateUserQuery("ORDERBYnumber", true)).toBe("ORDERBYnumber");
    expect(validateUserQuery("priority=1^ORDERBYnumber", true)).toBe("priority=1^ORDERBYnumber");
    expect(validateUserQuery("priority=1^ORDERBYDESCnumber", true)).toBe("priority=1^ORDERBYDESCnumber");
    expect(validateUserQuery("^ORDERBYnumber", true)).toBe("^ORDERBYnumber");
  });

  it("P6b-2 — validateUserQuery rejects the ^OR / ^NQ / ^EQ escapes in ANY case (case-insensitive)", () => {
    for (const q of ["NQb", "ORb", "EQ", "a=1^ORb=2", "a^NQb", "a^EQ", "a=1^orb=2", "a^nqb", "a^eq", "a^ORderbyfield=1", "a^orderbynumber"]) {
      expect(() => validateUserQuery(q, true)).toThrow(McpToolError);
    }
  });

  it("P6b — assertMandatoryRowFilterSafe rejects ^OR variants but accepts exact ^ORDERBY", () => {
    expect(() => assertMandatoryRowFilterSafe("incident", "NQactive=false")).toThrow();
    expect(() => assertMandatoryRowFilterSafe("incident", "active=true^ORactive=false")).toThrow();
    expect(() => assertMandatoryRowFilterSafe("incident", "active=true^ORderbyfield=1")).toThrow();
    expect(() => assertMandatoryRowFilterSafe("incident", "active=true^ORDERBYnumber")).not.toThrow();
  });

  it("rejects a control-char reason", () => {
    expect(() => validateReason("bad\u0000reason")).toThrow(McpToolError);
    expect(() => validateReason("bad\u0007reason")).toThrow(McpToolError);
    expect(() => validateReason("bad\u007freason")).toThrow(McpToolError);
  });
});

// ─── H-1 — runServerScript enforces the ActorPolicy maxMode ceiling at the sink ───
// Regression test for the review's headline finding: the per-actor maxMode cap was enforced on
// every read/write (assertActorPolicy) but NOT on runServerScript, so an actor pinned to `write`
// could still run arbitrary admin script. The check must run at the dangerous sink, driven through
// the RPC — not merely asserted on assertActorPolicy in isolation (isolation-only is what hid it).
describe("H-1 — runServerScript respects ActorPolicy.maxMode", () => {
  const SCRIPT_ARGS = { script: "return gs.getUserName();" };

  it("DENIES admin_script when the actor's maxMode is write (the cap no longer fails open)", async () => {
    const { rpc: r, http } = rpc({ policy: { ...permissivePolicy([INSTANCE]), maxMode: "write" } });
    await expect(r.runServerScript(SCRIPT_ARGS)).rejects.toMatchObject({ code: "actor_policy_denied" });
    expect(http.calls.length).toBe(0); // denied before any executor request (and before signing)
  });

  it("DENIES admin_script when the actor's maxMode is read_only", async () => {
    const { rpc: r } = rpc({ policy: { ...permissivePolicy([INSTANCE]), maxMode: "read_only" } });
    await expect(r.runServerScript(SCRIPT_ARGS)).rejects.toMatchObject({ code: "actor_policy_denied" });
  });

  it("does NOT over-block: maxMode admin_script passes the ceiling (fails later on unconfigured executor, not policy)", async () => {
    // permissivePolicy.maxMode is admin_script and effectiveMode is admin_script -> the H-1 ceiling
    // check passes; the call then fails because signing/executorPath are unwired in this unit — a
    // DIFFERENT error, proving the policy gate itself did not deny.
    const { rpc: r } = rpc(); // permissive policy (maxMode admin_script)
    await expect(r.runServerScript(SCRIPT_ARGS)).rejects.toSatisfy(
      (e: unknown) => !(e instanceof McpToolError) || e.code !== "actor_policy_denied",
    );
  });
});

// ─── M-6 — field masks apply to the query predicate, not just requested fields ───
// A caller could filter ON a masked column without REQUESTING it (a row-selection / aggregate
// oracle) and reconstruct the masked value. The mask must reject masked-field references in the
// query — including TEXT operators (LIKE/IN/…), OR-clauses, ORDERBY, and dot-walk — without
// over-rejecting legitimately-named fields.
describe("M-6 — masked fields rejected in query predicates", () => {
  const maskedPolicy = (): ActorPolicy => ({ ...permissivePolicy([INSTANCE]), fieldMasks: { incident: ["salary", "caller_id"] } });

  it("DENIES tableQuery filtering on a masked field with a symbol operator", async () => {
    const { rpc: r, http } = rpc({ policy: maskedPolicy() });
    await expect(r.tableQuery({ table: "incident", query: "salary>500000", fields: ["number"] })).rejects.toMatchObject({
      code: "actor_policy_denied",
    });
    expect(http.calls.length).toBe(0); // rejected before the ServiceNow request
  });

  it("DENIES a masked field behind a TEXT operator (salaryLIKE5) — the parser must not stop at the field run", async () => {
    const { rpc: r } = rpc({ policy: maskedPolicy() });
    await expect(r.tableQuery({ table: "incident", query: "salaryLIKE5", fields: ["number"] })).rejects.toMatchObject({
      code: "actor_policy_denied",
    });
  });

  it("DENIES a masked field in an OR-clause and in ORDERBY", async () => {
    const { rpc: r } = rpc({ policy: maskedPolicy() });
    await expect(r.tableQuery({ table: "incident", query: "active=true^ORsalary>1", fields: ["number"] })).rejects.toMatchObject({ code: "actor_policy_denied" });
    await expect(r.tableQuery({ table: "incident", query: "active=true^ORDERBYsalary", fields: ["number"] })).rejects.toMatchObject({ code: "actor_policy_denied" });
  });

  it("DENIES a dot-walked masked reference (caller_id.name when caller_id is masked)", async () => {
    const { rpc: r } = rpc({ policy: maskedPolicy() });
    await expect(r.tableQuery({ table: "incident", query: "caller_id.name=Bob", fields: ["number"] })).rejects.toMatchObject({ code: "actor_policy_denied" });
  });

  it("DENIES a masked-field predicate in aggregate()", async () => {
    const { rpc: r } = rpc({ policy: maskedPolicy() });
    await expect(r.aggregate({ table: "incident", query: "salary>1", groupBy: ["state"] })).rejects.toMatchObject({ code: "actor_policy_denied" });
  });

  it("does NOT over-reject: a non-masked field, or a longer field that merely starts with the mask, is allowed", async () => {
    const { rpc: r, http } = rpc({ policy: maskedPolicy() });
    await expect(r.tableQuery({ table: "incident", query: "active=true", fields: ["number"] })).resolves.toBeDefined();
    // `salary_band` starts with `salary` but is a distinct field — must NOT be rejected.
    await expect(r.tableQuery({ table: "incident", query: "salary_band=high", fields: ["number"] })).resolves.toBeDefined();
    expect(http.calls.length).toBe(2); // both legitimate queries reached ServiceNow
  });
});
