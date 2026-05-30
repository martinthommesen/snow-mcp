// LIVE verification of the host-side ServiceNowRPC read path + ActorPolicy + masking
// against the configured instance, run in NODE (workerd outbound fetch is blocked in
// this env; Node fetch works). Imports the COMPILED modules from dist/ — same code the
// Worker runs. Read-only; prints PASS/FAIL per check; never prints secrets/PII.
//
// Build dist first (`tsc -b`), then bundle+run via scripts/live-rpc-verify.sh.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { SnFetchClient } from "../packages/mcp-server/dist/sn/http.js";
import { ServiceNowRPC } from "../packages/mcp-server/dist/sn/rpc.js";
import { RunBudget } from "../packages/mcp-server/dist/sn/run-budget.js";
import { permissivePolicy } from "../packages/mcp-server/dist/authz/actor-policy.js";
import { describeTable, listTables } from "../packages/mcp-server/dist/sn/discovery.js";

function parseDotenv(path) {
  const out = {};
  for (const raw of readFileSync(path, "utf8").split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq < 0) continue;
    let v = line.slice(eq + 1).trim();
    if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
    out[line.slice(0, eq).trim()] = v;
  }
  return out;
}

const env = parseDotenv(process.env.DEV_VARS_PATH ?? resolve(process.cwd(), ".dev.vars"));
const host = env.SNOW_INSTANCE_HOST;
const auth = "Basic " + Buffer.from(`${env.SNOW_DEV_ROPC_USERNAME}:${env.SNOW_DEV_ROPC_PASSWORD}`).toString("base64");
const allowlist = { allowedHostSuffixes: ["service-now.com"] };

function rpc(mode, budget, policy) {
  const http = new SnFetchClient({ instanceHost: host, allowlist, getAuthorization: async () => auth, timeoutMs: 20000 });
  return new ServiceNowRPC({ http, instanceHost: host, effectiveMode: mode, actorPolicy: policy ?? permissivePolicy([host]), runBudget: budget });
}

let passed = 0, failed = 0;
function check(name, cond) {
  if (cond) { passed++; console.log(`  PASS  ${name}`); }
  else { failed++; console.log(`  FAIL  ${name}`); }
}

console.log(`LIVE RPC verify against ${host}\n`);

// 1) tableQuery — real rows, requested fields, sys_id always present.
{
  const r = await rpc("read_only", new RunBudget()).tableQuery({ table: "incident", fields: ["number", "short_description"], limit: 2 });
  check("tableQuery returns rows", Array.isArray(r.rows) && r.rows.length > 0);
  check("rows carry INC numbers", typeof r.rows[0]?.number === "string" && r.rows[0].number.startsWith("INC"));
  check("sys_id injected internally (§1.7)", r.rows[0]?.sys_id !== undefined);
}

// 2) aggregate — real count.
{
  const stats = await rpc("read_only", new RunBudget()).aggregate({ table: "incident" });
  const count = Number(stats?.stats?.count);
  check("aggregate count is a finite number", Number.isFinite(count));
  console.log(`        (incident count = ${count})`);
}

// 3) ActorPolicy denies a non-allowlisted table BEFORE the live call (B5).
{
  const policy = { allowedInstances: [host], tables: { allow: [/^incident$/] }, fieldMasks: {}, maxMode: "read_only", maxRowsPerRun: 1000, maxBytesPerRun: 1e6 };
  let denied = false;
  try { await rpc("read_only", new RunBudget(), policy).tableQuery({ table: "sys_user" }); }
  catch (e) { denied = /not allowed/i.test(String(e?.message)); }
  check("ActorPolicy denies sys_user (B5)", denied);
}

// 4) Response field masking strips a forbidden field from the LIVE response.
{
  const policy = { allowedInstances: [host], tables: {}, fieldMasks: { incident: ["short_description"] }, maxMode: "read_only", maxRowsPerRun: 1000, maxBytesPerRun: 1e6 };
  const r = await rpc("read_only", new RunBudget(), policy).tableQuery({ table: "incident", limit: 1 });
  check("masked field absent from response", r.rows[0] && r.rows[0].short_description === undefined && r.rows[0].number !== undefined);
}

// 5) Capability gate: read_only cannot write (no mutation reaches LIVE).
{
  let denied = false;
  try {
    await rpc("read_only", new RunBudget()).tableUpdate({ table: "incident", sys_id: "doesnotmatter", fields: { state: 7 }, idempotencyKey: "k" });
  } catch (e) { denied = /not permitted/i.test(String(e?.message)); }
  check("read_only cannot tableUpdate (capability_denied)", denied);
}

// 6) describe_table — real field schema from sys_dictionary.
{
  const http = new SnFetchClient({ instanceHost: host, allowlist, getAuthorization: async () => auth, timeoutMs: 20000 });
  const deps = { http, instanceHost: host, effectiveMode: "read_only", actorPolicy: permissivePolicy([host]), runBudget: new RunBudget() };
  const fields = await describeTable(deps, "incident");
  const byName = new Map(fields.map((f) => [f.name, f]));
  check("describe_table(incident) returns fields", fields.length > 10);
  check("describe_table includes 'number' with a type", byName.has("number") && !!byName.get("number").type);
  console.log(`        (incident has ${fields.length} fields)`);
}

// 7) list_tables — filtered table list from sys_db_object.
{
  const http = new SnFetchClient({ instanceHost: host, allowlist, getAuthorization: async () => auth, timeoutMs: 20000 });
  const deps = { http, instanceHost: host, effectiveMode: "read_only", actorPolicy: permissivePolicy([host]), runBudget: new RunBudget() };
  const tables = await listTables(deps, "incident");
  check("list_tables('incident') finds the incident table", tables.some((t) => t.name === "incident"));
  console.log(`        (matched ${tables.length} tables)`);
}

console.log(`\n${failed === 0 ? "LIVE RPC VERIFY: ALL PASS" : "LIVE RPC VERIFY: FAILURES"} — ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
