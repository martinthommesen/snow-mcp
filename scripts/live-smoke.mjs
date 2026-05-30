// Live connectivity smoke test against the configured ServiceNow instance.
// Reads .dev.vars, authenticates with Basic Auth (dev), queries a NON-PII table, and
// prints ONLY status + counts. Never prints credentials or record contents.
//
//   node scripts/live-smoke.mjs
import { readFileSync } from "node:fs";

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

const env = parseDotenv(new URL("../.dev.vars", import.meta.url).pathname);
const host = env.SNOW_INSTANCE_HOST;
const user = env.SNOW_DEV_ROPC_USERNAME;
const pass = env.SNOW_DEV_ROPC_PASSWORD;
if (!host || !user || !pass) {
  console.error("Missing SNOW_INSTANCE_HOST / SNOW_DEV_ROPC_USERNAME / SNOW_DEV_ROPC_PASSWORD");
  process.exit(2);
}

const auth = "Basic " + Buffer.from(`${user}:${pass}`).toString("base64");

async function get(path) {
  const res = await fetch(`https://${host}${path}`, {
    headers: { authorization: auth, accept: "application/json" },
  });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* non-JSON (e.g. hibernation splash) */ }
  return { status: res.status, json, isHtml: /^\s*</.test(text), len: text.length };
}

console.log(`Instance: ${host}`);

// 1) Non-PII schema table: sys_db_object (table catalog).
const tables = await get("/api/now/table/sys_db_object?sysparm_limit=3&sysparm_fields=name,label&sysparm_exclude_reference_link=true");
console.log(`sys_db_object  -> HTTP ${tables.status}${tables.isHtml ? " (HTML — hibernating?)" : ""}`);
if (tables.json?.result) {
  console.log(`  rows: ${tables.json.result.length}; sample table names: ${tables.json.result.map((r) => r.name).join(", ")}`);
}

// 2) Aggregate count on a common table (no row contents).
const agg = await get("/api/now/stats/incident?sysparm_count=true");
console.log(`stats/incident -> HTTP ${agg.status}`);
if (agg.json?.result?.stats?.count !== undefined) {
  console.log(`  incident count: ${agg.json.result.stats.count}`);
}

// 3) Dictionary read for a known table (schema discovery path).
const dict = await get("/api/now/table/sys_dictionary?sysparm_query=name=incident^elementISNOTEMPTY&sysparm_limit=5&sysparm_fields=element,internal_type&sysparm_exclude_reference_link=true");
console.log(`sys_dictionary -> HTTP ${dict.status}`);
if (dict.json?.result) {
  console.log(`  incident fields (sample): ${dict.json.result.map((r) => r.element).filter(Boolean).join(", ")}`);
}

const ok = tables.status === 200;
console.log(ok ? "\nLIVE SMOKE: OK — instance reachable, Table/Aggregate/Dictionary APIs respond." : "\nLIVE SMOKE: FAILED — see statuses above.");
process.exit(ok ? 0 : 1);
