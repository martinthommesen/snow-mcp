// Alchemy IaC (plan §1, §2.11). Provisions the Worker + bindings on Cloudflare:
//   LOADER (Worker Loader), SCHEMA_KV + OAUTH_KV, four sqlite Durable Objects,
//   and the ServiceNow/crypto secrets. Run with:  npx alchemy deploy  (or destroy).
//
// Secrets are read from .dev.vars (gitignored) into process.env below. The scope
// password (for Alchemy's encrypted state) comes from OAUTH_PROVIDER_SECRET.
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import alchemy from "alchemy";
import { Worker, KVNamespace, DurableObjectNamespace, WorkerLoader } from "alchemy/cloudflare";

// --- load .dev.vars into process.env (no external dotenv dep) ---
const devVarsPath = fileURLToPath(new URL("./.dev.vars", import.meta.url));
if (existsSync(devVarsPath)) {
  for (const raw of readFileSync(devVarsPath, "utf8").split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    let v = line.slice(eq + 1).trim();
    if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
    if (process.env[key] === undefined) process.env[key] = v;
  }
}
function reqEnv(k: string): string {
  const v = process.env[k];
  if (!v) throw new Error(`Missing ${k} in environment/.dev.vars`);
  return v;
}

const app = await alchemy("servicenow-codemode-mcp", {
  password: process.env.OAUTH_PROVIDER_SECRET ?? "dev-state-password-change-me",
});

// Adopt the KV namespaces already created in the account (by title).
const SCHEMA_KV = await KVNamespace("SCHEMA_KV", { title: "servicenow-codemode-SCHEMA_KV", adopt: true });
const OAUTH_KV = await KVNamespace("OAUTH_KV", { title: "servicenow-codemode-OAUTH_KV", adopt: true });

export const worker = await Worker("servicenow-codemode-mcp", {
  // Explicit script name → clean URL `servicenow-mcp.<subdomain>.workers.dev`
  // (otherwise Alchemy derives `<app>-<resource>-<stage>`, hence the doubled mess).
  name: "servicenow-mcp",
  entrypoint: "./packages/mcp-server/src/index.ts",
  compatibilityDate: "2026-05-13",
  compatibilityFlags: ["nodejs_compat"],
  adopt: true,
  url: true,
  bindings: {
    LOADER: WorkerLoader(),
    SCHEMA_KV,
    OAUTH_KV,
    AUTH_DO: DurableObjectNamespace("AUTH_DO", { className: "AuthCorrelationDO", sqlite: true }),
    TOKEN_DO: DurableObjectNamespace("TOKEN_DO", { className: "TokenStoreDO", sqlite: true }),
    BUDGET_DO: DurableObjectNamespace("BUDGET_DO", { className: "BudgetDO", sqlite: true }),
    LEDGER_DO: DurableObjectNamespace("LEDGER_DO", { className: "MutationLedgerDO", sqlite: true }),

    // Non-sensitive config (plain bindings)
    SNOW_INSTANCE_HOST: reqEnv("SNOW_INSTANCE_HOST"),
    ...(process.env.SNOW_OAUTH_CLIENT_ID ? { SNOW_OAUTH_CLIENT_ID: process.env.SNOW_OAUTH_CLIENT_ID } : {}),
    ...(process.env.SNOW_EXECUTOR_PATH ? { SNOW_EXECUTOR_PATH: process.env.SNOW_EXECUTOR_PATH } : {}),

    // Secrets (encrypted in Alchemy state; uploaded as Worker secrets)
    MCP_OPERATOR_SECRET: alchemy.secret(reqEnv("MCP_OPERATOR_SECRET")),
    SNOW_DEV_ROPC_USERNAME: alchemy.secret(reqEnv("SNOW_DEV_ROPC_USERNAME")),
    SNOW_DEV_ROPC_PASSWORD: alchemy.secret(reqEnv("SNOW_DEV_ROPC_PASSWORD")),
    X_MCP_EXECUTOR_HMAC_KEY: alchemy.secret(reqEnv("X_MCP_EXECUTOR_HMAC_KEY")),
    TOKEN_KEK: alchemy.secret(reqEnv("TOKEN_KEK")),
    OAUTH_PROVIDER_SECRET: alchemy.secret(reqEnv("OAUTH_PROVIDER_SECRET")),
    ...(process.env.SNAPSHOT_KEK ? { SNAPSHOT_KEK: alchemy.secret(process.env.SNAPSHOT_KEK) } : {}),
    ...(process.env.SNOW_OAUTH_CLIENT_SECRET ? { SNOW_OAUTH_CLIENT_SECRET: alchemy.secret(process.env.SNOW_OAUTH_CLIENT_SECRET) } : {}),
  },
});

console.log(`Deployed: ${worker.url}`);
await app.finalize();
