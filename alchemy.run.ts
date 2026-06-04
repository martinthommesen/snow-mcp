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
// Explicit .ts extension: alchemy.run.ts is executed by node's native ESM loader (type-stripping),
// which — unlike esbuild/vitest — does NOT resolve an extensionless relative import.
import { operatorSecretBindings, parseDevVarLine, tokenKekBindings } from "./alchemy.bindings.ts";
import { assertProductionPosture, type PostureEnv } from "./packages/mcp-server/src/authz/production-posture-core.ts";

// --- load .dev.vars into process.env (no external dotenv dep) ---
const devVarsPath = fileURLToPath(new URL("./.dev.vars", import.meta.url));
if (existsSync(devVarsPath)) {
  for (const raw of readFileSync(devVarsPath, "utf8").split("\n")) {
    const parsed = parseDevVarLine(raw);
    if (!parsed) continue;
    const [key, value] = parsed;
    if (process.env[key] === undefined) process.env[key] = value;
  }
}
function reqEnv(k: string): string {
  const v = process.env[k];
  if (!v) throw new Error(`Missing ${k} in environment/.dev.vars`);
  return v;
}

if (process.env.DEPLOYMENT_PROFILE?.trim() !== "production") {
  throw new Error('Alchemy deploy requires DEPLOYMENT_PROFILE="production".');
}

const app = await alchemy("servicenow-codemode-mcp", {
  // Fail-closed (plan §P6a, finding 26): the Alchemy encrypted-state password MUST be the real
  // OAUTH_PROVIDER_SECRET — never a hardcoded dev default. reqEnv throws when it is unset,
  // matching the Worker-secret bindings below (which already fail closed via reqEnv).
  password: reqEnv("OAUTH_PROVIDER_SECRET"),
});

// Adopt the KV namespaces already created in the account (by title).
const SCHEMA_KV = await KVNamespace("SCHEMA_KV", { title: "servicenow-codemode-SCHEMA_KV", adopt: true });
const OAUTH_KV = await KVNamespace("OAUTH_KV", { title: "servicenow-codemode-OAUTH_KV", adopt: true });
// Host audit (§7.2) + recovery snapshots (§7.7). Created on first deploy (adopt: true).
const AUDIT_KV = await KVNamespace("AUDIT_KV", { title: "servicenow-codemode-AUDIT_KV", adopt: true });
const SNAPSHOT_KV = await KVNamespace("SNAPSHOT_KV", { title: "servicenow-codemode-SNAPSHOT_KV", adopt: true });

const bindings = {
  LOADER: WorkerLoader(),
  SCHEMA_KV,
  OAUTH_KV,
  AUDIT_KV,
  SNAPSHOT_KV,
  AUTH_DO: DurableObjectNamespace("AUTH_DO", { className: "AuthCorrelationDO", sqlite: true }),
  TOKEN_DO: DurableObjectNamespace("TOKEN_DO", { className: "TokenStoreDO", sqlite: true }),
  BUDGET_DO: DurableObjectNamespace("BUDGET_DO", { className: "BudgetDO", sqlite: true }),
  LEDGER_DO: DurableObjectNamespace("LEDGER_DO", { className: "MutationLedgerDO", sqlite: true }),
  // Consent-write rate limiter (finding 4 / CDX-4). MUST be declared here too — alchemy is the
  // production deploy path; without this the binding is unbound and the GET /authorize admission
  // cap silently no-ops in production (the handler guards on `if (env.CONSENT_RATE_DO)`).
  CONSENT_RATE_DO: DurableObjectNamespace("CONSENT_RATE_DO", { className: "ConsentRateDO", sqlite: true }),

  // Non-sensitive config (plain bindings)
  SNOW_INSTANCE_HOST: reqEnv("SNOW_INSTANCE_HOST"),
  ...(process.env.DEPLOYMENT_PROFILE ? { DEPLOYMENT_PROFILE: process.env.DEPLOYMENT_PROFILE } : {}),
  ...(process.env.ALLOW_ADMIN_SCRIPT_CEILING ? { ALLOW_ADMIN_SCRIPT_CEILING: process.env.ALLOW_ADMIN_SCRIPT_CEILING } : {}),
  ...(process.env.SNOW_EXECUTOR_VERIFIER_ATTESTED ? { SNOW_EXECUTOR_VERIFIER_ATTESTED: process.env.SNOW_EXECUTOR_VERIFIER_ATTESTED } : {}),
  ...(process.env.ALLOWED_ORIGINS ? { ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS } : {}),
  ...(process.env.WORKER_PUBLIC_ORIGIN ? { WORKER_PUBLIC_ORIGIN: process.env.WORKER_PUBLIC_ORIGIN } : {}),
  ...(process.env.SNOW_OAUTH_CLIENT_ID ? { SNOW_OAUTH_CLIENT_ID: process.env.SNOW_OAUTH_CLIENT_ID } : {}),
  ...(process.env.SNOW_EXECUTOR_PATH ? { SNOW_EXECUTOR_PATH: process.env.SNOW_EXECUTOR_PATH } : {}),
  ...(process.env.MCP_OPERATOR_USER_ID ? { MCP_OPERATOR_USER_ID: process.env.MCP_OPERATOR_USER_ID } : {}),
  ...(process.env.MCP_OPERATOR_EMAIL ? { MCP_OPERATOR_EMAIL: process.env.MCP_OPERATOR_EMAIL } : {}),
  ...(process.env.MCP_OPERATOR_ACCESS_GROUPS ? { MCP_OPERATOR_ACCESS_GROUPS: process.env.MCP_OPERATOR_ACCESS_GROUPS } : {}),
  ...(process.env.AUTH_MODE ? { AUTH_MODE: process.env.AUTH_MODE } : {}),
  ...(process.env.SNAPSHOT_ENABLED_TABLES ? { SNAPSHOT_ENABLED_TABLES: process.env.SNAPSHOT_ENABLED_TABLES } : {}),
  ...(process.env.ADMIN_SCRIPT_ALLOWLIST ? { ADMIN_SCRIPT_ALLOWLIST: process.env.ADMIN_SCRIPT_ALLOWLIST } : {}),
  ...(process.env.ADMIN_SCRIPT_REQUIRED_GROUP ? { ADMIN_SCRIPT_REQUIRED_GROUP: process.env.ADMIN_SCRIPT_REQUIRED_GROUP } : {}),
  ...(process.env.ACTOR_POLICY_TABLE_ALLOWLIST ? { ACTOR_POLICY_TABLE_ALLOWLIST: process.env.ACTOR_POLICY_TABLE_ALLOWLIST } : {}),
  ...(process.env.ACTOR_POLICY_FIELD_MASKS ? { ACTOR_POLICY_FIELD_MASKS: process.env.ACTOR_POLICY_FIELD_MASKS } : {}),
  ...(process.env.ACTOR_POLICY_ROW_FILTERS ? { ACTOR_POLICY_ROW_FILTERS: process.env.ACTOR_POLICY_ROW_FILTERS } : {}),
  ...(process.env.ACTOR_POLICY_MAX_ROWS_PER_RUN ? { ACTOR_POLICY_MAX_ROWS_PER_RUN: process.env.ACTOR_POLICY_MAX_ROWS_PER_RUN } : {}),
  ...(process.env.ACTOR_POLICY_MAX_BYTES_PER_RUN ? { ACTOR_POLICY_MAX_BYTES_PER_RUN: process.env.ACTOR_POLICY_MAX_BYTES_PER_RUN } : {}),
  ...(process.env.ACTOR_POLICY_MAX_MODE ? { ACTOR_POLICY_MAX_MODE: process.env.ACTOR_POLICY_MAX_MODE } : {}),
  ...(process.env.ACTOR_POLICIES_JSON ? { ACTOR_POLICIES_JSON: process.env.ACTOR_POLICIES_JSON } : {}),
  ...(process.env.OIDC_ISSUER ? { OIDC_ISSUER: process.env.OIDC_ISSUER } : {}),
  ...(process.env.OIDC_CLIENT_ID ? { OIDC_CLIENT_ID: process.env.OIDC_CLIENT_ID } : {}),
  ...(process.env.OIDC_SCOPES ? { OIDC_SCOPES: process.env.OIDC_SCOPES } : {}),
  ...(process.env.OIDC_GROUP_CLAIM ? { OIDC_GROUP_CLAIM: process.env.OIDC_GROUP_CLAIM } : {}),
  ...(process.env.OIDC_GROUP_POLICY_MAP ? { OIDC_GROUP_POLICY_MAP: process.env.OIDC_GROUP_POLICY_MAP } : {}),
  ...(process.env.OIDC_DEFAULT_POLICY_NAME ? { OIDC_DEFAULT_POLICY_NAME: process.env.OIDC_DEFAULT_POLICY_NAME } : {}),
  ...(process.env.GIT_COMMIT_SHA ? { GIT_COMMIT_SHA: process.env.GIT_COMMIT_SHA } : {}),
  ...(process.env.BUILD_TIMESTAMP ? { BUILD_TIMESTAMP: process.env.BUILD_TIMESTAMP } : {}),
  // Optional config knobs (P0; consumed in P5/P6). Plain bindings, never required.
  ...(process.env.SERVICENOW_CREDENTIAL_MODE ? { SERVICENOW_CREDENTIAL_MODE: process.env.SERVICENOW_CREDENTIAL_MODE } : {}),
  ...(process.env.ALLOW_LOCALHOST ? { ALLOW_LOCALHOST: process.env.ALLOW_LOCALHOST } : {}),
  ...(process.env.TENANT_MAX_MODE ? { TENANT_MAX_MODE: process.env.TENANT_MAX_MODE } : {}),
  ...(process.env.INSTANCE_MAX_MODE ? { INSTANCE_MAX_MODE: process.env.INSTANCE_MAX_MODE } : {}),
  ...(process.env.SNOW_DEV_ROPC ? { SNOW_DEV_ROPC: process.env.SNOW_DEV_ROPC } : {}),

  // Secrets (encrypted in Alchemy state; uploaded as Worker secrets)
  ...operatorSecretBindings(process.env, (v) => alchemy.secret(v)),
  ...(process.env.SNOW_DEV_ROPC === "1"
    ? {
        SNOW_DEV_ROPC_USERNAME: alchemy.secret(reqEnv("SNOW_DEV_ROPC_USERNAME")),
        SNOW_DEV_ROPC_PASSWORD: alchemy.secret(reqEnv("SNOW_DEV_ROPC_PASSWORD")),
      }
    : {}),
  X_MCP_EXECUTOR_HMAC_KEY: alchemy.secret(reqEnv("X_MCP_EXECUTOR_HMAC_KEY")),
  // Token KEK ring (P3): require TOKEN_KEK_CURRENT and pass TOKEN_KEK_PREV only during rotation.
  ...tokenKekBindings(process.env, (v) => alchemy.secret(v)),
  OAUTH_PROVIDER_SECRET: alchemy.secret(reqEnv("OAUTH_PROVIDER_SECRET")),
  ...(process.env.OIDC_CLIENT_SECRET ? { OIDC_CLIENT_SECRET: alchemy.secret(process.env.OIDC_CLIENT_SECRET) } : {}),
  ...(process.env.SNOW_OAUTH_CLIENT_SECRET ? { SNOW_OAUTH_CLIENT_SECRET: alchemy.secret(process.env.SNOW_OAUTH_CLIENT_SECRET) } : {}),
  ...(process.env.ADMIN_SCRIPT_APPROVAL_TOKENS ? { ADMIN_SCRIPT_APPROVAL_TOKENS: alchemy.secret(process.env.ADMIN_SCRIPT_APPROVAL_TOKENS) } : {}),
  // Versioned snapshot-KEK ring (P3). Optional until provisioned; never reqEnv yet so the
  // deploy doesn't break before they exist. (Token KEK ring is bound above via tokenKekBindings.)
  ...(process.env.SNAPSHOT_KEK_CURRENT ? { SNAPSHOT_KEK_CURRENT: alchemy.secret(process.env.SNAPSHOT_KEK_CURRENT) } : {}),
  ...(process.env.SNAPSHOT_KEK_PREV ? { SNAPSHOT_KEK_PREV: alchemy.secret(process.env.SNAPSHOT_KEK_PREV) } : {}),
};

// Binding-aware deploy posture check: KV/DO presence comes from the assembled bindings object,
// while secret strength is checked against the raw process env values before upload.
assertProductionPosture({
  ...bindings,
  MCP_OPERATOR_SECRET: process.env.MCP_OPERATOR_SECRET,
  X_MCP_EXECUTOR_HMAC_KEY: process.env.X_MCP_EXECUTOR_HMAC_KEY,
  TOKEN_KEK_CURRENT: process.env.TOKEN_KEK_CURRENT,
  OAUTH_PROVIDER_SECRET: process.env.OAUTH_PROVIDER_SECRET,
  OIDC_CLIENT_SECRET: process.env.OIDC_CLIENT_SECRET,
  SNAPSHOT_KEK_CURRENT: process.env.SNAPSHOT_KEK_CURRENT,
  SNOW_OAUTH_CLIENT_SECRET: process.env.SNOW_OAUTH_CLIENT_SECRET,
  ADMIN_SCRIPT_APPROVAL_TOKENS: process.env.ADMIN_SCRIPT_APPROVAL_TOKENS,
} as PostureEnv);

export const worker = await Worker("servicenow-codemode-mcp", {
  // Explicit script name → clean URL `servicenow-mcp.<subdomain>.workers.dev`
  // (otherwise Alchemy derives `<app>-<resource>-<stage>`, hence the doubled mess).
  name: "servicenow-mcp",
  entrypoint: "./packages/mcp-server/src/index.ts",
  compatibilityDate: "2026-05-13",
  compatibilityFlags: ["nodejs_compat"],
  adopt: true,
  url: true,
  bindings,
});

console.log(`Deployed: ${worker.url}`);
await app.finalize();
