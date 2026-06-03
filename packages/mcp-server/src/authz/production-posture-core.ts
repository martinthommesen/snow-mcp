type Mode = "read_only" | "write" | "admin_script";

export type DeploymentProfile = "pilot" | "production";

export interface PostureEnv {
  DEPLOYMENT_PROFILE?: string;
  AUTH_MODE?: string;
  ALLOW_ADMIN_SCRIPT_CEILING?: string;
  SERVICENOW_CREDENTIAL_MODE?: string;
  SNOW_OAUTH_CLIENT_ID?: string;
  SNOW_OAUTH_CLIENT_SECRET?: string;
  WORKER_PUBLIC_ORIGIN?: string;
  MCP_OPERATOR_SECRET?: string;
  MCP_OPERATOR_USER_ID?: string;
  TOKEN_KEK?: string;
  TOKEN_KEK_CURRENT?: string;
  OAUTH_PROVIDER_SECRET?: string;
  X_MCP_EXECUTOR_HMAC_KEY?: string;
  SNAPSHOT_ENABLED_TABLES?: string;
  SNAPSHOT_KV?: unknown;
  SNAPSHOT_KEK?: string;
  SNAPSHOT_KEK_CURRENT?: string;
  ALLOW_LOCALHOST?: string;
  ALLOWED_ORIGINS?: string;
  SNOW_INSTANCE_HOST?: string;
  SNOW_EXECUTOR_PATH?: string;
  SNOW_DEV_ROPC?: string;
  TENANT_MAX_MODE?: Mode | string;
  INSTANCE_MAX_MODE?: Mode | string;
  LOADER?: unknown;
  AUDIT_KV?: unknown;
  OAUTH_KV?: unknown;
  AUTH_DO?: unknown;
  TOKEN_DO?: unknown;
  BUDGET_DO?: unknown;
  LEDGER_DO?: unknown;
  CONSENT_RATE_DO?: unknown;
  ACTOR_POLICY_TABLE_ALLOWLIST?: string;
  ACTOR_POLICY_FIELD_MASKS?: string;
  ACTOR_POLICY_ROW_FILTERS?: string;
  ACTOR_POLICY_MAX_ROWS_PER_RUN?: string;
  ACTOR_POLICY_MAX_BYTES_PER_RUN?: string;
  ACTOR_POLICY_MAX_MODE?: Mode | string;
  ACTOR_POLICIES_JSON?: string;
  OIDC_ISSUER?: string;
  OIDC_CLIENT_ID?: string;
  OIDC_CLIENT_SECRET?: string;
  OIDC_GROUP_POLICY_MAP?: string;
  OIDC_DEFAULT_POLICY_NAME?: string;
}

export class ProductionPostureError extends Error {
  readonly violations: string[];

  constructor(violations: string[]) {
    super(`Production posture violations:\n- ${violations.join("\n- ")}`);
    this.name = "ProductionPostureError";
    this.violations = violations;
  }
}

const coreBindings = [
  "AUDIT_KV",
  "BUDGET_DO",
  "LEDGER_DO",
  "OAUTH_KV",
  "AUTH_DO",
  "TOKEN_DO",
  "LOADER",
  "CONSENT_RATE_DO",
] as const satisfies readonly (keyof PostureEnv)[];

const modeSet = new Set(["read_only", "write", "admin_script"]);
const scopedExecutorPath = /^\/api\/(x|sn)_[a-z0-9_]+\/x_mcp\/executor\/run$/;
const actorPolicyTableNameRe = /^[a-z0-9_]{1,80}$/;
const actorPolicyFieldNameRe = /^[a-z0-9_.]{1,80}$/;
const onceCache = new WeakMap<object, true | ProductionPostureError>();
let warnedPilot = false;

export function parseDeploymentProfile(value: string | undefined): DeploymentProfile | undefined {
  const trimmed = value?.trim();
  if (trimmed === "pilot" || trimmed === "production") return trimmed;
  return undefined;
}

function isValidMode(value: unknown): value is Mode {
  return typeof value === "string" && modeSet.has(value);
}

function hasText(value: string | undefined): boolean {
  return value !== undefined && value.trim() !== "";
}

function isCanonicalHttpsOrigin(value: string | undefined): boolean {
  if (!hasText(value)) return false;
  try {
    const url = new URL(value!);
    return url.protocol === "https:" && !url.username && !url.password && url.pathname === "/" && url.search === "" && url.hash === "";
  } catch {
    return false;
  }
}

function isHttpsUrl(value: string | undefined): boolean {
  if (!hasText(value)) return false;
  try {
    return new URL(value!).protocol === "https:";
  } catch {
    return false;
  }
}

function csv(value: string | undefined): string[] {
  return (value ?? "").split(",").map((s) => s.trim()).filter(Boolean);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function looksLikeStrongSecret(secret: string): boolean {
  const s = secret.trim();
  const base64ish = /^[A-Za-z0-9+/_-]+={0,2}$/.test(s) && s.replace(/=+$/, "").length >= 43;
  const hexish = /^[0-9a-fA-F]+$/.test(s) && s.length >= 64;
  return base64ish || hexish;
}

function strongSecret(value: string | undefined): boolean {
  return hasText(value) && looksLikeStrongSecret(value!);
}

function requireStrongSecret(violations: string[], label: string, value: string | undefined): void {
  if (!strongSecret(value)) violations.push(`${label} must be a strong CSPRNG secret.`);
}

function base64ToBytes(value: string): Uint8Array {
  const bin = atob(value);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function decodeFixedBase64Secret(value: string | undefined, expectedBytes: number): void {
  const normalized = (value ?? "").trim();
  if (
    normalized.length === 0 ||
    !/^[A-Za-z0-9+/]*={0,2}$/.test(normalized) ||
    normalized.length % 4 === 1
  ) {
    throw new Error("invalid base64");
  }
  const padded = normalized.padEnd(normalized.length + (4 - (normalized.length % 4)) % 4, "=");
  if (base64ToBytes(padded).length !== expectedBytes) throw new Error("wrong length");
}

function validateModeCeiling(violations: string[], label: string, value: unknown, allowAdminScript: boolean): void {
  if (!isValidMode(value)) {
    violations.push(`${label} must be set to read_only or write in production.`);
    return;
  }
  if (value === "admin_script" && !allowAdminScript) {
    violations.push(`${label} must be set below admin_script unless ALLOW_ADMIN_SCRIPT_CEILING=true.`);
  }
}

function parseJsonObject(violations: string[], label: string, value: string | undefined): Record<string, unknown> | undefined {
  if (!hasText(value)) return undefined;
  try {
    const parsed = JSON.parse(value!);
    if (!isRecord(parsed)) {
      violations.push(`${label} must be a JSON object.`);
      return undefined;
    }
    return parsed;
  } catch {
    violations.push(`${label} must be valid JSON.`);
    return undefined;
  }
}

function hasActorPolicySetting(policy: Record<string, unknown>): boolean {
  return (
    hasText(typeof policy.ACTOR_POLICY_TABLE_ALLOWLIST === "string" ? policy.ACTOR_POLICY_TABLE_ALLOWLIST : undefined) ||
    hasText(typeof policy.ACTOR_POLICY_FIELD_MASKS === "string" ? policy.ACTOR_POLICY_FIELD_MASKS : undefined) ||
    hasText(typeof policy.ACTOR_POLICY_ROW_FILTERS === "string" ? policy.ACTOR_POLICY_ROW_FILTERS : undefined) ||
    policy.ACTOR_POLICY_MAX_ROWS_PER_RUN !== undefined ||
    policy.ACTOR_POLICY_MAX_BYTES_PER_RUN !== undefined ||
    policy.ACTOR_POLICY_MAX_MODE !== undefined
  );
}

function validateActorPolicyTableAllowlist(violations: string[], label: string, value: string | undefined): void {
  const tables = csv(value);
  if (hasText(value) && tables.length === 0) {
    violations.push(`${label} is set but contains no table names.`);
  }
  for (const table of tables) {
    if (!actorPolicyTableNameRe.test(table)) {
      violations.push(`${label} contains invalid table name "${table}".`);
    }
  }
}

function validateUniqueActorPolicyTable(violations: string[], label: string, seen: Set<string>, table: string, entry: string): boolean {
  if (!actorPolicyTableNameRe.test(table)) {
    violations.push(`${label} contains invalid table name "${table}" in entry "${entry}".`);
    return false;
  }
  if (seen.has(table)) {
    violations.push(`${label} contains duplicate table entry "${table}" in entry "${entry}".`);
    return false;
  }
  seen.add(table);
  return true;
}

function actorPolicyTableEntries(
  violations: string[],
  label: string,
  value: string | undefined,
  expectedShape: string,
): Array<{ entry: string; table: string; rawValue: string }> {
  const entries = (value ?? "").split(";").map((s) => s.trim()).filter(Boolean);
  if (hasText(value) && entries.length === 0) violations.push(`${label} is set but contains no entries.`);
  const parsed: Array<{ entry: string; table: string; rawValue: string }> = [];
  for (const entry of entries) {
    const idx = entry.indexOf(":");
    if (idx <= 0) {
      violations.push(`${label} entry must be "${expectedShape}", got "${entry}".`);
      continue;
    }
    parsed.push({ entry, table: entry.slice(0, idx).trim(), rawValue: entry.slice(idx + 1) });
  }
  return parsed;
}

function validateActorPolicyFieldMasks(violations: string[], label: string, value: string | undefined): void {
  const seen = new Set<string>();
  for (const { entry, table, rawValue } of actorPolicyTableEntries(violations, label, value, "table:field,field")) {
    const validTable = validateUniqueActorPolicyTable(violations, label, seen, table, entry);
    const fields = csv(rawValue);
    if (fields.length === 0) violations.push(`${label} entry must include at least one field, got "${entry}".`);
    if (validTable) {
      for (const field of fields) {
        if (!actorPolicyFieldNameRe.test(field)) {
          violations.push(`${label} contains invalid field name "${field}" in entry "${entry}".`);
        }
      }
    }
  }
}

function validateActorPolicyRowFilters(violations: string[], label: string, value: string | undefined): void {
  const seen = new Set<string>();
  for (const { entry, table, rawValue } of actorPolicyTableEntries(violations, label, value, "table:encoded_query")) {
    validateUniqueActorPolicyTable(violations, label, seen, table, entry);
    const filter = rawValue.trim();
    if (!filter) {
      violations.push(`${label} entry must include a non-empty encoded query, got "${entry}".`);
    } else if (hasActorPolicyStructuralOperator(filter)) {
      violations.push(`${label} contains a self-defeating structural operator.`);
    }
  }
}

function hasActorPolicyStructuralOperator(query: string): boolean {
  for (let i = 0; i < query.length; i++) {
    const atStart = i === 0;
    const afterCaret = query.charCodeAt(i) === 94; // ^
    if (!atStart && !afterCaret) continue;
    const tokenStart = afterCaret ? i + 1 : i;
    if (query.startsWith("ORDERBYDESC", tokenStart) || query.startsWith("ORDERBY", tokenStart)) continue;
    const op = query.slice(tokenStart, tokenStart + 2).toUpperCase();
    if (op === "OR" || op === "NQ" || op === "EQ") return true;
  }
  return false;
}

function validateActorPolicyPositiveInt(violations: string[], label: string, value: unknown): void {
  if (value === undefined) return;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1) violations.push(`${label} must be a positive integer.`);
}

function validateActorPolicyMode(violations: string[], label: string, value: unknown): void {
  if (value !== undefined && !isValidMode(value)) {
    violations.push(`${label} must be read_only, write, or admin_script.`);
  }
}

function validateActorPolicyEnv(violations: string[], label: string, policy: Record<string, unknown>): void {
  validateActorPolicyTableAllowlist(
    violations,
    `${label}.ACTOR_POLICY_TABLE_ALLOWLIST`,
    typeof policy.ACTOR_POLICY_TABLE_ALLOWLIST === "string" ? policy.ACTOR_POLICY_TABLE_ALLOWLIST : undefined,
  );
  validateActorPolicyFieldMasks(
    violations,
    `${label}.ACTOR_POLICY_FIELD_MASKS`,
    typeof policy.ACTOR_POLICY_FIELD_MASKS === "string" ? policy.ACTOR_POLICY_FIELD_MASKS : undefined,
  );
  validateActorPolicyRowFilters(
    violations,
    `${label}.ACTOR_POLICY_ROW_FILTERS`,
    typeof policy.ACTOR_POLICY_ROW_FILTERS === "string" ? policy.ACTOR_POLICY_ROW_FILTERS : undefined,
  );
  validateActorPolicyPositiveInt(violations, `${label}.ACTOR_POLICY_MAX_ROWS_PER_RUN`, policy.ACTOR_POLICY_MAX_ROWS_PER_RUN);
  validateActorPolicyPositiveInt(violations, `${label}.ACTOR_POLICY_MAX_BYTES_PER_RUN`, policy.ACTOR_POLICY_MAX_BYTES_PER_RUN);
  validateActorPolicyMode(violations, `${label}.ACTOR_POLICY_MAX_MODE`, policy.ACTOR_POLICY_MAX_MODE);
}

function validateActorPolicy(violations: string[], env: PostureEnv): Set<string> {
  const policyNames = new Set<string>(["default"]);
  const namedPolicies = parseJsonObject(violations, "ACTOR_POLICIES_JSON", env.ACTOR_POLICIES_JSON);
  const jsonDefault = namedPolicies?.default;
  const jsonDefaultAllowlist = isRecord(jsonDefault) && typeof jsonDefault.ACTOR_POLICY_TABLE_ALLOWLIST === "string"
    ? jsonDefault.ACTOR_POLICY_TABLE_ALLOWLIST
    : undefined;
  if (!hasText(env.ACTOR_POLICY_TABLE_ALLOWLIST) && !hasText(jsonDefaultAllowlist)) {
    violations.push("ActorPolicy default table allowlist must be set in production.");
  }
  validateActorPolicyEnv(violations, "ACTOR_POLICY", env as Record<string, unknown>);
  if (namedPolicies) {
    for (const name of Object.keys(namedPolicies)) {
      if (/^[a-zA-Z0-9_.-]{1,64}$/.test(name)) policyNames.add(name);
    }
  }
  if (!namedPolicies) return policyNames;
  for (const [name, policy] of Object.entries(namedPolicies)) {
    if (!/^[a-zA-Z0-9_.-]{1,64}$/.test(name)) {
      violations.push(`ACTOR_POLICIES_JSON contains invalid policy name "${name}".`);
      continue;
    }
    policyNames.add(name);
    if (!isRecord(policy)) {
      violations.push(`ACTOR_POLICIES_JSON.${name} must be a JSON object.`);
      continue;
    }
    if (!hasActorPolicySetting(policy)) {
      violations.push(`ACTOR_POLICIES_JSON.${name} must configure at least one ACTOR_POLICY_* setting.`);
    }
    const tableAllowlist = typeof policy.ACTOR_POLICY_TABLE_ALLOWLIST === "string" ? policy.ACTOR_POLICY_TABLE_ALLOWLIST : undefined;
    if (!hasText(tableAllowlist)) {
      violations.push(`ACTOR_POLICIES_JSON.${name}.ACTOR_POLICY_TABLE_ALLOWLIST must be set in production.`);
    }
    validateActorPolicyEnv(violations, `ACTOR_POLICIES_JSON.${name}`, policy);
  }
  return policyNames;
}

function validateOidcPolicyReferences(violations: string[], env: PostureEnv, policyNames: ReadonlySet<string>): void {
  const defaultPolicy = env.OIDC_DEFAULT_POLICY_NAME?.trim() || "default";
  const referenced = new Set<string>([defaultPolicy]);
  const groupMap = parseJsonObject(violations, "OIDC_GROUP_POLICY_MAP", env.OIDC_GROUP_POLICY_MAP);
  if (groupMap) {
    for (const [group, entry] of Object.entries(groupMap)) {
      let maxMode: unknown;
      let policyName = defaultPolicy;
      if (typeof entry === "string") {
        maxMode = entry;
      } else if (isRecord(entry)) {
        maxMode = entry.maxMode;
        if (typeof entry.policy === "string" && entry.policy.trim()) policyName = entry.policy.trim();
      } else {
        violations.push(`OIDC_GROUP_POLICY_MAP.${group} must be a mode string or JSON object.`);
        continue;
      }
      if (!isValidMode(maxMode)) {
        violations.push(`OIDC_GROUP_POLICY_MAP.${group}.maxMode must be read_only, write, or admin_script.`);
      }
      referenced.add(policyName);
    }
  }
  for (const policyName of referenced) {
    if (!policyNames.has(policyName)) {
      violations.push(`OIDC_GROUP_POLICY_MAP references unknown ActorPolicy "${policyName}".`);
    }
  }
}

function validatePinnedInstance(violations: string[], env: PostureEnv): void {
  if (!hasText(env.SNOW_INSTANCE_HOST)) {
    violations.push("SNOW_INSTANCE_HOST must be pinned in production.");
    return;
  }
  try {
    canonicalizeServiceNowHost(env.SNOW_INSTANCE_HOST!);
  } catch (e) {
    violations.push(`SNOW_INSTANCE_HOST is invalid: ${e instanceof Error ? e.message : String(e)}`);
  }
}

function canonicalizeServiceNowHost(input: string): string {
  const raw = input.trim();
  const candidate = raw.includes("://") ? raw : `https://${raw}`;
  const url = new URL(candidate);
  if (url.protocol !== "https:") throw new Error("instance host rejected: not_https");
  if (url.username !== "" || url.password !== "") throw new Error("instance host rejected: has_userinfo");
  if ((url.pathname !== "" && url.pathname !== "/") || url.search !== "" || url.hash !== "") {
    throw new Error("instance host rejected: has_path_query_or_fragment");
  }
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (host === "localhost" || host.startsWith("[") || /^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    throw new Error("instance host rejected: private_or_loopback");
  }
  if (!(host === "service-now.com" || host.endsWith(".service-now.com"))) {
    throw new Error("instance host rejected: not_allowlisted");
  }
  return host;
}

export function collectPostureViolations(env: PostureEnv): string[] {
  const violations: string[] = [];
  const profile = parseDeploymentProfile(env.DEPLOYMENT_PROFILE);
  if (!profile) {
    violations.push('DEPLOYMENT_PROFILE must be set to "pilot" or "production".');
  } else if (profile === "pilot") {
    return [];
  }

  const actorPolicyNames = validateActorPolicy(violations, env);

  if (env.SERVICENOW_CREDENTIAL_MODE !== "per_user_oauth") {
    violations.push('SERVICENOW_CREDENTIAL_MODE must be "per_user_oauth" in production.');
  }
  const authMode = env.AUTH_MODE?.trim() || "operator_secret";
  if (authMode !== "operator_secret" && authMode !== "oidc") {
    violations.push('AUTH_MODE must be "operator_secret" or "oidc".');
  }
  if (!hasText(env.SNOW_OAUTH_CLIENT_ID)) violations.push("SNOW_OAUTH_CLIENT_ID is required in production.");
  if (!hasText(env.SNOW_OAUTH_CLIENT_SECRET)) violations.push("SNOW_OAUTH_CLIENT_SECRET is required in production.");
  if (!hasText(env.WORKER_PUBLIC_ORIGIN)) {
    violations.push("WORKER_PUBLIC_ORIGIN is required in production.");
  } else if (!isCanonicalHttpsOrigin(env.WORKER_PUBLIC_ORIGIN)) {
    violations.push("WORKER_PUBLIC_ORIGIN must be a canonical HTTPS origin in production.");
  }
  if (authMode === "oidc") {
    if (hasText(env.MCP_OPERATOR_SECRET)) violations.push("MCP_OPERATOR_SECRET must be unset when AUTH_MODE=oidc.");
    if (!hasText(env.OIDC_ISSUER)) {
      violations.push("OIDC_ISSUER is required when AUTH_MODE=oidc.");
    } else if (!isHttpsUrl(env.OIDC_ISSUER)) {
      violations.push("OIDC_ISSUER must be an HTTPS URL when AUTH_MODE=oidc.");
    }
    if (!hasText(env.OIDC_CLIENT_ID)) violations.push("OIDC_CLIENT_ID is required when AUTH_MODE=oidc.");
    if (!hasText(env.OIDC_CLIENT_SECRET)) violations.push("OIDC_CLIENT_SECRET is required when AUTH_MODE=oidc.");
    if (!hasText(env.OIDC_GROUP_POLICY_MAP)) violations.push("OIDC_GROUP_POLICY_MAP is required when AUTH_MODE=oidc.");
    validateOidcPolicyReferences(violations, env, actorPolicyNames);
  } else {
    if (!hasText(env.MCP_OPERATOR_USER_ID)) violations.push("MCP_OPERATOR_USER_ID is required while operator-secret consent is active.");
    requireStrongSecret(violations, "MCP_OPERATOR_SECRET", env.MCP_OPERATOR_SECRET);
  }

  const allowAdminScript = env.ALLOW_ADMIN_SCRIPT_CEILING === "true";
  validateModeCeiling(violations, "TENANT_MAX_MODE", env.TENANT_MAX_MODE, allowAdminScript);
  validateModeCeiling(violations, "INSTANCE_MAX_MODE", env.INSTANCE_MAX_MODE, allowAdminScript);

  requireStrongSecret(violations, "TOKEN_KEK_CURRENT/TOKEN_KEK", env.TOKEN_KEK_CURRENT ?? env.TOKEN_KEK);
  requireStrongSecret(violations, "OAUTH_PROVIDER_SECRET", env.OAUTH_PROVIDER_SECRET);
  try {
    decodeFixedBase64Secret(env.X_MCP_EXECUTOR_HMAC_KEY, 32);
  } catch {
    violations.push("X_MCP_EXECUTOR_HMAC_KEY must decode to exactly 32 bytes.");
  }

  if (env.ALLOW_LOCALHOST === "true") violations.push('ALLOW_LOCALHOST must not be "true" in production.');
  if (csv(env.ALLOWED_ORIGINS).length === 0) {
    violations.push("ALLOWED_ORIGINS must include at least one origin in production.");
  }
  for (const binding of coreBindings) {
    if (!env[binding]) violations.push(`${binding} binding is required in production.`);
  }

  if (csv(env.SNAPSHOT_ENABLED_TABLES).length > 0) {
    if (!env.SNAPSHOT_KV) violations.push("SNAPSHOT_KV binding is required when SNAPSHOT_ENABLED_TABLES is set.");
    if (!strongSecret(env.SNAPSHOT_KEK_CURRENT ?? env.SNAPSHOT_KEK)) {
      violations.push("SNAPSHOT_KEK_CURRENT/SNAPSHOT_KEK must be a strong CSPRNG secret when SNAPSHOT_ENABLED_TABLES is set.");
    }
  }

  validatePinnedInstance(violations, env);
  if (hasText(env.SNOW_EXECUTOR_PATH) && !scopedExecutorPath.test(env.SNOW_EXECUTOR_PATH!.trim())) {
    violations.push("SNOW_EXECUTOR_PATH must be /api/(x|sn)_<scope>/x_mcp/executor/run when configured.");
  }
  if (env.SNOW_DEV_ROPC === "1") violations.push("SNOW_DEV_ROPC must be disabled in production.");

  return violations;
}

function warnPilotOnce(): void {
  if (warnedPilot) return;
  warnedPilot = true;
  console.warn(JSON.stringify({
    event: "production_posture_pilot",
    profile: "pilot",
    skippedChecks: [
      "restrictive_actor_policy",
      "per_user_oauth",
      "strong_secrets",
      "durable_bindings",
      "pinned_instance",
      "scoped_executor_path",
    ],
  }));
}

export function assertProductionPosture(env: PostureEnv): void {
  if (parseDeploymentProfile(env.DEPLOYMENT_PROFILE) === "pilot") {
    warnPilotOnce();
    return;
  }
  const violations = collectPostureViolations(env);
  if (violations.length > 0) throw new ProductionPostureError(violations);
}

export function assertProductionPostureOnce(env: PostureEnv): void {
  const cached = onceCache.get(env);
  if (cached === true) return;
  if (cached) throw cached;
  try {
    assertProductionPosture(env);
    onceCache.set(env, true);
  } catch (e) {
    if (e instanceof ProductionPostureError) {
      onceCache.set(env, e);
    }
    throw e;
  }
}
