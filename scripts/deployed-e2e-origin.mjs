import { readFileSync } from "node:fs";

export function readDevVarFromText(text, key) {
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line.startsWith(`${key}=`)) continue;
    let value = line.slice(key.length + 1).trim();
    if (value.startsWith('"')) {
      const end = value.indexOf('"', 1);
      value = end >= 1 ? value.slice(1, end) : value.slice(1);
    } else {
      const comment = value.search(/\s#/);
      if (comment >= 0) value = value.slice(0, comment).trim();
    }
    return value === "" ? undefined : value;
  }
  return undefined;
}

export function readDevVar(key) {
  let text;
  try {
    text = readFileSync(".dev.vars", "utf8");
  } catch {
    return undefined;
  }
  return readDevVarFromText(text, key);
}

export function canonicalHttpsOrigin(raw, label) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`${label} must be a canonical HTTPS origin.`);
  }
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  ) {
    throw new Error(`${label} must be a canonical HTTPS origin.`);
  }
  return url.origin;
}

export function resolveDeployedE2eConfig({ argvBase, env, devVar }) {
  const configuredRaw = env.WORKER_PUBLIC_ORIGIN ?? devVar("WORKER_PUBLIC_ORIGIN");
  const authMode = env.AUTH_MODE ?? devVar("AUTH_MODE") ?? "operator_secret";
  const deploymentProfile = env.DEPLOYMENT_PROFILE ?? devVar("DEPLOYMENT_PROFILE") ?? "pilot";
  if (deploymentProfile === "production" || authMode !== "operator_secret") {
    throw new Error("scripts/deployed-e2e.mjs is pilot-only for the operator-secret consent flow; production AUTH_MODE=oidc needs a separate IdP-backed E2E gate.");
  }
  const selectedRaw = argvBase ?? configuredRaw;
  if (!selectedRaw) {
    throw new Error("usage: node scripts/deployed-e2e.mjs <pilot-worker-base-url>   (or set WORKER_PUBLIC_ORIGIN in env or .dev.vars)");
  }
  if (!configuredRaw) {
    throw new Error("WORKER_PUBLIC_ORIGIN is required before pilot deployed E2E can use MCP_OPERATOR_SECRET.");
  }
  const configuredOrigin = canonicalHttpsOrigin(configuredRaw, "WORKER_PUBLIC_ORIGIN");
  const selectedOrigin = canonicalHttpsOrigin(selectedRaw, "worker base URL");
  if (selectedOrigin !== configuredOrigin) {
    throw new Error("Refusing to send MCP_OPERATOR_SECRET to a base URL that does not match WORKER_PUBLIC_ORIGIN.");
  }
  return {
    base: selectedOrigin,
    operatorSecret: env.MCP_OPERATOR_SECRET ?? devVar("MCP_OPERATOR_SECRET"),
  };
}
