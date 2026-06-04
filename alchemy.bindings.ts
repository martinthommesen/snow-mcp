// Pure, side-effect-free Worker secret-binding helpers for alchemy.run.ts. Kept in a separate
// module — it imports neither `alchemy` nor any node builtin and runs no top-level deploy — so
// the binding logic is unit-testable without triggering a deploy (alchemy.run.ts itself has a
// top-level `await alchemy(...)`; importing it to test bindings would attempt to provision).

import { parseAuthMode } from "@servicenow-codemode/shared";

export interface TokenKekEnv {
  TOKEN_KEK_CURRENT?: string;
  TOKEN_KEK_PREV?: string;
}

export interface OperatorSecretEnv {
  DEPLOYMENT_PROFILE?: string;
  AUTH_MODE?: string;
  MCP_OPERATOR_SECRET?: string;
}

export function parseDevVarLine(raw: string): [string, string] | undefined {
  const line = raw.trim();
  if (!line || line.startsWith("#")) return undefined;
  const eq = line.indexOf("=");
  if (eq < 0) return undefined;
  const key = line.slice(0, eq).trim();
  if (!key) return undefined;
  let value = line.slice(eq + 1).trim();
  let quote: string | undefined;
  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    if ((ch === '"' || ch === "'") && (i === 0 || value[i - 1] !== "\\")) {
      quote = quote === ch ? undefined : quote ?? ch;
      continue;
    }
    if (ch === "#" && quote === undefined && (i === 0 || /\s/.test(value[i - 1]!))) {
      value = value.slice(0, i).trim();
      break;
    }
  }
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    value = value.slice(1, -1);
  }
  return [key, value];
}

export function operatorSecretBindings<S>(env: OperatorSecretEnv, secret: (value: string) => S): Record<string, S> {
  if (env.DEPLOYMENT_PROFILE?.trim() === "production") return {};
  if (parseAuthMode(env.AUTH_MODE) === "oidc") return {};
  const operatorSecret = env.MCP_OPERATOR_SECRET;
  if (!operatorSecret) throw new Error("Missing MCP_OPERATOR_SECRET in environment/.dev.vars");
  return { MCP_OPERATOR_SECRET: secret(operatorSecret) };
}

/**
 * Build the token-KEK Worker secret bindings (P3 versioned ring). `TOKEN_KEK_CURRENT` is required;
 * `TOKEN_KEK_PREV` is accepted only during an active rotation window.
 */
export function tokenKekBindings<S>(env: TokenKekEnv, secret: (value: string) => S): Record<string, S> {
  const current = env.TOKEN_KEK_CURRENT?.trim() || undefined;
  if (!current) {
    throw new Error("Missing token KEK: set TOKEN_KEK_CURRENT in environment/.dev.vars");
  }
  const prev = env.TOKEN_KEK_PREV?.trim() || undefined;
  return {
    TOKEN_KEK_CURRENT: secret(current),
    ...(prev ? { TOKEN_KEK_PREV: secret(prev) } : {}),
  };
}
