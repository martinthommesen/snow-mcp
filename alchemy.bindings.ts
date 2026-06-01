// Pure, side-effect-free Worker secret-binding helpers for alchemy.run.ts. Kept in a separate
// module — it imports neither `alchemy` nor any node builtin and runs no top-level deploy — so
// the binding logic is unit-testable without triggering a deploy (alchemy.run.ts itself has a
// top-level `await alchemy(...)`; importing it to test bindings would attempt to provision).

export interface TokenKekEnv {
  TOKEN_KEK?: string;
  TOKEN_KEK_CURRENT?: string;
  TOKEN_KEK_PREV?: string;
}

/**
 * Build the token-KEK Worker secret bindings (P3 versioned ring). The host reads
 * `TOKEN_KEK_CURRENT ?? TOKEN_KEK`, so the deploy must accept EITHER key: require at least one
 * of `TOKEN_KEK_CURRENT` (preferred) / `TOKEN_KEK`, bind the legacy `TOKEN_KEK` only when
 * present (so the versioned-key config deploys without the legacy alias), and pass through an
 * optional `TOKEN_KEK_PREV`. `secret` wraps a raw value as an Alchemy secret and is injected to
 * keep this module free of the `alchemy` import.
 */
export function tokenKekBindings<S>(env: TokenKekEnv, secret: (value: string) => S): Record<string, S> {
  const current = env.TOKEN_KEK_CURRENT?.trim() || undefined;
  const legacy = env.TOKEN_KEK?.trim() || undefined;
  if (!current && !legacy) {
    throw new Error(
      "Missing token KEK: set TOKEN_KEK_CURRENT (preferred) or TOKEN_KEK in environment/.dev.vars",
    );
  }
  const prev = env.TOKEN_KEK_PREV?.trim() || undefined;
  return {
    ...(legacy ? { TOKEN_KEK: secret(legacy) } : {}),
    ...(current ? { TOKEN_KEK_CURRENT: secret(current) } : {}),
    ...(prev ? { TOKEN_KEK_PREV: secret(prev) } : {}),
  };
}
