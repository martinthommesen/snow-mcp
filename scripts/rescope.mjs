// Re-scope the Fluent executor app for a forker. Substitutes the CURRENT scope prefix
// (read from now.config.json — NOT a hardcoded literal) with a new full scope across the
// source set, mints/sets a new scopeId, and deletes the generated keys.ts so the next
// `now-sdk build` regenerates it cleanly.
//
//   node scripts/rescope.mjs <new-scope> [<scopeId>] [--check]
//   node scripts/rescope.mjs x_acme_mcp                 # mint a fresh scopeId
//   node scripts/rescope.mjs x_acme_mcp <32-hex>        # supply a scopeId
//   node scripts/rescope.mjs x_acme_mcp --check         # dry-run (report only)
import { readFileSync, writeFileSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";

// fileURLToPath (not .pathname) so the script works from a clone path containing spaces.
const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const configPath = resolve(root, "sn-executor-app/fluent/now.config.json");

// Files whose every `<oldScope>` occurrence is rewritten with `<newScope>` (literal substring
// replacement; safe because the input guard rejects a scope that is a substring of a preserved
// global). Both x_mcp_verify.js copies get the IDENTICAL replacement, so
// scripts/check-verifier-sync.mjs stays green. keys.ts is NOT here — it is build-generated.
const SOURCE_FILES = [
  "sn-executor-app/fluent/src/fluent/x_mcp.now.ts",
  "sn-executor-app/fluent/src/server/x_mcp_executor.js",
  "sn-executor-app/fluent/src/server/x_mcp_verify.js",
  "sn-executor-app/script-include/x_mcp_verify.js",
  "scripts/executor-install.mjs",
  "scripts/executor-scoped-verify.mjs",
];
const KEYS_PATH = "sn-executor-app/fluent/src/fluent/generated/keys.ts";

function fail(msg) {
  console.error(`rescope: ${msg}`);
  process.exit(1);
}

// 1) INPUT + VALIDATION.
const argv = process.argv.slice(2);
const check = argv.includes("--check");
const positional = argv.filter((a) => a !== "--check");
const newScope = positional[0];
if (!newScope) fail("usage: node scripts/rescope.mjs <new-scope> [<scopeId>] [--check]");
// Regex shape AND explicit length bound (the regex does not bound length).
if (!/^((x|sn)_[a-z0-9_]+|global)$/.test(newScope)) {
  fail(`invalid scope "${newScope}" — must match ^((x|sn)_[a-z0-9_]+|global)$`);
}
if (newScope.length < 4 || newScope.length > 18) {
  fail(`invalid scope "${newScope}" — length must be 4-18 (got ${newScope.length})`);
}
// Substitution is SUBSTRING replacement, not whole-token (see step 4). Reject a new scope that is a
// substring of a preserved GLOBAL identifier: it becomes the next search token, so a later re-scope
// would over-match and corrupt the global helper (e.g. "x_mcp" inside "x_mcp_verify") — and the
// verifier-sync self-check would NOT catch it (both copies get the same wrong edit).
const PRESERVED_GLOBALS = ["x_mcp", "x_mcp_verify", "x_mcp_executor"];
const clash = PRESERVED_GLOBALS.find((g) => g.includes(newScope));
if (clash) {
  fail(`unsafe scope "${newScope}": it is a substring of the preserved global "${clash}" — a later ` +
    `re-scope would corrupt it. Choose a more specific scope (e.g. x_<vendor>_mcp).`);
}

const config = JSON.parse(readFileSync(configPath, "utf8"));
const oldScope = config.scope;
const oldScopeId = config.scopeId;

// scopeId: explicit arg, else keep the existing id on a same-scope re-run, else mint a fresh 32-hex
// GUID. Under --check we do NOT mint (a dry-run id would not match the eventual real run); show a
// placeholder instead so the dry-run doesn't read as authoritative.
const scopeIdProvided = positional[1] !== undefined;
const scopeIdMinted = !scopeIdProvided && oldScope !== newScope;
let newScopeId;
if (scopeIdProvided) {
  newScopeId = positional[1];
} else if (oldScope === newScope) {
  newScopeId = oldScopeId;
} else {
  newScopeId = check ? "<minted at run time>" : randomBytes(16).toString("hex");
}
// Validate only a real (non-placeholder) scopeId.
if (!(check && scopeIdMinted) && !/^([0-9a-f]{32}|global)$/.test(newScopeId)) {
  fail(`invalid scopeId "${newScopeId}" — must match ^([0-9a-f]{32}|global)$`);
}

// 2) SEARCH TOKEN + idempotency. The CURRENT scope is the search token (prefix-free script body).
if (oldScope === newScope && oldScopeId === newScopeId) {
  console.log(`already on ${newScope} (scopeId ${newScopeId}) — nothing to do`);
  process.exit(0);
}
if (oldScope === newScope && oldScopeId !== newScopeId) {
  // Prefix unchanged, only scopeId differs: still refuse to string-replace a same prefix.
  fail(`refusing to substitute: old scope == new scope ("${newScope}"). Pass a different scope, or edit scopeId only.`);
}

console.log(`${check ? "[--check] " : ""}rescope ${oldScope} -> ${newScope}`);
console.log(`  scopeId ${oldScopeId} -> ${newScopeId}\n`);

// 3) now.config.json — mutate the parsed object, preserve 2-space style + original trailing newline.
const configRaw = readFileSync(configPath, "utf8");
const configHadTrailingNewline = configRaw.endsWith("\n");
config.scope = newScope;
config.scopeId = newScopeId;
const configOut = JSON.stringify(config, null, 2) + (configHadTrailingNewline ? "\n" : "");
if (!check) writeFileSync(configPath, configOut);
console.log(`  now.config.json: scope + scopeId updated`);

// 4) SOURCE SUBSTITUTION — literal substring split/join (no regex pitfalls; the input guard above
//    rejected any scope that is a substring of a preserved global, so substring replacement is safe).
let total = 0;
for (const rel of SOURCE_FILES) {
  const p = resolve(root, rel);
  const before = readFileSync(p, "utf8");
  const count = before.split(oldScope).length - 1;
  total += count;
  const after = before.split(oldScope).join(newScope);
  if (!check) writeFileSync(p, after);
  console.log(`  ${rel}: ${count}`);
}
console.log(`  total source replacements: ${total}`);

// 5) keys.ts — delete the generated file so `now-sdk build` regenerates it (idempotent on ENOENT).
const keysAbs = resolve(root, KEYS_PATH);
if (!check) {
  try {
    rmSync(keysAbs);
    console.log(`  ${KEYS_PATH}: deleted (will be regenerated)`);
  } catch (e) {
    if (e.code === "ENOENT") console.log(`  ${KEYS_PATH}: already absent`);
    else throw e;
  }
} else {
  console.log(`  ${KEYS_PATH}: would delete`);
}

// 6) SELF-CHECK — assert no oldScope remains, and that the two x_mcp_verify.js bodies are still
// byte-identical (the only way to break check:verifier-sync is an asymmetric substitution).
if (!check) {
  // Token-aware: strip the freshly-written newScope first (replace with a sentinel that can't occur
  // in source), so a newScope that CONTAINS oldScope (e.g. x_acme -> x_acme_mcp) is not a false
  // positive — without this, the run would abort AFTER rewriting files and deleting keys.ts.
  const SENTINEL = "\u0000";
  const stragglers = [];
  for (const rel of SOURCE_FILES) {
    if (readFileSync(resolve(root, rel), "utf8").split(newScope).join(SENTINEL).includes(oldScope)) stragglers.push(rel);
  }
  if (JSON.stringify(config).split(newScope).join(SENTINEL).includes(oldScope)) stragglers.push("now.config.json");
  if (stragglers.length) fail(`old scope "${oldScope}" still present in: ${stragglers.join(", ")}`);

  // Mirror scripts/check-verifier-sync.mjs: compare the closure-backed verifier core.
  const verifierBody = (rel) => {
    const src = readFileSync(resolve(root, rel), "utf8").replace(/\r\n/g, "\n");
    const marker = "(function () {";
    const start = src.indexOf(marker);
    const end = src.lastIndexOf("\n})();");
    if (start < 0 || end < 0 || end <= start) fail(`could not locate x_mcp_verify closure body in ${rel}`);
    return src.slice(start + marker.length, end).trim();
  };
  if (verifierBody("sn-executor-app/fluent/src/server/x_mcp_verify.js") !==
      verifierBody("sn-executor-app/script-include/x_mcp_verify.js")) {
    fail("x_mcp_verify bodies diverged after substitution — would break check:verifier-sync");
  }
}

// 7) REPORT + next steps.
console.log(`\n${check ? "Dry-run complete — no files written." : "Re-scope complete."}`);
console.log(`  scope:   ${oldScope} -> ${newScope}`);
console.log(`  scopeId: ${newScopeId}`);
if (!check) console.log(`  keys.ts deleted — run now-sdk build to regenerate, then commit it.`);
console.log("\nNext steps:");
console.log("  1) cd sn-executor-app/fluent && npx now-sdk build   # regenerates src/fluent/generated/keys.ts");
console.log("  2) git add -A && git commit                          # commit rescoped source + new keys.ts");
console.log("  3) npm run typecheck && npm test && npm run check:verifier-sync   # green gate");
process.exit(0);
