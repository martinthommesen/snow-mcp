import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

// Load .dev.vars (gitignored) so live integration tests can read instance creds from
// `env`. Absent .dev.vars => no SNOW_* bindings => live tests skip. Secrets never live
// in source; only the local file. We forward just what the live test needs.
function devVars(): Record<string, string> {
  const path = fileURLToPath(new URL("./.dev.vars", import.meta.url));
  if (!existsSync(path)) return {};
  const out: Record<string, string> = {};
  const want = new Set(["SNOW_INSTANCE_HOST", "SNOW_DEV_ROPC_USERNAME", "SNOW_DEV_ROPC_PASSWORD"]);
  for (const raw of readFileSync(path, "utf8").split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    if (!want.has(key)) continue;
    let v = line.slice(eq + 1).trim();
    if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
    if (v) out[key] = v;
  }
  return out;
}

// Tests run inside workerd via @cloudflare/vitest-pool-workers — REQUIRED because
// @cloudflare/codemode and esbuild-wasm run in workerd, and the Worker Loader
// (LOADER) binding only exists there (plan §2.2, Phase 0.8).
//
// NOTE: vitest-pool-workers 0.16.10 (vitest 4) replaced the old
// `defineWorkersConfig` / `poolOptions.workers` API with the `cloudflareTest`
// plugin. Recorded in docs/DELTAS.md.
export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./packages/mcp-server/wrangler.jsonc" },
      miniflare: {
        compatibilityDate: "2026-05-13",
        compatibilityFlags: ["nodejs_compat"],
        bindings: devVars(),
      },
    }),
  ],
  test: {
    include: ["packages/**/test/**/*.test.ts"],
  },
});
