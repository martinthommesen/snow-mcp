#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { basename, dirname } from "node:path";

function packageName(pathKey, pkg) {
  if (pkg.name) return pkg.name;
  const parts = pathKey.split("node_modules/");
  return parts[parts.length - 1] || basename(dirname(pathKey)) || "(root)";
}

function reportFor(lockfile) {
  const lock = JSON.parse(readFileSync(lockfile, "utf8"));
  const packages = Object.entries(lock.packages ?? {}).map(([pathKey, pkg]) => ({
    name: packageName(pathKey, pkg),
    version: pkg.version ?? lock.version ?? "",
    license: pkg.license ?? "UNKNOWN",
    path: pathKey || ".",
  }));
  const byLicense = {};
  for (const pkg of packages) byLicense[pkg.license] = (byLicense[pkg.license] ?? 0) + 1;
  return { lockfile, packageCount: packages.length, byLicense, packages };
}

const lockfiles = process.argv.slice(2);
if (lockfiles.length === 0) {
  console.error("usage: node scripts/license-report.mjs <package-lock.json> [...]");
  process.exit(2);
}

console.log(JSON.stringify({ generatedAt: new Date().toISOString(), reports: lockfiles.map(reportFor) }, null, 2));
