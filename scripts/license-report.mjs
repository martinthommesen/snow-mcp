#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { basename, dirname, relative, resolve } from "node:path";

const DEFAULT_DENIED_LICENSE_RE = /\b(?:AGPL|GPL|LGPL)\b|UNKNOWN|UNLICENSED/i;
const repoRoot = process.cwd();
const lockfileBasenames = new Set(["package-lock.json"]);
const policyBasenames = new Set(["license-policy.json"]);

function packageName(pathKey, pkg) {
  if (pkg.name) return pkg.name;
  const parts = pathKey.split("node_modules/");
  return parts[parts.length - 1] || basename(dirname(pathKey)) || "(root)";
}

function repoFilePath(input, allowedBasenames) {
  const absolute = resolve(repoRoot, input);
  const rel = relative(repoRoot, absolute);
  if (rel.startsWith("..") || rel === "" || rel.includes("..")) {
    throw new Error(`Refusing to read non-repository file: ${input}`);
  }
  if (!allowedBasenames.has(basename(absolute))) {
    throw new Error(`Refusing to read unexpected file type: ${input}`);
  }
  return absolute;
}

function readJsonFile(input, allowedBasenames) {
  return JSON.parse(readFileSync(repoFilePath(input, allowedBasenames), "utf8"));
}

function reportFor(lockfile) {
  const lock = readJsonFile(lockfile, lockfileBasenames);
  const lockPackages = lock.packages ?? {};
  const packages = Object.entries(lockPackages).map(([pathKey, pkg]) => {
    const target = pkg.link && pkg.resolved ? lockPackages[pkg.resolved] : undefined;
    const effective = target ?? pkg;
    return {
      name: packageName(pathKey, effective),
      version: effective.version ?? lock.version ?? "",
      license: effective.license ?? "UNKNOWN",
      path: pathKey || ".",
    };
  });
  const byLicense = {};
  for (const pkg of packages) byLicense[pkg.license] = (byLicense[pkg.license] ?? 0) + 1;
  return { lockfile, packageCount: packages.length, byLicense, packages };
}

function parseArgs(argv) {
  const out = { enforce: false, policyPath: undefined, lockfiles: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--enforce") {
      out.enforce = true;
    } else if (arg === "--policy") {
      out.policyPath = argv[++i];
    } else if (arg.startsWith("--policy=")) {
      out.policyPath = arg.slice("--policy=".length);
    } else {
      out.lockfiles.push(arg);
    }
  }
  return out;
}

function globRegex(pattern) {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`);
}

function loadPolicy(path) {
  if (!path) return undefined;
  return readJsonFile(path, policyBasenames);
}

function compileException(exception) {
  return {
    lockfile: exception.lockfile,
    name: exception.name ? globRegex(exception.name) : undefined,
    path: exception.path ? globRegex(exception.path) : undefined,
    license: exception.license ? globRegex(exception.license) : undefined,
    reason: exception.reason,
  };
}

function exceptionMatches(exception, pkg, report) {
  if (exception.lockfile && exception.lockfile !== report.lockfile) return false;
  if (exception.name && !exception.name.test(pkg.name)) return false;
  if (exception.path && !exception.path.test(pkg.path)) return false;
  if (exception.license && !exception.license.test(pkg.license)) return false;
  return true;
}

function evaluatePolicy(reports, policy) {
  if (!policy) return { violations: [], exceptionsUsed: [] };
  const allowed = new Set(policy.allowedLicenses ?? []);
  const deniedRe = new RegExp(policy.deniedLicensePattern ?? DEFAULT_DENIED_LICENSE_RE.source, "i");
  const exceptions = (policy.exceptions ?? []).map(compileException);
  const violations = [];
  const exceptionsUsed = [];
  for (const report of reports) {
    for (const pkg of report.packages) {
      const allowedLicense = allowed.has(pkg.license);
      const deniedLicense = deniedRe.test(pkg.license);
      if (allowedLicense && !deniedLicense) continue;
      const exception = exceptions.find((candidate) => exceptionMatches(candidate, pkg, report));
      if (exception) {
        exceptionsUsed.push({
          lockfile: report.lockfile,
          name: pkg.name,
          version: pkg.version,
          license: pkg.license,
          reason: exception.reason,
        });
        continue;
      }
      violations.push({
        lockfile: report.lockfile,
        name: pkg.name,
        version: pkg.version,
        license: pkg.license,
        path: pkg.path,
        reason: deniedLicense ? "denied_license" : "license_not_in_allowlist",
      });
    }
  }
  return { violations, exceptionsUsed };
}

const args = parseArgs(process.argv.slice(2));
const lockfiles = args.lockfiles;
if (lockfiles.length === 0) {
  console.error("usage: node scripts/license-report.mjs [--policy license-policy.json] [--enforce] <package-lock.json> [...]");
  process.exit(2);
}

const reports = lockfiles.map(reportFor);
const policy = loadPolicy(args.policyPath);
const policyResult = evaluatePolicy(reports, policy);
console.log(JSON.stringify({
  generatedAt: new Date().toISOString(),
  ...(policy ? { policy: { path: args.policyPath, enforced: args.enforce, ...policyResult } } : {}),
  reports,
}, null, 2));

if (args.enforce && policyResult.violations.length > 0) {
  console.error(`license policy violations: ${policyResult.violations.length}`);
  for (const v of policyResult.violations) {
    console.error(`- ${v.lockfile}: ${v.name}@${v.version} ${v.license} (${v.reason})`);
  }
  process.exit(1);
}
