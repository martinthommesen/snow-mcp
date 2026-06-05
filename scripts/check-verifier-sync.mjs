import { readFileSync } from "node:fs";
import { relative, resolve } from "node:path";

const root = process.cwd();
const canonicalPath = resolve(root, "sn-executor-app/script-include/x_mcp_verify.js");
const fluentPath = resolve(root, "sn-executor-app/fluent/src/server/x_mcp_verify.js");

function verifierBody(path) {
  const source = readFileSync(path, "utf8").replace(/\r\n/g, "\n");
  const marker = "(function () {";
  const start = source.indexOf(marker);
  const end = source.lastIndexOf("\n})();");
  if (start < 0 || end < 0 || end <= start) {
    throw new Error(`Could not locate x_mcp_verify closure body in ${relative(root, path)}`);
  }
  return source.slice(start + marker.length, end).trim();
}

const canonicalBody = verifierBody(canonicalPath);
const fluentBody = verifierBody(fluentPath);

if (canonicalBody !== fluentBody) {
  console.error("x_mcp_verify verifier bodies differ.");
  console.error(`canonical: ${relative(root, canonicalPath)}`);
  console.error(`fluent:    ${relative(root, fluentPath)}`);
  process.exit(1);
}

console.log("x_mcp_verify verifier bodies are in sync.");
