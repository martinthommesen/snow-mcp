// Production OIDC deployed E2E gate.
//
// This script intentionally uses a real Chromium browser context for /authorize -> IdP ->
// /oidc/callback so the __Host- Secure SameSite=Lax state cookie is stored and sent by a
// browser cookie jar, not by hand-written Cookie headers. It is meant for manual-dispatch
// CI against a deployed Worker and an enterprise/test IdP tenant.
import http from "node:http";
import { randomBytes } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { chromium } from "playwright";

const DEFAULT_TIMEOUT_MS = 120_000;
const USERNAME_SELECTORS = [
  'input[name="loginfmt"]',
  'input[name="username"]',
  'input[name="identifier"]',
  'input[type="email"]',
  "#username",
  "#email",
];
const PASSWORD_SELECTORS = [
  'input[name="passwd"]',
  'input[name="password"]',
  'input[type="password"]',
  "#password",
];
const CONTINUE_SELECTORS = [
  'button[type="submit"]',
  'input[type="submit"]',
  "#idSIButton9",
  "#identifierNext",
  "#passwordNext",
  'button:has-text("Next")',
  'button:has-text("Sign in")',
  'button:has-text("Continue")',
  'button:has-text("Allow")',
  'button:has-text("Accept")',
  'button:has-text("Approve")',
  'button:has-text("Yes")',
];

let pass = 0;
let fail = 0;
let skipped = 0;

function b64url(bytes) {
  return Buffer.from(bytes).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function pkce() {
  const verifier = b64url(randomBytes(32));
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return { verifier, challenge: b64url(new Uint8Array(digest)) };
}

function check(name, condition, detail = "") {
  if (condition) {
    pass++;
    console.log("  PASS", name);
  } else {
    fail++;
    console.log("  FAIL", name, detail);
  }
}

function skip(name, reason) {
  skipped++;
  console.log("  SKIPPED", name, "-", reason);
}

function requiredEnv(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required for production OIDC deployed E2E.`);
  return value;
}

function canonicalHttpsOrigin(raw, label) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`${label} must be a canonical HTTPS origin.`);
  }
  if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
    throw new Error(`${label} must be a canonical HTTPS origin.`);
  }
  return url.origin;
}

function selectorsFromEnv(name, defaults) {
  const raw = process.env[name]?.trim();
  if (!raw) return defaults;
  return raw.split(/\n|\|\|/).map((s) => s.trim()).filter(Boolean);
}

function boolEnv(name, defaultValue) {
  const raw = process.env[name]?.trim();
  if (raw === undefined || raw === "") return defaultValue;
  return raw === "1" || raw.toLowerCase() === "true";
}

function numberEnv(name, defaultValue) {
  const n = Number(process.env[name]);
  return Number.isInteger(n) && n > 0 ? n : defaultValue;
}

function parseScopes(raw) {
  const value = raw?.trim() || "servicenow:write";
  return value
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function resolveConfig() {
  const baseRaw = process.argv[2] ?? process.env.WORKER_PUBLIC_ORIGIN;
  if (!baseRaw) {
    throw new Error("usage: WORKER_PUBLIC_ORIGIN=https://worker.example.com npm run production:oidc:e2e");
  }
  if (process.env.MCP_OPERATOR_SECRET?.trim()) {
    throw new Error("MCP_OPERATOR_SECRET must not be set for the production OIDC deployed E2E gate.");
  }
  if (process.env.AUTH_MODE && process.env.AUTH_MODE.trim() !== "oidc") {
    throw new Error('AUTH_MODE must be "oidc" for production OIDC deployed E2E.');
  }
  if (process.env.DEPLOYMENT_PROFILE && process.env.DEPLOYMENT_PROFILE.trim() !== "production") {
    throw new Error('DEPLOYMENT_PROFILE must be "production" for production OIDC deployed E2E.');
  }
  const scopes = parseScopes(process.env.OIDC_E2E_SCOPES);
  if (scopes.length === 0) throw new Error("OIDC_E2E_SCOPES must include at least one MCP scope.");
  return {
    base: canonicalHttpsOrigin(baseRaw, "WORKER_PUBLIC_ORIGIN"),
    username: requiredEnv("OIDC_E2E_USERNAME"),
    password: requiredEnv("OIDC_E2E_PASSWORD"),
    headless: boolEnv("OIDC_E2E_HEADLESS", true),
    timeoutMs: numberEnv("OIDC_E2E_TIMEOUT_MS", DEFAULT_TIMEOUT_MS),
    expectRefreshWriteDenied: boolEnv("OIDC_E2E_EXPECT_REFRESH_WRITE_DENIED", true),
    scopes,
    usernameSelectors: selectorsFromEnv("OIDC_E2E_USERNAME_SELECTORS", USERNAME_SELECTORS),
    passwordSelectors: selectorsFromEnv("OIDC_E2E_PASSWORD_SELECTORS", PASSWORD_SELECTORS),
    continueSelectors: selectorsFromEnv("OIDC_E2E_CONTINUE_SELECTORS", CONTINUE_SELECTORS),
  };
}

async function withTimeout(promise, ms, label) {
  let timeout;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timeout = setTimeout(() => reject(new Error(`${label} timed out after ${ms} ms`)), ms);
      }),
    ]);
  } finally {
    clearTimeout(timeout);
  }
}

async function firstVisible(page, selectors, timeout = 250) {
  for (const selector of selectors) {
    const locator = page.locator(selector).first();
    try {
      if (await locator.isVisible({ timeout })) return locator;
    } catch {
      // Try the next selector.
    }
  }
  return undefined;
}

async function maybeFill(page, selectors, value) {
  const locator = await firstVisible(page, selectors);
  if (!locator) return false;
  await locator.fill(value);
  return true;
}

async function maybeClick(page, selectors) {
  const locator = await firstVisible(page, selectors);
  if (!locator) return false;
  try {
    await locator.click({ timeout: 1_000 });
    return true;
  } catch {
    return false;
  }
}

async function driveIdpUntil(page, done, config) {
  const deadline = Date.now() + config.timeoutMs;
  let usernameFilled = false;
  let passwordFilled = false;
  while (Date.now() < deadline) {
    if (await done()) return;
    if (!usernameFilled) {
      usernameFilled = await maybeFill(page, config.usernameSelectors, config.username);
      if (usernameFilled) await maybeClick(page, config.continueSelectors);
    }
    if (!passwordFilled) {
      passwordFilled = await maybeFill(page, config.passwordSelectors, config.password);
      if (passwordFilled) await maybeClick(page, config.continueSelectors);
    }
    await maybeClick(page, config.continueSelectors);
    await sleep(500);
  }
  throw new Error(`OIDC browser flow did not complete; current URL is ${page.url()}`);
}

function startCallbackServer() {
  let resolveCallback;
  const codePromise = new Promise((resolve) => {
    resolveCallback = resolve;
  });
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (url.pathname !== "/callback") {
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("not found");
      return;
    }
    resolveCallback({
      code: url.searchParams.get("code") ?? "",
      state: url.searchParams.get("state") ?? "",
      error: url.searchParams.get("error") ?? "",
    });
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("OIDC E2E callback captured. You can close this page.");
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("Unable to determine local callback port."));
        return;
      }
      resolve({
        redirectUri: `http://localhost:${address.port}/callback`,
        waitForCode: () => codePromise,
        close: () => new Promise((closeResolve) => server.close(closeResolve)),
      });
    });
  });
}

async function registerClient(config, redirectUri) {
  const res = await fetch(`${config.base}/oauth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      redirect_uris: [redirectUri],
      token_endpoint_auth_method: "none",
      client_name: "production-oidc-e2e",
    }),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok || typeof json.client_id !== "string") {
    throw new Error(`DCR failed with HTTP ${res.status}: ${JSON.stringify(json).slice(0, 400)}`);
  }
  return json.client_id;
}

async function buildAuthorizeUrl(config, clientId, redirectUri) {
  const { verifier, challenge } = await pkce();
  const clientState = b64url(randomBytes(18));
  const q = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: config.scopes.join(" "),
    state: clientState,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  return { url: `${config.base}/authorize?${q}`, verifier, clientState };
}

async function beginOidcRedirect(context, authorizeUrl, config, label) {
  const page = await context.newPage();
  const authorizeResponse = page.waitForResponse((res) => res.url().startsWith(`${config.base}/authorize?`), {
    timeout: config.timeoutMs,
  });
  await page.goto(authorizeUrl, { waitUntil: "domcontentloaded", timeout: config.timeoutMs }).catch(() => undefined);
  const res = await authorizeResponse;
  const location = res.headers().location;
  const internalState = location ? new URL(location).searchParams.get("state") : "";
  if (!internalState) throw new Error(`${label}: /authorize redirect did not include OIDC state.`);
  const cookies = await context.cookies(config.base);
  const stateCookie = cookies.find((c) => c.name === `__Host-oidc_state_${internalState}`);
  check(
    `${label}: browser stored __Host- OIDC state cookie with Secure/HttpOnly/SameSite=Lax`,
    Boolean(stateCookie?.secure && stateCookie?.httpOnly && stateCookie?.sameSite === "Lax"),
  );
  await page.close();
  return internalState;
}

async function browserStatus(context, url, config) {
  const page = await context.newPage();
  const res = await page.goto(url, { waitUntil: "domcontentloaded", timeout: config.timeoutMs });
  const body = await page.locator("body").innerText({ timeout: 1_000 }).catch(() => "");
  await page.close();
  return { status: res?.status() ?? 0, body };
}

async function assertStateCookieNegatives(browser, config, clientId, redirectUri) {
  const negativeContext = await browser.newContext();
  const { url } = await buildAuthorizeUrl(config, clientId, redirectUri);
  const state = await beginOidcRedirect(negativeContext, url, config, "state-cookie-negative");

  const missingContext = await browser.newContext();
  const missing = await browserStatus(
    missingContext,
    `${config.base}/oidc/callback?code=code-injection-attempt&state=${encodeURIComponent(state)}`,
    config,
  );
  check("missing state cookie rejects callback before code exchange", missing.status === 400 && /not bound/i.test(missing.body));
  await missingContext.close();

  const mismatchContext = await browser.newContext();
  await mismatchContext.addCookies([{
    name: "__Host-oidc_state_wrong_state",
    value: "1",
    url: config.base,
    path: "/",
    secure: true,
    httpOnly: true,
    sameSite: "Lax",
  }]);
  const mismatch = await browserStatus(
    mismatchContext,
    `${config.base}/oidc/callback?code=code-injection-attempt&state=${encodeURIComponent(state)}`,
    config,
  );
  check("mismatched state cookie rejects callback before code exchange", mismatch.status === 400 && /not bound/i.test(mismatch.body));
  await mismatchContext.close();
  await negativeContext.close();
}

async function captureIdpCallback(context, authorizeUrl, config, label) {
  const page = await context.newPage();
  let captured;
  await page.route(`${config.base}/oidc/callback**`, async (route) => {
    captured = new URL(route.request().url());
    await route.fulfill({ status: 200, contentType: "text/plain", body: "captured oidc callback" });
  });
  await page.goto(authorizeUrl, { waitUntil: "domcontentloaded", timeout: config.timeoutMs }).catch(() => undefined);
  await driveIdpUntil(page, async () => captured !== undefined, config);
  await page.unroute(`${config.base}/oidc/callback**`);
  await page.close();
  const code = captured?.searchParams.get("code") ?? "";
  const state = captured?.searchParams.get("state") ?? "";
  if (!code || !state) throw new Error(`${label}: failed to capture IdP callback code/state.`);
  return { code, state };
}

async function assertCodeInjectionRejected(context, config, clientId, redirectUri) {
  const first = await buildAuthorizeUrl(config, clientId, redirectUri);
  const second = await buildAuthorizeUrl(config, clientId, redirectUri);
  const injected = await captureIdpCallback(context, first.url, config, "code-injection-source");
  const victim = await captureIdpCallback(context, second.url, config, "code-injection-victim");
  const page = await context.newPage();
  const res = await page.goto(
    `${config.base}/oidc/callback?code=${encodeURIComponent(injected.code)}&state=${encodeURIComponent(victim.state)}`,
    { waitUntil: "domcontentloaded", timeout: config.timeoutMs },
  );
  const text = await page.locator("body").innerText({ timeout: 1_000 }).catch(() => "");
  await page.close();
  check(
    "negative OIDC code-injection attempt is rejected",
    (res?.status() ?? 0) >= 400 && !/name="oidc_consent"/i.test(text),
  );
}

async function completeOidcFlow(context, config, clientId, redirectUri, waitForCode) {
  const auth = await buildAuthorizeUrl(config, clientId, redirectUri);
  const page = await context.newPage();
  await page.goto(auth.url, { waitUntil: "domcontentloaded", timeout: config.timeoutMs }).catch(() => undefined);
  await driveIdpUntil(
    page,
    async () => await page.locator('input[name="oidc_consent"]').first().isVisible({ timeout: 250 }).catch(() => false),
    config,
  );
  await page.locator('form[action="/oidc/consent"] button, button[type="submit"], input[type="submit"]').first().click({
    timeout: config.timeoutMs,
  });
  const callback = await withTimeout(waitForCode(), config.timeoutMs, "MCP OAuth callback");
  await page.close();
  if (callback.error) throw new Error(`MCP OAuth callback returned error=${callback.error}`);
  check("MCP OAuth callback preserves client state", callback.state === auth.clientState);
  if (!callback.code) throw new Error("MCP OAuth callback did not include an authorization code.");
  return { code: callback.code, verifier: auth.verifier };
}

async function exchangeMcpCode(config, clientId, redirectUri, code, verifier) {
  const res = await fetch(`${config.base}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: verifier,
    }),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok || typeof json.access_token !== "string") {
    throw new Error(`MCP token exchange failed with HTTP ${res.status}: ${JSON.stringify(json).slice(0, 400)}`);
  }
  check("OIDC auth-code + MCP PKCE exchange issues an access token", json.access_token.length > 20);
  check("OIDC auth-code grant issues an MCP refresh token", typeof json.refresh_token === "string" && json.refresh_token.length > 20);
  return json;
}

async function refreshMcpToken(config, clientId, refreshToken) {
  const res = await fetch(`${config.base}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: clientId,
      scope: config.scopes.join(" "),
    }),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok || typeof json.access_token !== "string") {
    throw new Error(`MCP refresh-token exchange failed with HTTP ${res.status}: ${JSON.stringify(json).slice(0, 400)}`);
  }
  check("MCP refresh-token exchange reissues an access token", json.access_token.length > 20);
  return json;
}

async function withMcpClient(config, token, label, fn) {
  const transport = new StreamableHTTPClientTransport(new URL(`${config.base}/mcp`), {
    requestInit: { headers: { authorization: `Bearer ${token}` } },
  });
  const client = new Client({ name: label, version: "0.1.0" });
  await client.connect(transport);
  try {
    return await fn(client);
  } finally {
    await client.close();
  }
}

async function assertMcpAuthenticated(config, token, label) {
  await withMcpClient(config, token, label, async (client) => {
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name).sort().join(",");
    check(`${label}: authenticated /mcp lists expected tools`, names === "describe_table,list_tables,run_code");
  });
}

async function assertRefreshedWriteDenied(config, token) {
  if (!config.expectRefreshWriteDenied) {
    skip("refresh write-denial assertion", "OIDC_E2E_EXPECT_REFRESH_WRITE_DENIED=0");
    return;
  }
  if (!config.scopes.includes("servicenow:write") && !config.scopes.includes("servicenow:admin_script")) {
    throw new Error("OIDC_E2E_EXPECT_REFRESH_WRITE_DENIED=1 requires OIDC_E2E_SCOPES to include servicenow:write or servicenow:admin_script.");
  }
  await withMcpClient(config, token, "production-oidc-e2e-refresh", async (client) => {
    const out = await client.callTool({
      name: "run_code",
      arguments: {
        mode: "write",
        code: "async () => 1",
      },
    });
    check(
      "refreshed token denies write under current OIDC policy",
      out.isError === true && out.structuredContent?.code === "mode_not_permitted",
      JSON.stringify(out.structuredContent ?? {}).slice(0, 300),
    );
  });
}

async function main() {
  const config = resolveConfig();
  const callbackServer = await startCallbackServer();
  let browser;
  try {
    const unauth = await fetch(`${config.base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    check("unauthenticated deployed /mcp returns 401", unauth.status === 401);

    const clientId = await registerClient(config, callbackServer.redirectUri);
    browser = await chromium.launch({ headless: config.headless });

    await assertStateCookieNegatives(browser, config, clientId, callbackServer.redirectUri);

    const context = await browser.newContext();
    await assertCodeInjectionRejected(context, config, clientId, callbackServer.redirectUri);

    const flow = await completeOidcFlow(
      context,
      config,
      clientId,
      callbackServer.redirectUri,
      callbackServer.waitForCode,
    );
    const tokenResult = await exchangeMcpCode(config, clientId, callbackServer.redirectUri, flow.code, flow.verifier);
    await assertMcpAuthenticated(config, tokenResult.access_token, "production-oidc-e2e");

    const refreshed = await refreshMcpToken(config, clientId, tokenResult.refresh_token);
    await assertMcpAuthenticated(config, refreshed.access_token, "production-oidc-e2e-refreshed");
    await assertRefreshedWriteDenied(config, refreshed.access_token);
    await context.close();
  } finally {
    await browser?.close();
    await callbackServer.close();
  }

  console.log(`\nPRODUCTION OIDC DEPLOYED E2E: ${fail === 0 ? "ALL PASS" : "FAILURES"} - ${pass} passed, ${fail} failed, ${skipped} skipped`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : String(e));
  process.exit(1);
});
