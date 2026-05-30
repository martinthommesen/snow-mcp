# ADR-0001 — Code Mode integration shape (the one shape every sample conforms to)

**Status:** Accepted (Phase 0.8a/0.8b proven locally under `@cloudflare/vitest-pool-workers`).
**Date:** 2026-05-30.
**Package proven against:** `@cloudflare/[email protected]`, `esbuild-[email protected]`, `[email protected]` (workerd `1.20260526.1`, miniflare `4.20260526.0`).

> Per DEVELOPMENT_PLAN §3.4: "Phase 0.8 proves the exact `execute()` contract and the TS pipeline before this is built … Every sample in the plan then conforms to that one shape." This ADR is that shape, derived from the **installed** package, not from the plan's prose. Where the two differ, this ADR (and the installed package) win; differences are logged in `docs/DELTAS.md`.

## Decision 1 — Primary pipeline confirmed; no worker-bundler fallback

The plan's **primary** path holds: `esbuild-wasm.transform(userTs) → JS string → DynamicWorkerExecutor.execute(jsString, providers)`. All six 0.8a assertions pass under workerd (see `test/sandbox-contract.test.ts`). **`@cloudflare/worker-bundler` is NOT installed and NOT needed** — the fallback in plan §2.2/§3.4 is not taken. Re-open only if a future codemode version rejects the transformed string.

## Decision 2 — The exact code shape the model writes

The model authors a **single async arrow function** in **TypeScript**:

```ts
async () => {
  const r = await servicenow.tableQuery({ table: "incident", limit: 10 });
  return r.rows.length;
}
```

- It is an **expression** (`async () => { ... }`), not a module, not `export default`, not a named function.
- It **returns** the result. `return` lives inside the arrow body (top-level `return` is a syntax error after transpile — esbuild runs before codemode's `normalizeCode`).
- `console.log/warn/error` are allowed and captured (see Decision 5).
- `codemode.normalizeCode()` also tolerates a bare trailing expression, a statement list, a single named `function`, and `export default function/class`, but **the documented, supported shape is the async arrow** — all plan samples use it.

## Decision 3 — The exact string passed to `execute()`

`transpileTs()` (`src/sandbox/transpile.ts`) returns `esbuild.transform(userTs, { loader:"ts", format:"esm", target:"es2022" }).code`, **with the trailing `;` stripped**.

> **Why strip the trailing `;` (load-bearing):** esbuild emits `async () => {...}` as a *statement* (`async () => {...};`). codemode's executor embeds the code as `( <code> )()`. A trailing semicolon yields `(async () => {...};)()` → `Uncaught SyntaxError: Unexpected token ';'`. Stripping the single trailing `;` makes it a bare expression that `normalizeCode()` recognizes as an arrow. Proven by the 6 contract tests flipping red→green on this one change.

## Decision 4 — The exact `fns` / providers shape and the sandbox namespace

`execute(code, providers)` takes a **`ResolvedProvider[]`**, not a raw fns record (the raw-record form is **deprecated** in 0.3.8 and warns). Each provider becomes a **single-level** sandbox global:

```ts
await executor.execute(js, [
  { name: "servicenow", fns: { tableQuery, tableGet, aggregate, /* … */ } },
]);
// sandbox sees:  servicenow.tableQuery(args)  →  Promise<result>
```

- `provider.name` must be a **valid JS identifier** and not one of codemode's reserved names; it is the global.
- Tool args are JSON-serialized over Workers RPC; each tool returns a `Promise`.
- A tool that throws host-side surfaces inside the sandbox as a thrown `Error` (catchable in the snippet).

> **DELTA from the plan (recorded in DELTAS.md):** the plan writes the surface as `codemode.servicenow.*`. The installed SDK exposes a **single-level** namespace — `servicenow.*` (the provider name *is* the global). There is no two-level `codemode.servicenow` nesting. **All samples use `servicenow.*`.**

## Decision 5 — Errors, logs, timeout (the executor never throws)

`execute()` returns `ExecuteResult = { result: unknown; error?: string; logs?: string[] }` and **never throws** (codemode contract). Therefore:
- A snippet that throws → `{ result: undefined, error: "<message>" }`.
- `console.*` → captured into `logs` (`warn`/`error` prefixed).
- Timeout (`DynamicWorkerExecutor({ timeout })`, default 30 000 ms) → `error` contains `"Execution timed out"` via an internal `Promise.race`. **It does not abort already-running synchronous CPU** — it loses the race; long sync work is still bounded only by workerd limits.

## Decision 6 — Import policy (0.8b)

- **Mechanism (proven):** the executor's `modules: Record<specifier, source>` map is injected into the sandbox module map and is reachable via dynamic `import("<specifier>")` inside the snippet (`test/import-policy.test.ts`).
- **v1 policy:** pass **no** modules. Arbitrary npm imports are **disabled**; the only capability is the `servicenow` provider. Zero supply-chain surface. A future vetted allowlist is a config change to `createExecutor({ modules })`, not a rewrite.
- **Type-checking:** esbuild `transform` **strips types, does not type-check**. v1 accepts **runtime-only typing** — a *type* error still runs (proven). Rationale: a `tsc --noEmit` per snippet adds latency and a second toolchain in-Worker for little safety gain, because the typed `servicenow.*` surface in the tool description already steers the model. Revisit if mistyped snippets become a real failure mode.

## Decision 7 — `export default`: rejected by convention

`normalizeCode()` *would* unwrap `export default function/class`, but v1 instructs the model to write the bare async arrow only. We do not document or test `export default`; treat its use as undefined behavior.

## Consequences

- `tools/run_code.ts` (Phase 4) builds `{ code, mode?, reason?, idempotencyKey? }` → `transpileTs` → `createExecutor(env.LOADER, { timeoutMs })` → `executeSnippet(js, [{ name:"servicenow", fns }])` → serialize `ExecuteResult`.
- The tool description embeds the `declare const servicenow: { … }` surface (single-level) generated for the ServiceNow RPC methods (Phase 4.3).
- The sandbox inner-Worker compat date is **hardcoded to `2025-06-01` inside codemode 0.3.8** — not our unified host date `2026-05-13`. We cannot change it without forking the SDK. Recorded as a delta; acceptable because the sandbox only runs transpiled user code against the RPC proxy.
