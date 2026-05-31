import {
    Table,
    Role,
    Acl,
    RestApi,
    Property,
    ScheduledScript,
    StringColumn,
    IntegerColumn,
    BooleanColumn,
    DateTimeColumn,
} from '@servicenow/sdk/core'

// ─── Roles (plan §12) ─────────────────────────────────────────────────────────
const executorRole = Role({
    $id: Now.ID['role_executor'],
    name: 'x_1793136_mcp.executor',
    description: 'The only role allowed to hit the executor endpoint. Creates/closes its own audit row; cannot read/alter other rows or change properties.',
})
const adminRole = Role({
    $id: Now.ID['role_admin'],
    name: 'x_1793136_mcp.admin',
    description: 'Manages the audit log, kill switch + egress properties (separation of duty). Not the integration user.',
})

// ─── Tables (plan §10): audit log + nonce ─────────────────────────────────────
export const x_1793136_mcp_audit_log = Table({
    $id: Now.ID['t_audit'],
    name: 'x_1793136_mcp_audit_log',
    label: 'MCP Audit Log',
    schema: {
        snow_user: StringColumn({ label: 'SN User', maxLength: 64 }),
        snow_user_name: StringColumn({ label: 'SN User Name', maxLength: 128 }),
        mcp_actor_user_id: StringColumn({ label: 'MCP Actor', maxLength: 128 }),
        mcp_actor_email: StringColumn({ label: 'MCP Actor Email', maxLength: 255 }),
        request_id: StringColumn({ label: 'Request ID', maxLength: 128 }),
        actor_verified: BooleanColumn({ label: 'Actor Verified' }),
        // SIGNED, verified justification persisted from the HMAC-bound actor.reason (plan §P7
        // item 1/4) — never the unsigned POST body. 1024 = the host validateReason cap.
        reason: StringColumn({ label: 'Reason', maxLength: 1024 }),
        code_hash: StringColumn({ label: 'Code Hash', maxLength: 64 }),
        code_size: IntegerColumn({ label: 'Code Size' }),
        started_at: DateTimeColumn({ label: 'Started' }),
        duration: IntegerColumn({ label: 'Duration' }),
        status: StringColumn({ label: 'Status', maxLength: 40 }),
        output_size: IntegerColumn({ label: 'Output Size' }),
        error_class: StringColumn({ label: 'Error Class', maxLength: 128 }),
    },
})

// ⚠️ THE LIVE REPLAY-DEFENSE STORE (plan §P7 nonce-store fix; finding 24). Single-use nonce
// consumption is owned by the SCOPED executor wrapper (server/x_mcp_executor.js), which INSERTs
// into THIS table after delegating HMAC verify to the global core. now-sdk install deploys the
// table + its UNIQUE index correctly (app-deploy DDL), unlike the Table API used by
// scripts/executor-install.mjs, which 403s on table/index creation even for admin — which is why
// the nonce store MUST be this scoped table, not a global one.
export const x_1793136_mcp_nonce = Table({
    $id: Now.ID['t_nonce'],
    name: 'x_1793136_mcp_nonce',
    label: 'MCP Nonce',
    schema: {
        value: StringColumn({ label: 'Value', maxLength: 128 }),
        created: DateTimeColumn({ label: 'Created' }),
    },
    // UNIQUE index on `value` (plan §P7) — the DB race arbiter for the wrapper's INSERT-as-arbiter
    // single-use consume: two concurrent identical signed requests cannot both insert the nonce.
    index: [{ name: 'x_1793136_mcp_nonce_value_uq', unique: true, element: 'value' }],
})

// HMAC verification + script eval are delegated to the GLOBAL x_mcp_verify Script Include
// (GlideCertificateEncryption + new Function are global-only; plan §0.13a) via its verify()/
// execute() split — installed by scripts/executor-install.mjs. SINGLE-USE NONCE consumption stays
// in scope: the wrapper INSERTs into x_1793136_mcp_nonce (above) between verify() and execute().

// ─── Audit-table hardening (plan §P7 item 5; finding 25) ──────────────────────
// Restrict reading + writing the audit log to x_1793136_mcp.admin ONLY (separation of duty:
// the integration/executor user creates+closes its OWN row via the REST script, but no human
// role short of admin may read or alter rows). adminOverrides:false so the audit trail is not
// silently editable. (The executor REST script writes its row server-side regardless of the
// caller's record ACLs.)
Acl({
    $id: Now.ID['acl_audit_read'],
    operation: 'read',
    type: 'record',
    table: 'x_1793136_mcp_audit_log',
    field: '*',
    active: true,
    adminOverrides: false,
    roles: [adminRole],
    description: 'Read x_1793136_mcp_audit_log -> x_1793136_mcp.admin only.',
})
Acl({
    $id: Now.ID['acl_audit_write'],
    operation: 'write',
    type: 'record',
    table: 'x_1793136_mcp_audit_log',
    field: '*',
    active: true,
    adminOverrides: false,
    roles: [adminRole],
    description: 'Write x_1793136_mcp_audit_log -> x_1793136_mcp.admin only.',
})

// ─── Scheduled nonce-purge (TTL) job (plan §P7 item 5; finding 24) ────────────
// THE LIVE nonce purge: bounds the scoped x_1793136_mcp_nonce table the wrapper writes.
// The nonce table grows one row per executor call and is never read after the freshness
// window (120s). Purge rows older than 1 hour every 15 minutes so the table stays bounded
// (the 1-hour cutoff is far longer than the freshness window, so a still-relevant nonce is
// never deleted).
// ⚠️ SDK BUG (now-sdk 4.7.1) — P8 MANUAL FIX REQUIRED: the ScheduledScript serializer does
// String(value) on the interval, so the Duration OBJECT below lands as "[object Object]" in
// the generated sysauto_script.run_period (reproduced with the documented
// {hours,minutes,seconds} shape too). The Fluent linter rejects the string escape hatch the
// underlying `string | Duration` column would accept (`as unknown` => TS159; inline object
// type => TS150). So the job RECORD (name/type/script/active) is correct and the build is
// green, but run_period must be set by hand after install (or via a fixup script) until the
// SDK serializer is fixed. The script + cadence intent (15-min purge of >1h-old nonces) is
// authoritative; the interval value is the only field needing the manual touch.
ScheduledScript({
    $id: Now.ID['job_nonce_purge'],
    name: 'MCP Nonce Purge',
    frequency: 'periodically',
    executionInterval: { hours: 0, minutes: 15, seconds: 0 },
    executionStart: '2026-05-31 00:00:00',
    active: true,
    script: `// Purge MCP nonces older than 1 hour (TTL >> the 120s freshness window).
(function () {
    var gr = new GlideRecord('x_1793136_mcp_nonce');
    gr.addQuery('created', '<', gs.hoursAgoStart(1));
    gr.deleteMultiple();
})();
`,
})

// ─── REST_Endpoint ACL requiring x_1793136_mcp.executor (the role gate, S8) ────
const executorAcl = Acl({
    $id: Now.ID['acl_executor'],
    name: 'x_1793136_mcp_executor_run',
    operation: 'execute',
    type: 'rest_endpoint',
    active: true,
    adminOverrides: false,
    roles: [executorRole],
    description: 'Requires x_1793136_mcp.executor on the executor resource.',
})

// ─── Scripted REST API: x_mcp, resource executor/run (POST) ───────────────────
RestApi({
    $id: Now.ID['api_x_mcp'],
    name: 'x_mcp',
    serviceId: 'x_mcp',
    active: true,
    enforceAcl: [executorAcl],
    routes: [
        {
            $id: Now.ID['route_run'],
            name: 'run',
            path: '/executor/run',
            method: 'POST',
            active: true,
            authentication: true,
            authorization: true,
            script: Now.include('../server/x_mcp_executor.js'),
        },
    ],
})

// ─── Properties (plan §10, §P7 item 5) — scoped vendor-prefix namespace ───────
// Aligned to x_1793136_mcp.executor.* (was x_mcp.executor.*) to match the app scope and the
// executor scripts (kills the now-sdk TS11 prefix warnings; reconciles the naming split).
// Set hmac_secret to the Cloudflare X_MCP_EXECUTOR_HMAC_KEY; hmac_secret_prev holds the
// previous key during a rotation window. Both are password2 — set on the instance, never in
// source control (no `value` here so deploy does not overwrite an instance-set secret).
Property({ $id: Now.ID['p_enabled'], name: 'x_1793136_mcp.executor.enabled', type: 'boolean', value: true })
Property({ $id: Now.ID['p_egress'], name: 'x_1793136_mcp.executor.run_server_script_enabled', type: 'boolean', value: true })
Property({ $id: Now.ID['p_maxb'], name: 'x_1793136_mcp.executor.max_bytes', type: 'integer', value: 32768 })
Property({ $id: Now.ID['p_maxout'], name: 'x_1793136_mcp.executor.max_output_bytes', type: 'integer', value: 65536 })
Property({ $id: Now.ID['p_timeout'], name: 'x_1793136_mcp.executor.timeout_ms', type: 'integer', value: 30000 })
Property({ $id: Now.ID['p_hmac'], name: 'x_1793136_mcp.executor.hmac_secret', type: 'password2' })
Property({ $id: Now.ID['p_hmac_prev'], name: 'x_1793136_mcp.executor.hmac_secret_prev', type: 'password2' })
