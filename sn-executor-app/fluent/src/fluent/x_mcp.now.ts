import '@servicenow/sdk/global'
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
// Application access grants the installed Global verifier helper read-only proof-row visibility.
// Human/API row access remains locked down separately by explicit admin-only record ACLs below.
export const x_1793136_mcp_audit_log = Table({
    $id: Now.ID['t_audit'],
    name: 'x_1793136_mcp_audit_log',
    label: 'MCP Audit Log',
    accessibleFrom: 'public',
    callerAccess: 'none',
    actions: ['read'],
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
    accessibleFrom: 'public',
    callerAccess: 'none',
    actions: ['read'],
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
// execute() split — installed by scripts/executor-install.mjs with HMAC material injected into the
// global helper. SINGLE-USE NONCE consumption stays in scope: the wrapper INSERTs into
// x_1793136_mcp_nonce (above) between verify() and execute().

// ─── Audit-table hardening (plan §P7 item 5; finding 25) ──────────────────────
// Restrict reading + writing the audit log to x_1793136_mcp.admin ONLY (separation of duty:
// the integration/executor user creates+closes its OWN row via the REST script, but no human
// role short of admin may read or alter rows). adminOverrides:false so the audit trail is not
// silently editable. (The executor REST script writes its row server-side regardless of the
// caller's record ACLs.)
Acl({
    $id: Now.ID['acl_audit_table_create'],
    operation: 'create',
    type: 'record',
    table: 'x_1793136_mcp_audit_log',
    active: true,
    adminOverrides: false,
    roles: [adminRole],
    description: 'Create x_1793136_mcp_audit_log -> x_1793136_mcp.admin only.',
})
Acl({
    $id: Now.ID['acl_audit_table_read'],
    operation: 'read',
    type: 'record',
    table: 'x_1793136_mcp_audit_log',
    active: true,
    adminOverrides: false,
    roles: [adminRole],
    description: 'Table read x_1793136_mcp_audit_log -> x_1793136_mcp.admin only.',
})
Acl({
    $id: Now.ID['acl_audit_table_write'],
    operation: 'write',
    type: 'record',
    table: 'x_1793136_mcp_audit_log',
    active: true,
    adminOverrides: false,
    roles: [adminRole],
    description: 'Table write x_1793136_mcp_audit_log -> x_1793136_mcp.admin only.',
})
Acl({
    $id: Now.ID['acl_audit_table_delete'],
    operation: 'delete',
    type: 'record',
    table: 'x_1793136_mcp_audit_log',
    active: true,
    adminOverrides: false,
    roles: [adminRole],
    description: 'Delete x_1793136_mcp_audit_log -> x_1793136_mcp.admin only.',
})
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
// The nonce table stores bounded proof rows: wrapper nonce consumption plus the wrapper's one-time
// execution claim. These rows are never read after the freshness window (120s). Purge rows
// older than 1 hour every 15 minutes so the table stays bounded (the 1-hour cutoff is far longer
// than the freshness window, so a still-relevant proof row is never deleted).
ScheduledScript({
    $id: Now.ID['job_nonce_purge'],
    name: 'MCP Nonce Purge',
    frequency: 'periodically',
    executionInterval: Duration({ minutes: 15 }),
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
// Aligned to x_1793136_mcp.executor.* to match the app scope and executor scripts.
// hmac_secret mirrors the Cloudflare X_MCP_EXECUTOR_HMAC_KEY for admin inventory only;
// hmac_secret_prev mirrors the previous key during a rotation window. Runtime verification uses
// the admin-installed global x_mcp_verify helper rendered by scripts/executor-install.mjs, never
// executor-role property reads. Both properties are password2 — set by the installer, never in
// source control (no `value` here so deploy does not overwrite an instance-set secret).
// Break-glass executor toggles default OFF and RE-ARM OFF on every deploy (fresh install AND
// upgrade). A break-glass kill-switch must not silently persist "on" across an upgrade, so these
// ship as ordinary app properties with value:false — NOT installMethod:'first install', which maps
// the record to the fresh-install-only `unload` folder and would SKIP the upgrade, leaving a prior
// `true` in place. An operator who needs break-glass enables it deliberately AFTER the deploy; the
// next deploy re-arms it off. NOTE: this cannot be exercised by the local gate (it does not build or
// deploy the Fluent app) — verify on a live UPGRADE that `x_1793136_mcp.executor.enabled` reads `false`.
const runtimePropertyRoles = { read: [executorRole, adminRole], write: [adminRole] }
// The executor role gates REST endpoint invocation only. It must never grant read access to the
// Worker HMAC signing secret or its rotation predecessor.
const secretPropertyRoles = { read: [adminRole], write: [adminRole] }

Property({
    $id: Now.ID['p_enabled'],
    name: 'x_1793136_mcp.executor.enabled',
    type: 'boolean',
    value: false,
    description: 'Enable the MCP executor REST endpoint after the target-family verifier gate passes.',
    roles: runtimePropertyRoles,
})
Property({
    $id: Now.ID['p_egress'],
    name: 'x_1793136_mcp.executor.run_server_script_enabled',
    type: 'boolean',
    value: false,
    description: 'Permit break-glass runServerScript execution; keep disabled unless governance approval is active.',
    roles: runtimePropertyRoles,
})
Property({
    $id: Now.ID['p_maxb'],
    name: 'x_1793136_mcp.executor.max_bytes',
    type: 'integer',
    value: 32768,
    description: 'Maximum inbound script payload size accepted by the executor.',
    roles: runtimePropertyRoles,
})
Property({
    $id: Now.ID['p_maxout'],
    name: 'x_1793136_mcp.executor.max_output_bytes',
    type: 'integer',
    value: 65536,
    description: 'Maximum serialized executor response size returned to the Worker.',
    roles: runtimePropertyRoles,
})
Property({
    $id: Now.ID['p_timeout'],
    name: 'x_1793136_mcp.executor.timeout_ms',
    type: 'integer',
    value: 30000,
    description: 'Cooperative executor timeout budget in milliseconds; platform quotas still bound synchronous CPU.',
    roles: runtimePropertyRoles,
})
Property({
    $id: Now.ID['p_hmac'],
    name: 'x_1793136_mcp.executor.hmac_secret',
    type: 'password2',
    description: 'Current HMAC key mirrored from the Worker X_MCP_EXECUTOR_HMAC_KEY secret.',
    isPrivate: true,
    roles: secretPropertyRoles,
})
Property({
    $id: Now.ID['p_hmac_prev'],
    name: 'x_1793136_mcp.executor.hmac_secret_prev',
    type: 'password2',
    description: 'Previous HMAC key accepted during a bounded Worker/executor key rotation window.',
    isPrivate: true,
    roles: secretPropertyRoles,
})
