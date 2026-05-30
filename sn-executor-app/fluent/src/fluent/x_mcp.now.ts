import {
    Table,
    Role,
    Acl,
    RestApi,
    Property,
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
Role({
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
        code_hash: StringColumn({ label: 'Code Hash', maxLength: 64 }),
        code_size: IntegerColumn({ label: 'Code Size' }),
        started_at: DateTimeColumn({ label: 'Started' }),
        duration: IntegerColumn({ label: 'Duration' }),
        status: StringColumn({ label: 'Status', maxLength: 40 }),
        output_size: IntegerColumn({ label: 'Output Size' }),
        error_class: StringColumn({ label: 'Error Class', maxLength: 128 }),
    },
})

export const x_1793136_mcp_nonce = Table({
    $id: Now.ID['t_nonce'],
    name: 'x_1793136_mcp_nonce',
    label: 'MCP Nonce',
    schema: {
        value: StringColumn({ label: 'Value', maxLength: 128 }),
        created: DateTimeColumn({ label: 'Created' }),
    },
})

// Actor verification is delegated to the GLOBAL x_mcp_verify Script Include
// (GlideCertificateEncryption is global-only; plan §0.13a). The executor resource calls
// `new global.x_mcp_verify()`. The global helper is installed by scripts/executor-install.mjs.

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

// ─── Properties (plan §10) — set hmac_secret to the Cloudflare X_MCP_EXECUTOR_HMAC_KEY ─
Property({ $id: Now.ID['p_enabled'], name: 'x_mcp.executor.enabled', type: 'boolean', value: true })
Property({ $id: Now.ID['p_egress'], name: 'x_mcp.executor.run_server_script_enabled', type: 'boolean', value: true })
Property({ $id: Now.ID['p_maxb'], name: 'x_mcp.executor.max_bytes', type: 'integer', value: 32768 })
Property({ $id: Now.ID['p_maxout'], name: 'x_mcp.executor.max_output_bytes', type: 'integer', value: 65536 })
Property({ $id: Now.ID['p_timeout'], name: 'x_mcp.executor.timeout_ms', type: 'integer', value: 30000 })
