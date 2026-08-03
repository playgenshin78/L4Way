CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
    expires_at DATETIME,
    resource_version INTEGER NOT NULL DEFAULT 1 CHECK (resource_version > 0),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    tenant_id TEXT REFERENCES tenants(id) ON DELETE CASCADE,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE CHECK (length(username) BETWEEN 3 AND 64),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 128),
    role TEXT NOT NULL CHECK (role IN ('owner','tenant')),
    password_hash TEXT NOT NULL CHECK (length(password_hash) BETWEEN 32 AND 512),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
    failed_login_count INTEGER NOT NULL DEFAULT 0 CHECK (failed_login_count >= 0),
    locked_until DATETIME,
    expires_at DATETIME,
    resource_version INTEGER NOT NULL DEFAULT 1 CHECK (resource_version > 0),
    last_login_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK ((role='owner' AND tenant_id IS NULL) OR (role='tenant' AND tenant_id IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS accounts_single_owner_idx ON accounts(role) WHERE role='owner';
CREATE INDEX IF NOT EXISTS accounts_tenant_idx ON accounts(tenant_id,status);

CREATE TABLE IF NOT EXISTS tenant_policies (
    tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    allowed_ingress_nodes TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(allowed_ingress_nodes)),
    allowed_exit_nodes TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(allowed_exit_nodes)),
    allowed_listen_ips TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(allowed_listen_ips)),
    allowed_port_ranges TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(allowed_port_ranges)),
    allowed_protocols TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(allowed_protocols)),
    allow_via_exit INTEGER NOT NULL DEFAULT 0 CHECK (allow_via_exit IN (0,1)),
    max_forwards INTEGER NOT NULL DEFAULT 0 CHECK (max_forwards BETWEEN 0 AND 1000000),
    ingress_rate_limit_bps INTEGER NOT NULL DEFAULT 0 CHECK (ingress_rate_limit_bps >= 0),
    egress_rate_limit_bps INTEGER NOT NULL DEFAULT 0 CHECK (egress_rate_limit_bps >= 0),
    traffic_quota_bytes INTEGER NOT NULL DEFAULT 0 CHECK (traffic_quota_bytes >= 0),
    allowed_target_cidrs TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(allowed_target_cidrs)),
    denied_target_cidrs TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(denied_target_cidrs)),
    resource_version INTEGER NOT NULL DEFAULT 1 CHECK (resource_version > 0),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS management_sessions (
    token_hash BLOB PRIMARY KEY CHECK (length(token_hash) = 32),
    csrf_hash BLOB NOT NULL CHECK (length(csrf_hash) = 32),
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at DATETIME,
    remote_ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS management_sessions_account_idx ON management_sessions(account_id,expires_at);
CREATE INDEX IF NOT EXISTS management_sessions_expiry_idx ON management_sessions(expires_at) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS management_audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_account_id TEXT REFERENCES accounts(id) ON DELETE SET NULL,
    actor_username TEXT NOT NULL DEFAULT '',
    actor_role TEXT NOT NULL DEFAULT '' CHECK (actor_role IN ('','owner','tenant','system')),
    tenant_id TEXT REFERENCES tenants(id) ON DELETE SET NULL,
    action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 128),
    resource_type TEXT NOT NULL CHECK (length(resource_type) BETWEEN 1 AND 64),
    resource_id TEXT NOT NULL DEFAULT '',
    outcome TEXT NOT NULL CHECK (outcome IN ('success','denied','error')),
    source_ip TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(detail)),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS management_audit_created_idx ON management_audit_events(created_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS management_audit_tenant_idx ON management_audit_events(tenant_id,created_at DESC);
