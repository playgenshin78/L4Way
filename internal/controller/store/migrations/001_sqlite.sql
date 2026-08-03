CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    desired_generation INTEGER NOT NULL DEFAULT 0 CHECK (desired_generation >= 0),
    applied_generation INTEGER NOT NULL DEFAULT 0 CHECK (applied_generation >= 0),
    applied_desired_checksum TEXT,
    applied_program_checksum TEXT,
    agent_version TEXT,
    capabilities TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(capabilities)),
    wireguard_public_key TEXT,
    last_seen_at DATETIME,
    policy_checked_at DATETIME,
    revoked_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    token_hash BLOB PRIMARY KEY CHECK (length(token_hash) = 32),
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    expires_at DATETIME NOT NULL,
    used_at DATETIME,
    node_key_fingerprint TEXT,
    node_public_key BLOB,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS enrollment_tokens_expiry_idx ON enrollment_tokens(expires_at) WHERE used_at IS NULL;

CREATE TABLE IF NOT EXISTS node_keys (
    fingerprint TEXT PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    public_key BLOB NOT NULL UNIQUE CHECK (length(public_key) = 32),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at DATETIME,
    revoked_at DATETIME
);
CREATE INDEX IF NOT EXISTS node_keys_node_idx ON node_keys(node_id);

CREATE TABLE IF NOT EXISTS node_generations (
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    generation INTEGER NOT NULL CHECK (generation > 0),
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    desired_checksum TEXT NOT NULL,
    desired_state TEXT NOT NULL CHECK (json_valid(desired_state)),
    required_capabilities TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(required_capabilities)),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','applied','retryable_error','permanent_error')),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    applied_at DATETIME,
    PRIMARY KEY(node_id,generation)
);

CREATE TABLE IF NOT EXISTS generation_ack_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    desired_checksum TEXT NOT NULL,
    program_checksum TEXT,
    status TEXT NOT NULL CHECK (status IN ('applied','retryable_error','permanent_error')),
    error_code TEXT NOT NULL,
    error_message TEXT NOT NULL DEFAULT '',
    observed_at DATETIME NOT NULL,
    received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(node_id,generation) REFERENCES node_generations(node_id,generation) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS generation_ack_events_lookup_idx ON generation_ack_events(node_id,generation,received_at DESC);

CREATE TABLE IF NOT EXISTS transactional_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    topic TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    payload TEXT NOT NULL CHECK (json_valid(payload)),
    available_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    leased_by TEXT,
    leased_until DATETIME,
    attempts INTEGER NOT NULL DEFAULT 0,
    delivered_at DATETIME,
    last_error TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS transactional_outbox_ready_idx ON transactional_outbox(available_at,id) WHERE delivered_at IS NULL;

CREATE INDEX IF NOT EXISTS nodes_policy_scan_idx ON nodes(policy_checked_at,id) WHERE revoked_at IS NULL AND desired_generation > 0;
CREATE TABLE IF NOT EXISTS traffic_class_allocations (
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    owner_kind TEXT NOT NULL CHECK (owner_kind IN ('user','forward')),
    owner_id TEXT NOT NULL,
    class_id INTEGER NOT NULL CHECK (class_id BETWEEN 2 AND 65534),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(node_id,owner_kind,owner_id), UNIQUE(node_id,class_id)
);

CREATE TABLE IF NOT EXISTS usage_batches (
    node_id TEXT NOT NULL,
    counter_epoch TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    generation INTEGER NOT NULL CHECK (generation > 0),
    observed_at DATETIME NOT NULL,
    received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(node_id,counter_epoch,sequence),
    FOREIGN KEY(node_id,generation) REFERENCES node_generations(node_id,generation) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS usage_deltas (
    node_id TEXT NOT NULL,
    counter_epoch TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    forward_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK (protocol IN ('tcp','udp')),
    direction TEXT NOT NULL CHECK (direction IN ('upload','download')),
    resource_version INTEGER NOT NULL CHECK (resource_version > 0),
    packets INTEGER NOT NULL CHECK (packets >= 0),
    bytes INTEGER NOT NULL CHECK (bytes >= 0),
    counter_reset INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(node_id,counter_epoch,sequence,forward_id,protocol,direction,resource_version),
    FOREIGN KEY(node_id,counter_epoch,sequence) REFERENCES usage_batches(node_id,counter_epoch,sequence) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS usage_rollups (
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    forward_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK (protocol IN ('tcp','udp')),
    direction TEXT NOT NULL CHECK (direction IN ('upload','download')),
    packets INTEGER NOT NULL DEFAULT 0 CHECK (packets >= 0),
    bytes INTEGER NOT NULL DEFAULT 0 CHECK (bytes >= 0),
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(node_id,forward_id,protocol,direction)
);
CREATE INDEX IF NOT EXISTS usage_rollups_user_idx ON usage_rollups(node_id,user_id);
CREATE TABLE IF NOT EXISTS policy_audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    generation INTEGER NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('forward_quota_pause','user_quota_pause','expiry_pause','drain_force','force_remove')),
    subject_id TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(detail)),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS policy_audit_events_node_idx ON policy_audit_events(node_id,created_at DESC);

CREATE TABLE IF NOT EXISTS node_wireguard_key_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    previous_public_key TEXT,
    public_key TEXT NOT NULL,
    observed_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS node_wireguard_key_events_node_idx ON node_wireguard_key_events(node_id,created_at DESC);
CREATE TABLE IF NOT EXISTS service_vip_allocations (
    service_vip TEXT PRIMARY KEY,
    forward_id TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL,
    ingress_node_id TEXT NOT NULL,
    exit_node_id TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK(ingress_node_id <> exit_node_id)
);
CREATE TABLE IF NOT EXISTS service_vip_bindings (
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    forward_id TEXT NOT NULL,
    service_vip TEXT NOT NULL REFERENCES service_vip_allocations(service_vip) ON DELETE RESTRICT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(node_id,forward_id), UNIQUE(node_id,service_vip)
);
CREATE INDEX IF NOT EXISTS service_vip_bindings_vip_idx ON service_vip_bindings(service_vip);

CREATE TABLE IF NOT EXISTS cluster_plans (
    id TEXT PRIMARY KEY,
    active_revision INTEGER NOT NULL CHECK(active_revision > 0),
    active_checksum TEXT NOT NULL,
    reconcile_after DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_scheduled_at DATETIME,
    last_error TEXT,
    paused_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS cluster_plan_revisions (
    plan_id TEXT NOT NULL REFERENCES cluster_plans(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK(revision > 0),
    checksum TEXT NOT NULL,
    plan TEXT NOT NULL CHECK(json_valid(plan)),
    actor TEXT NOT NULL CHECK(actor <> '' AND length(actor) <= 256),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(plan_id,revision), UNIQUE(plan_id,checksum)
);
CREATE TABLE IF NOT EXISTS node_scheduling_profiles (
    node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    plan_id TEXT NOT NULL REFERENCES cluster_plans(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK(revision > 0),
    enabled INTEGER NOT NULL,
    roles TEXT NOT NULL CHECK(json_valid(roles)),
    labels TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(labels)),
    failure_domain TEXT NOT NULL,
    capacity TEXT NOT NULL CHECK(json_valid(capacity)),
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS node_scheduling_profiles_plan_idx ON node_scheduling_profiles(plan_id,enabled,node_id);
CREATE TABLE IF NOT EXISTS cluster_forward_placements (
    plan_id TEXT NOT NULL REFERENCES cluster_plans(id) ON DELETE CASCADE,
    forward_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    ingress_node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    exit_node_id TEXT REFERENCES nodes(id) ON DELETE RESTRICT,
    backend_id TEXT NOT NULL,
    target TEXT NOT NULL,
    target_port INTEGER NOT NULL CHECK(target_port BETWEEN 1 AND 65535),
    service_vip TEXT,
    fabric_in_id TEXT,
    fabric_out_id TEXT,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(plan_id,forward_id)
);
CREATE INDEX IF NOT EXISTS cluster_forward_placements_nodes_idx ON cluster_forward_placements(plan_id,ingress_node_id,exit_node_id);
CREATE TABLE IF NOT EXISTS backend_health_observations (
    plan_id TEXT NOT NULL REFERENCES cluster_plans(id) ON DELETE CASCADE,
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    pool_id TEXT NOT NULL,
    backend_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation > 0),
    resource_version INTEGER NOT NULL CHECK(resource_version > 0),
    status TEXT NOT NULL CHECK(status IN ('unknown','healthy','unhealthy')),
    latency_milliseconds INTEGER NOT NULL CHECK(latency_milliseconds >= 0),
    error_message TEXT NOT NULL DEFAULT '',
    observed_at DATETIME NOT NULL,
    received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(plan_id,node_id,pool_id,backend_id)
);
CREATE INDEX IF NOT EXISTS backend_health_observations_fresh_idx ON backend_health_observations(plan_id,observed_at DESC);

CREATE TABLE IF NOT EXISTS cluster_rollouts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id TEXT NOT NULL REFERENCES cluster_plans(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK(revision > 0),
    previous_revision INTEGER,
    actor TEXT NOT NULL CHECK(actor <> '' AND length(actor) <= 256),
    action TEXT NOT NULL CHECK(action IN ('apply','health_reconcile','rollback')),
    status TEXT NOT NULL CHECK(status IN ('publishing','awaiting_ack','baking','rollback_pending','rolling_back','completed','rolled_back','failed')),
    detail TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(detail)),
    current_stage INTEGER NOT NULL DEFAULT 1 CHECK(current_stage > 0),
    bake_until DATETIME,
    failure_message TEXT NOT NULL DEFAULT '',
    auto_rollback INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME
);
CREATE INDEX IF NOT EXISTS cluster_rollouts_plan_idx ON cluster_rollouts(plan_id,id DESC);
CREATE INDEX IF NOT EXISTS cluster_rollouts_active_idx ON cluster_rollouts(status,id) WHERE status IN ('publishing','awaiting_ack','baking','rollback_pending','rolling_back');
CREATE TABLE IF NOT EXISTS cluster_rollout_stages (
    rollout_id INTEGER NOT NULL REFERENCES cluster_rollouts(id) ON DELETE CASCADE,
    stage_order INTEGER NOT NULL CHECK(stage_order > 0),
    wave TEXT NOT NULL CHECK(wave IN ('canary','full','compensation')),
    phase TEXT NOT NULL CHECK(phase IN ('prepare','promote','cleanup','bake','compensate')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','awaiting_ack','baking','completed','failed')),
    bake_seconds INTEGER NOT NULL DEFAULT 0 CHECK(bake_seconds BETWEEN 0 AND 86400),
    started_at DATETIME,
    completed_at DATETIME,
    PRIMARY KEY(rollout_id,stage_order)
);
CREATE INDEX IF NOT EXISTS cluster_rollout_stages_active_idx ON cluster_rollout_stages(rollout_id,stage_order) WHERE status IN ('pending','awaiting_ack','baking');
CREATE TABLE IF NOT EXISTS cluster_rollout_nodes (
    rollout_id INTEGER NOT NULL,
    stage_order INTEGER NOT NULL DEFAULT 1 CHECK(stage_order > 0),
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    previous_generation INTEGER NOT NULL CHECK(previous_generation >= 0),
    generation INTEGER,
    desired_checksum TEXT,
    desired_state TEXT NOT NULL CHECK(json_valid(desired_state)),
    status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','pending','applied','retryable_error','permanent_error')),
    error_message TEXT NOT NULL DEFAULT '',
    applied_at DATETIME,
    PRIMARY KEY(rollout_id,stage_order,node_id),
    FOREIGN KEY(rollout_id,stage_order) REFERENCES cluster_rollout_stages(rollout_id,stage_order) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS cluster_rollout_baselines (
    rollout_id INTEGER NOT NULL REFERENCES cluster_rollouts(id) ON DELETE CASCADE,
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    desired_state TEXT NOT NULL CHECK(json_valid(desired_state)),
    PRIMARY KEY(rollout_id,node_id)
);
CREATE TABLE IF NOT EXISTS cluster_audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id TEXT REFERENCES cluster_plans(id) ON DELETE SET NULL,
    revision INTEGER,
    actor TEXT NOT NULL CHECK(actor <> '' AND length(actor) <= 256),
    action TEXT NOT NULL CHECK(action <> '' AND length(action) <= 128),
    subject_id TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(detail)),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS cluster_audit_events_plan_idx ON cluster_audit_events(plan_id,created_at DESC);
CREATE TABLE IF NOT EXISTS cluster_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id TEXT NOT NULL REFERENCES cluster_plans(id) ON DELETE CASCADE,
    forward_id TEXT NOT NULL,
    code TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active','resolved')),
    detail TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(detail)),
    opened_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME,
    UNIQUE(plan_id,forward_id,code)
);
CREATE INDEX IF NOT EXISTS cluster_alerts_active_idx ON cluster_alerts(plan_id,opened_at DESC) WHERE status='active';
