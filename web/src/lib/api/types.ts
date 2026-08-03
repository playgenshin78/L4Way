/**
 * Flux Controller API v1 类型定义。
 * 与真实后端契约严格一致：
 * - 成功响应：{"data": ...}
 * - 错误响应：{"error": {"code": "...", "message": "..."}}
 */

export type Role = "owner" | "tenant";

export interface Account {
  id: string;
  username: string;
  display_name: string;
  role: Role;
  /** tenant 账号所属租户；owner 为 null */
  tenant_id: string | null;
}

/** 兼容早期页面测试中的命名；运行时仍以 Account 为唯一账号模型。 */
export type User = Account;

export interface LoginRequest {
  username: string;
  password: string;
}

/** login 与 /auth/me 的 data 载荷；csrf_token 仅保存于内存 */
export interface SessionPayload {
  account: Account;
  csrf_token: string;
}

/* ---------------------------------- 转发 ---------------------------------- */

export type Protocol = "tcp" | "udp";
export type PathMode = "direct" | "via_exit";
export type ForwardStatus = "active" | "paused" | "draining" | "force_deleting";

export interface ForwardEndpoint {
  address: string;
  port: number;
}

/**
 * 变更响应中携带的下发状态。没有独立的 rollout 查询接口，
 * 列表同步状态由节点的 desired/applied generation 推导。
 */
export interface Rollout {
  state: "pending" | "applying" | "acked" | "error";
  desired_generation: number;
  last_error: string | null;
}

export interface Forward {
  id: string;
  tenant_id: string;
  tenant_name: string;
  protocols: Protocol[];
  listen: ForwardEndpoint;
  target: ForwardEndpoint;
  path_mode: PathMode;
  ingress_node_id: string;
  ingress_node_name: string;
  exit_node_id: string | null;
  exit_node_name: string | null;
  status: ForwardStatus;
  enabled: boolean;
  /** 速率上限，单位 bps；null 为不限 */
  rate_limit: number | null;
  traffic_quota_bytes: number | null;
  expires_at: string | null;
  /** false 表示该转发来自手工或复杂 Cluster Plan，面板禁止编辑 */
  editable: boolean;
  /** 仅变更响应中携带；查询响应不保证返回 */
  rollout?: Rollout | null;
  created_at: string;
  updated_at: string;
  resource_version: number;
}

export interface ForwardCreateInput {
  /** 仅 Owner 可选；Tenant 由后端从会话推断 */
  tenant_id?: string;
  protocols: Protocol[];
  listen: ForwardEndpoint;
  target: ForwardEndpoint;
  path_mode: PathMode;
  ingress_node_id: string;
  exit_node_id: string | null;
  rate_limit: number | null;
  traffic_quota_bytes: number | null;
  expires_at: string | null;
  enabled: boolean;
}

export interface ForwardUpdateInput {
  protocols?: Protocol[];
  listen?: ForwardEndpoint;
  target?: ForwardEndpoint;
  rate_limit?: number | null;
  traffic_quota_bytes?: number | null;
  expires_at?: string | null;
  /** 暂停 / 恢复通过 PATCH enabled 实现 */
  enabled?: boolean;
  resource_version: number;
}

export type ForwardDeleteMode = "drain" | "force";

export interface ForwardListQuery {
  page?: number;
  page_size?: number;
  search?: string;
  status?: ForwardStatus | "";
  protocol?: Protocol | "";
}

export interface ForwardTCPCheck {
  forward_id: string;
  reachable: boolean;
  latency_ms: number;
  checked_at: string;
  execution_node_id: string;
  message: string;
}

/* ---------------------------------- 节点 ---------------------------------- */

export type NodeStatus = "pending" | "online" | "offline" | "revoked";

export interface NodeProtocolBlocks {
  http: boolean;
  https: boolean;
  socks: boolean;
  tls: boolean;
}

export interface FluxNode {
  id: string;
  status: NodeStatus;
  agent_version: string | null;
  desired_generation: number;
  applied_generation: number;
  last_seen_at: string | null;
  labels: string[];
  listen_ips: string[];
  forwards_count: number;
  protocol_blocks: NodeProtocolBlocks;
  created_at: string;
  resource_version: number;
}

export interface NodeProtocolBlocksUpdate {
  resource_version: number;
  protocol_blocks: NodeProtocolBlocks;
}

export interface InstallCommandRequest {
  node_id: string;
  /** token 有效期，秒 */
  token_ttl_seconds: number;
}

export interface InstallCommand {
  node_id: string;
  token_id: string;
  command: string;
  bundle_base64: string;
  expires_at: string;
}

export interface NodeActionResponse {
  node_id: string;
  status: "restarting" | "uninstalled";
  message: string;
}

/* ---------------------------------- 租户 ---------------------------------- */

export type TenantStatus = "active" | "disabled";

export interface PortRange {
  start: number;
  end: number;
}

export interface TenantPolicy {
  allowed_ingress_nodes: string[];
  allowed_exit_nodes: string[];
  allowed_listen_ips: string[];
  allowed_port_ranges: PortRange[];
  allowed_protocols: Protocol[];
  allow_via_exit: boolean;
  max_forwards: number;
  ingress_rate_limit_bps: number | null;
  egress_rate_limit_bps: number | null;
  traffic_quota_bytes: number | null;
  allowed_target_cidrs: string[];
  denied_target_cidrs: string[];
}

export interface Tenant {
  id: string;
  username: string;
  display_name: string;
  status: TenantStatus;
  forwards_count: number;
  expires_at: string | null;
  created_at: string;
  resource_version: number;
}

export interface TenantCreateInput {
  username: string;
  display_name: string;
  password: string;
  policy: TenantPolicy;
}

export interface TenantUpdateInput {
  status?: TenantStatus;
  expires_at?: string | null;
  resource_version: number;
}

export interface TenantPolicyResponse {
  tenant_id: string;
  resource_version: number;
  policy: TenantPolicy;
}

export interface TenantPolicyUpdate {
  resource_version: number;
  policy: Partial<TenantPolicy>;
}

/* ---------------------------------- 审计 ---------------------------------- */

export type AuditResult = "success" | "failure" | "denied";

export interface AuditEvent {
  id: string;
  created_at: string;
  actor: string;
  actor_role: Role;
  action: string;
  resource_type: string;
  resource_id: string;
  resource_name: string;
  result: AuditResult;
  source_ip: string;
  detail: Record<string, unknown>;
}

export interface AuditListQuery {
  page?: number;
  page_size?: number;
  action?: string;
  result?: AuditResult | "";
  actor?: string;
}

/* ---------------------------------- 流量 ---------------------------------- */

export interface UsageSeriesPoint {
  ts: string;
  bytes: number;
}

export interface UsageByForward {
  forward_id: string;
  name: string;
  protocol: Protocol;
  bytes: number;
}

export interface UsageSummary {
  measurement: string;
  range_days: number;
  series: UsageSeriesPoint[];
  by_forward: UsageByForward[];
  quota: {
    used_bytes: number;
    quota_bytes: number | null;
  };
  rate_limit_mbps: number | null;
  expires_at: string | null;
}

/* ---------------------------------- 系统 ---------------------------------- */

export interface SystemStatus {
  controller_version: string;
  agent_min_version: string;
  encryption: string;
  uptime_seconds: number;
  sqlite: {
    path: string;
    size_bytes: number;
    wal_enabled: boolean;
    healthy: boolean;
  };
  last_backup_at: string | null;
  nodes_online: number;
  nodes_total: number;
}

export interface BackupResult {
  backup_id: string;
  created_at: string;
  size_bytes: number;
}

/* --------------------------------- 通用 ---------------------------------- */

export interface Paginated<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface ApiSuccess<T> {
  data: T;
}

export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
  };
}
