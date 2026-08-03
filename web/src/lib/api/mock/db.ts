import type {
  Account,
  AuditEvent,
  FluxNode,
  Forward,
  InstallCommand,
  Tenant,
} from "../types";

/**
 * Mock 内存数据库（仅开发/测试）。
 * 会话与 CSRF 只保存在内存中，不读写任何 Cookie 或 localStorage，
 * 刷新页面等同于 Cookie 失效，需要重新登录。
 */

const now = Date.now();
const MIN = 60_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;
const iso = (t: number) => new Date(t).toISOString();

/* --------------------------------- 账号 --------------------------------- */

interface StoredAccount extends Account {
  password: string;
}

export const accounts: StoredAccount[] = [
  { id: "u-owner", username: "owner", display_name: "平台管理员", role: "owner", tenant_id: null, password: "owner123" },
  { id: "u-alice", username: "alice", display_name: "Alice（Acme）", role: "tenant", tenant_id: "t-acme", password: "alice123" },
  { id: "u-bob", username: "bob", display_name: "Bob（Orbital）", role: "tenant", tenant_id: "t-orbital", password: "bob123" },
];

/* --------------------------------- 节点 --------------------------------- */

export const nodes: FluxNode[] = [
  {
    id: "fra-01",
    status: "online",
    agent_version: "0.9.4",
    desired_generation: 5,
    applied_generation: 5,
    last_seen_at: iso(now - 20_000),
    labels: ["eu", "de", "ssd"],
    listen_ips: ["203.0.113.10", "203.0.113.11"],
    forwards_count: 6,
    protocol_blocks: { http: false, https: false, socks: false, tls: false },
    created_at: iso(now - 92 * DAY),
    resource_version: 7,
  },
  {
    id: "fra-02",
    status: "online",
    agent_version: "0.9.4",
    desired_generation: 3,
    applied_generation: 3,
    last_seen_at: iso(now - 45_000),
    labels: ["eu", "de"],
    listen_ips: ["203.0.113.20"],
    forwards_count: 4,
    protocol_blocks: { http: true, https: false, socks: true, tls: false },
    created_at: iso(now - 60 * DAY),
    resource_version: 4,
  },
  {
    id: "nyc-01",
    status: "offline",
    agent_version: "0.9.2",
    desired_generation: 8,
    applied_generation: 7,
    last_seen_at: iso(now - 26 * HOUR),
    labels: ["us", "exit"],
    listen_ips: ["198.51.100.10", "198.51.100.11"],
    forwards_count: 3,
    protocol_blocks: { http: false, https: false, socks: false, tls: false },
    created_at: iso(now - 120 * DAY),
    resource_version: 11,
  },
  {
    id: "lon-01",
    status: "revoked",
    agent_version: "0.9.1",
    desired_generation: 2,
    applied_generation: 2,
    last_seen_at: iso(now - 40 * DAY),
    labels: ["uk"],
    listen_ips: ["192.0.2.10"],
    forwards_count: 0,
    protocol_blocks: { http: false, https: false, socks: false, tls: false },
    created_at: iso(now - 140 * DAY),
    resource_version: 3,
  },
];

/* --------------------------------- 租户 --------------------------------- */

export const tenants: Tenant[] = [
  {
    id: "t-acme",
    username: "alice",
    display_name: "Acme 游戏加速",
    status: "active",
    forwards_count: 7,
    expires_at: iso(now + 20 * DAY),
    created_at: iso(now - 88 * DAY),
    resource_version: 5,
  },
  {
    id: "t-orbital",
    username: "bob",
    display_name: "Orbital 工作室",
    status: "active",
    forwards_count: 5,
    expires_at: iso(now + 90 * DAY),
    created_at: iso(now - 45 * DAY),
    resource_version: 2,
  },
];

export const tenantPolicies: Record<string, import("../types").TenantPolicy> = {
  "t-acme": {
    allowed_ingress_nodes: ["fra-01", "fra-02"],
    allowed_exit_nodes: ["nyc-01"],
    allowed_listen_ips: ["203.0.113.10", "203.0.113.11", "203.0.113.20"],
    allowed_port_ranges: [
      { start: 20000, end: 20100 },
      { start: 30000, end: 30100 },
    ],
    allowed_protocols: ["tcp", "udp"],
    allow_via_exit: true,
    max_forwards: 12,
    ingress_rate_limit_bps: 500_000_000,
    egress_rate_limit_bps: 500_000_000,
    traffic_quota_bytes: 500 * 2 ** 30,
    allowed_target_cidrs: ["10.0.0.0/8", "192.168.0.0/16"],
    denied_target_cidrs: ["10.255.0.0/16"],
  },
  "t-orbital": {
    allowed_ingress_nodes: ["fra-01", "nyc-01"],
    allowed_exit_nodes: ["nyc-01"],
    allowed_listen_ips: ["203.0.113.10", "198.51.100.10"],
    allowed_port_ranges: [{ start: 40000, end: 40100 }],
    allowed_protocols: ["tcp"],
    allow_via_exit: false,
    max_forwards: 8,
    ingress_rate_limit_bps: 1_000_000_000,
    egress_rate_limit_bps: 1_000_000_000,
    traffic_quota_bytes: 3 * 2 ** 40,
    allowed_target_cidrs: ["10.20.0.0/16"],
    denied_target_cidrs: [],
  },
};

/* --------------------------------- 转发 --------------------------------- */

let fwdSeq = 0;
function fwd(
  partial: Partial<Forward> &
    Pick<Forward, "tenant_id" | "protocols" | "listen" | "target" | "path_mode" | "ingress_node_id">,
): Forward {
  fwdSeq += 1;
  const tenant = tenants.find((t) => t.id === partial.tenant_id)!;
  const ingress = nodes.find((n) => n.id === partial.ingress_node_id)!;
  const exit = partial.exit_node_id ? nodes.find((n) => n.id === partial.exit_node_id) ?? null : null;
  const createdAgo = (fwdSeq * 3 + 2) * DAY;
  const id = `fw-${String(fwdSeq).padStart(4, "0")}`;
  return {
    id,
    tenant_name: tenant.display_name,
    exit_node_id: exit?.id ?? null,
    exit_node_name: exit?.id ?? null,
    ingress_node_name: ingress.id,
    status: "active",
    enabled: true,
    rate_limit: null,
    traffic_quota_bytes: null,
    expires_at: null,
    editable: true,
    rollout: null,
    created_at: iso(now - createdAgo),
    updated_at: iso(now - createdAgo / 2),
    resource_version: 1,
    ...partial,
  };
}

export const forwards: Forward[] = [
  fwd({ tenant_id: "t-acme", protocols: ["tcp"], listen: { address: "203.0.113.10", port: 20001 }, target: { address: "10.0.1.15", port: 25565 }, path_mode: "direct", ingress_node_id: "fra-01", rate_limit: 200_000_000, traffic_quota_bytes: 100 * 2 ** 30 }),
  fwd({ tenant_id: "t-acme", protocols: ["udp"], listen: { address: "203.0.113.10", port: 20002 }, target: { address: "10.0.1.16", port: 19132 }, path_mode: "direct", ingress_node_id: "fra-01" }),
  fwd({ tenant_id: "t-acme", protocols: ["udp", "tcp"], listen: { address: "203.0.113.11", port: 20010 }, target: { address: "10.0.2.30", port: 27015 }, path_mode: "via_exit", ingress_node_id: "fra-01", exit_node_id: "nyc-01", rate_limit: 300_000_000 }),
  fwd({ tenant_id: "t-acme", protocols: ["udp"], listen: { address: "203.0.113.20", port: 20020 }, target: { address: "10.0.3.8", port: 9987 }, path_mode: "direct", ingress_node_id: "fra-02", status: "paused", enabled: false }),
  fwd({ tenant_id: "t-acme", protocols: ["tcp"], listen: { address: "203.0.113.20", port: 20080 }, target: { address: "192.168.10.4", port: 8080 }, path_mode: "direct", ingress_node_id: "fra-02", expires_at: iso(now + 6 * DAY) }),
  fwd({ tenant_id: "t-acme", protocols: ["udp"], listen: { address: "203.0.113.10", port: 20030 }, target: { address: "10.0.2.44", port: 28015 }, path_mode: "via_exit", ingress_node_id: "fra-01", exit_node_id: "nyc-01" }),
  fwd({ tenant_id: "t-acme", protocols: ["tcp"], listen: { address: "203.0.113.11", port: 20022 }, target: { address: "192.168.10.2", port: 22 }, path_mode: "direct", ingress_node_id: "fra-01", status: "draining", enabled: false }),
  fwd({ tenant_id: "t-acme", protocols: ["udp"], listen: { address: "203.0.113.20", port: 30001 }, target: { address: "10.0.4.9", port: 34197 }, path_mode: "direct", ingress_node_id: "fra-02" }),
  fwd({ tenant_id: "t-orbital", protocols: ["tcp"], listen: { address: "203.0.113.10", port: 40001 }, target: { address: "10.20.0.12", port: 5000 }, path_mode: "direct", ingress_node_id: "fra-01", traffic_quota_bytes: 2 ** 40 }),
  fwd({ tenant_id: "t-orbital", protocols: ["tcp"], listen: { address: "203.0.113.10", port: 40002 }, target: { address: "10.20.0.13", port: 443 }, path_mode: "direct", ingress_node_id: "fra-01", rate_limit: 800_000_000 }),
  fwd({ tenant_id: "t-orbital", protocols: ["tcp"], listen: { address: "198.51.100.10", port: 40010 }, target: { address: "10.20.1.5", port: 8443 }, path_mode: "direct", ingress_node_id: "nyc-01" }),
  fwd({ tenant_id: "t-orbital", protocols: ["tcp"], listen: { address: "198.51.100.10", port: 40011 }, target: { address: "10.20.1.6", port: 8443 }, path_mode: "direct", ingress_node_id: "nyc-01", status: "paused", enabled: false }),
  // 来自手工 Cluster Plan 的转发：面板禁止编辑
  fwd({ tenant_id: "t-orbital", protocols: ["tcp"], listen: { address: "203.0.113.10", port: 40099 }, target: { address: "10.20.9.1", port: 9000 }, path_mode: "direct", ingress_node_id: "fra-01", editable: false }),
];

/* --------------------------------- 审计 --------------------------------- */

let auditSeq = 0;
function audit(e: Omit<AuditEvent, "id" | "resource_name">): AuditEvent {
  auditSeq += 1;
  return { id: `ae-${String(auditSeq).padStart(4, "0")}`, resource_name: e.resource_id || e.resource_type, ...e };
}

export const auditEvents: AuditEvent[] = [
  audit({ created_at: iso(now - 2 * HOUR), actor: "owner", actor_role: "owner", action: "tenant.policy.update", resource_type: "tenant", resource_id: "t-acme", result: "success", source_ip: "10.9.0.2", detail: { changed: ["max_forwards"], from: 10, to: 12 } }),
  audit({ created_at: iso(now - 3 * HOUR), actor: "alice", actor_role: "tenant", action: "forward.update", resource_type: "forward", resource_id: "fw-0004", result: "success", source_ip: "85.214.32.10", detail: { enabled: false, note: "暂停转发" } }),
  audit({ created_at: iso(now - 5 * HOUR), actor: "owner", actor_role: "owner", action: "node.install_command", resource_type: "node", resource_id: "fra-02", result: "success", source_ip: "10.9.0.2", detail: { token_ttl_seconds: 900 } }),
  audit({ created_at: iso(now - 8 * HOUR), actor: "bob", actor_role: "tenant", action: "forward.create", resource_type: "forward", resource_id: "fw-0009", result: "success", source_ip: "91.66.120.7", detail: { listen: "203.0.113.10:40001", target: "10.20.0.12:5000", protocols: ["tcp"] } }),
  audit({ created_at: iso(now - 11 * HOUR), actor: "alice", actor_role: "tenant", action: "forward.delete", resource_type: "forward", resource_id: "fw-0007", result: "success", source_ip: "85.214.32.10", detail: { mode: "drain", drain_seconds: 300 } }),
  audit({ created_at: iso(now - 1 * DAY), actor: "mallory", actor_role: "tenant", action: "auth.login", resource_type: "session", resource_id: "-", result: "failure", source_ip: "185.220.101.4", detail: { reason: "invalid_credentials", attempts: 5 } }),
  audit({ created_at: iso(now - 1.2 * DAY), actor: "alice", actor_role: "tenant", action: "tenant.policy.view", resource_type: "tenant", resource_id: "t-orbital", result: "denied", source_ip: "85.214.32.10", detail: { reason: "cross_tenant_access" } }),
  audit({ created_at: iso(now - 2 * DAY), actor: "bob", actor_role: "tenant", action: "forward.update", resource_type: "forward", resource_id: "fw-0012", result: "success", source_ip: "91.66.120.7", detail: { enabled: false } }),
  audit({ created_at: iso(now - 3 * DAY), actor: "owner", actor_role: "owner", action: "node.install_command", resource_type: "node", resource_id: "lon-01", result: "success", source_ip: "10.9.0.2", detail: { token_ttl_seconds: 3600 } }),
  audit({ created_at: iso(now - 45 * DAY), actor: "owner", actor_role: "owner", action: "tenant.create", resource_type: "tenant", resource_id: "t-orbital", result: "success", source_ip: "10.9.0.2", detail: { username: "bob" } }),
];

/* ------------------------------ 会话（内存） ------------------------------ */

export interface MockSession {
  accountId: string;
  csrf: string;
  expiresAt: number;
}

let session: MockSession | null = null;

export function createSession(accountId: string): MockSession {
  const csrf = `csrf-${Math.random().toString(36).slice(2)}${Math.random().toString(36).slice(2)}`;
  session = { accountId, csrf, expiresAt: Date.now() + 12 * HOUR };
  return session;
}

export function getSession(): MockSession | null {
  if (session && session.expiresAt < Date.now()) {
    session = null;
    return null;
  }
  return session;
}

export function destroySession() {
  session = null;
}

/* ------------------------------ 安装令牌 ------------------------------- */

export interface InstallToken {
  tokenId: string;
  nodeId: string;
  expiresAt: number;
  used: boolean;
}

export const installTokens: InstallToken[] = [];

export function issueInstallCommand(nodeId: string, ttlSeconds: number): InstallCommand {
  const tokenId = `tok_${Math.random().toString(36).slice(2, 12)}`;
  const expiresAt = Date.now() + ttlSeconds * 1000;
  const bundlePayload = {
    v: 1,
    controller_url: "https://ctrl.flux.example.com:9443",
    controller_pubkey: "curve25519:7Hk2d9QpXm4vN8wLsJ3bR6cT1yU0eA5fG8hK2zX9vB4=",
    node_id: nodeId,
    enroll_token: tokenId,
    exp: new Date(expiresAt).toISOString(),
  };
  const bundle = btoa(unescape(encodeURIComponent(JSON.stringify(bundlePayload))));
  installTokens.push({ tokenId, nodeId, expiresAt, used: false });
  return {
    node_id: nodeId,
    token_id: tokenId,
    command: `set -o pipefail; curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 'https://downloads.example/flux/install.sh' | sudo bash -s -- agent --release-url 'https://downloads.example/flux/flux-beta.tar.gz' --bundle-base64 '${bundle}' --enable-fabric`,
    bundle_base64: bundle,
    expires_at: new Date(expiresAt).toISOString(),
  };
}

/* ------------------------------ 幂等与限流 ------------------------------ */

export const idempotencyCache = new Map<string, { status: number; body: unknown }>();
export const loginAttempts = new Map<string, number[]>();

/** 测试辅助：重置运行时状态 */
export function resetMockRuntime() {
  destroySession();
  installTokens.length = 0;
  idempotencyCache.clear();
  loginAttempts.clear();
}
