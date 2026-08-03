import type {
  Account,
  AuditEvent,
  AuditListQuery,
  BackupResult,
  Forward,
  ForwardCreateInput,
  ForwardListQuery,
  ForwardUpdateInput,
  InstallCommand,
  InstallCommandRequest,
  LoginRequest,
  NodeStatus,
  Paginated,
  SessionPayload,
  SystemStatus,
  Tenant,
  TenantCreateInput,
  TenantPolicyResponse,
  TenantPolicyUpdate,
  TenantUpdateInput,
  UsageSummary,
} from "../types";
import {
  accounts,
  auditEvents,
  createSession,
  destroySession,
  forwards,
  getSession,
  idempotencyCache,
  issueInstallCommand,
  loginAttempts,
  nodes,
  tenantPolicies,
  tenants,
} from "./db";

/**
 * 自写 Mock adapter：以 fetch 签名实现，严格遵守真实 Controller API 契约。
 * - 成功响应 {"data": ...}，错误响应 {"error": {code, message}}
 * - CSRF 从 login / /auth/me 响应下发，写操作校验 X-CSRF-Token
 * - 不包含任何虚构端点；生产构建默认不启用（见 client.ts）
 */

const IS_TEST = import.meta.env.MODE === "test";
const MIN_LATENCY = IS_TEST ? 0 : 120;
const MAX_LATENCY = IS_TEST ? 0 : 400;
let latestMockBackup: BackupResult | null = null;

function latency() {
  const ms = MIN_LATENCY + Math.random() * (MAX_LATENCY - MIN_LATENCY);
  return new Promise((r) => setTimeout(r, ms));
}

function ok(data: unknown, status = 200): Response {
  return new Response(JSON.stringify({ data }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function err(status: number, code: string, message: string): Response {
  return new Response(JSON.stringify({ error: { code, message } }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

type Ctx = {
  method: string;
  params: URLSearchParams;
  headers: Headers;
  body: unknown;
  account: Account;
};

type Handler = (ctx: Ctx, match: RegExpMatchArray) => Response;

interface Route {
  method: string;
  pattern: RegExp;
  auth: "public" | "session" | "owner";
  handler: Handler;
}

const routes: Route[] = [];

function route(method: string, pattern: string, auth: Route["auth"], handler: Handler) {
  const regex = new RegExp(`^${pattern.replace(/:(\w+)/g, "(?<$1>[^/]+)")}$`);
  routes.push({ method, pattern: regex, auth, handler });
}

function paginate<T>(items: T[], params: URLSearchParams): Paginated<T> {
  const page = Math.max(1, Number(params.get("page") ?? 1) || 1);
  const pageSize = Math.min(100, Math.max(1, Number(params.get("page_size") ?? 10)) || 10);
  const start = (page - 1) * pageSize;
  return { items: items.slice(start, start + pageSize), total: items.length, page, page_size: pageSize };
}

function publicAccount(a: (typeof accounts)[number]): Account {
  const { password: _pw, ...rest } = a;
  return rest;
}

function addAudit(e: Omit<AuditEvent, "id" | "created_at" | "resource_name">) {
  auditEvents.unshift({
    id: `ae-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 5)}`,
    created_at: new Date().toISOString(),
    resource_name: e.resource_id || e.resource_type,
    ...e,
  });
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const v = Number(p);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = (n << 8) | v;
  }
  return n >>> 0;
}

function ipInCidr(ip: string, cidr: string): boolean {
  const [base, bitsRaw] = cidr.split("/");
  const bits = Number(bitsRaw);
  const ipN = ipv4ToInt(ip);
  const baseN = ipv4ToInt(base ?? "");
  if (ipN === null || baseN === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  if (bits === 0) return true;
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return (ipN & mask) === (baseN & mask);
}

function mockResolvedTarget(value: string, allowedCidrs: string[]): string {
  if (ipv4ToInt(value) !== null) return value;
  const [base] = (allowedCidrs[0] ?? "").split("/");
  return ipv4ToInt(base ?? "") === null ? "192.0.2.1" : (base as string);
}

/** 数据面变更：提升入口节点 desired generation，模拟 Agent 异步应用 */
function bumpGeneration(nodeId: string): number {
  const node = nodes.find((n) => n.id === nodeId);
  if (!node) return 0;
  node.desired_generation += 1;
  const target = node.desired_generation;
  if (IS_TEST) {
    node.applied_generation = target;
  } else {
    setTimeout(() => {
      node.applied_generation = target;
    }, 900);
  }
  return target;
}

function rolloutFor(nodeId: string): NonNullable<Forward["rollout"]> {
  return { state: "pending", desired_generation: bumpGeneration(nodeId), last_error: null };
}

/* --------------------------------- 认证 --------------------------------- */

route("POST", "/auth/login", "public", ({ body }) => {
  const { username, password } = (body ?? {}) as LoginRequest;
  const key = String(username ?? "").toLowerCase();

  const attempts = (loginAttempts.get(key) ?? []).filter((t) => Date.now() - t < 10 * 60_000);
  if (attempts.length >= 5) {
    loginAttempts.set(key, attempts);
    return err(429, "rate_limited", "尝试次数过多，请 10 分钟后再试");
  }

  const account = accounts.find((a) => a.username.toLowerCase() === key);
  if (!account || account.password !== password) {
    attempts.push(Date.now());
    loginAttempts.set(key, attempts);
    return err(401, "invalid_credentials", "用户名或密码错误");
  }

  loginAttempts.delete(key);
  const session = createSession(account.id);
  addAudit({
    actor: account.username,
    actor_role: account.role,
    action: "auth.login",
    resource_type: "session",
    resource_id: account.id,
    result: "success",
    source_ip: "127.0.0.1",
    detail: {},
  });
  const payload: SessionPayload = { account: publicAccount(account), csrf_token: session.csrf };
  return ok(payload);
});

route("POST", "/auth/logout", "session", ({ account }) => {
  addAudit({
    actor: account.username,
    actor_role: account.role,
    action: "auth.logout",
    resource_type: "session",
    resource_id: account.id,
    result: "success",
    source_ip: "127.0.0.1",
    detail: {},
  });
  destroySession();
  return ok({ ok: true });
});

route("GET", "/auth/me", "session", ({ account }) => {
  const session = getSession()!;
  const payload: SessionPayload = { account, csrf_token: session.csrf };
  return ok(payload);
});

/* --------------------------------- 租户 --------------------------------- */

route("GET", "/tenants", "owner", ({ params }) => ok(paginate([...tenants], params)));

route("POST", "/tenants", "owner", ({ account, body, headers }) => {
  const idem = headers.get("Idempotency-Key");
  if (idem && idempotencyCache.has(idem)) {
    const cached = idempotencyCache.get(idem)!;
    return ok(cached.body, cached.status);
  }
  const input = (body ?? {}) as TenantCreateInput;
  if (!input.username || !/^[a-z0-9_]{3,24}$/.test(input.username))
    return err(400, "validation_error", "用户名需为 3-24 位小写字母、数字或下划线");
  if (accounts.some((a) => a.username === input.username) || tenants.some((t) => t.username === input.username))
    return err(409, "name_conflict", "用户名已存在");
  if (!input.password || input.password.length < 12) return err(400, "validation_error", "初始密码至少 12 位");

  const tenant: Tenant = {
    id: `t-${input.username}`,
    username: input.username,
    display_name: input.display_name || input.username,
    status: "active",
    forwards_count: 0,
    expires_at: input.policy?.allowed_target_cidrs ? null : null,
    created_at: new Date().toISOString(),
    resource_version: 1,
  };
  tenants.push(tenant);
  tenantPolicies[tenant.id] = input.policy;
  accounts.push({
    id: `u-${input.username}`,
    username: input.username,
    display_name: tenant.display_name,
    role: "tenant",
    tenant_id: tenant.id,
    password: input.password,
  });
  addAudit({
    actor: account.username,
    actor_role: account.role,
    action: "tenant.create",
    resource_type: "tenant",
    resource_id: tenant.id,
    result: "success",
    source_ip: "127.0.0.1",
    detail: { username: tenant.username },
  });
  if (idem) idempotencyCache.set(idem, { status: 201, body: tenant });
  return ok(tenant, 201);
});

route("GET", "/tenants/:id", "owner", (_ctx, match) => {
  const tenant = tenants.find((t) => t.id === match.groups!.id);
  if (!tenant) return err(404, "not_found", "租户不存在");
  return ok(tenant);
});

route("PATCH", "/tenants/:id", "owner", ({ account, body }, match) => {
  const tenant = tenants.find((t) => t.id === match.groups!.id);
  if (!tenant) return err(404, "not_found", "租户不存在");
  const input = (body ?? {}) as TenantUpdateInput;
  if (input.resource_version !== tenant.resource_version)
    return err(409, "version_conflict", "数据已变化，请刷新后再编辑");
  if (input.status) tenant.status = input.status;
  if (input.expires_at !== undefined) tenant.expires_at = input.expires_at;
  tenant.resource_version += 1;
  addAudit({
    actor: account.username,
    actor_role: account.role,
    action: "tenant.update",
    resource_type: "tenant",
    resource_id: tenant.id,
    result: "success",
    source_ip: "127.0.0.1",
    detail: { status: input.status, expires_at: input.expires_at },
  });
  return ok(tenant);
});

route("GET", "/tenants/:id/policy", "session", ({ account }, match) => {
  const tenant = tenants.find((t) => t.id === match.groups!.id);
  if (!tenant) return err(404, "not_found", "租户不存在");
  if (account.role !== "owner" && account.tenant_id !== tenant.id)
    return err(403, "forbidden", "无权查看其他租户的策略");
  const res: TenantPolicyResponse = {
    tenant_id: tenant.id,
    resource_version: tenant.resource_version,
    policy: tenantPolicies[tenant.id],
  };
  return ok(res);
});

route("PATCH", "/tenants/:id/policy", "owner", ({ account, body }, match) => {
  const tenant = tenants.find((t) => t.id === match.groups!.id);
  if (!tenant) return err(404, "not_found", "租户不存在");
  const input = (body ?? {}) as TenantPolicyUpdate;
  if (input.resource_version !== tenant.resource_version)
    return err(409, "version_conflict", "数据已变化，请刷新后再编辑");
  tenantPolicies[tenant.id] = { ...tenantPolicies[tenant.id], ...input.policy };
  tenant.resource_version += 1;
  addAudit({
    actor: account.username,
    actor_role: account.role,
    action: "tenant.policy.update",
    resource_type: "tenant",
    resource_id: tenant.id,
    result: "success",
    source_ip: "127.0.0.1",
    detail: { changed: Object.keys(input.policy) },
  });
  const res: TenantPolicyResponse = {
    tenant_id: tenant.id,
    resource_version: tenant.resource_version,
    policy: tenantPolicies[tenant.id],
  };
  return ok(res);
});

/* --------------------------------- 节点 --------------------------------- */

function visibleNodes(account: Account) {
  if (account.role === "owner") return nodes;
  const policy = account.tenant_id ? tenantPolicies[account.tenant_id] : null;
  if (!policy) return [];
  const allowed = new Set([...policy.allowed_ingress_nodes, ...policy.allowed_exit_nodes]);
  return nodes.filter((n) => allowed.has(n.id) && n.status !== "revoked");
}

route("GET", "/nodes", "session", ({ account }) => {
  const items = visibleNodes(account);
  return ok({ items, total: items.length, page: 1, page_size: items.length });
});

route("POST", "/nodes/install-command", "owner", ({ account, body }) => {
  const input = (body ?? {}) as InstallCommandRequest;
  if (!input.node_id || !/^[a-z0-9][a-z0-9-]{1,30}$/.test(input.node_id))
    return err(400, "validation_error", "node_id 需为 2-31 位小写字母、数字或短横线");
  const ttl = input.token_ttl_seconds ?? 900;
  if (!Number.isInteger(ttl) || ttl < 60 || ttl > 86400)
    return err(400, "validation_error", "安装命令有效期需在 60–86400 秒之间");

  let node = nodes.find((n) => n.id === input.node_id);
  if (node?.status === "revoked") return err(409, "invalid_state", "该节点已被吊销，请更换 node_id");
  if (!node) {
    node = {
      id: input.node_id,
      status: "pending" satisfies NodeStatus,
      agent_version: null,
      desired_generation: 0,
      applied_generation: 0,
      last_seen_at: null,
      labels: [],
      listen_ips: [],
      forwards_count: 0,
      protocol_blocks: { http: false, https: false, socks: false, tls: false },
      created_at: new Date().toISOString(),
      resource_version: 1,
    };
    nodes.push(node);
  } else if (node.status === "offline") {
    node.status = "pending";
  }

  const cmd: InstallCommand = issueInstallCommand(node.id, ttl);
  addAudit({
    actor: account.username,
    actor_role: account.role,
    action: "node.install_command",
    resource_type: "node",
    resource_id: node.id,
    result: "success",
    source_ip: "127.0.0.1",
    detail: { token_ttl_seconds: ttl },
  });
  return ok(cmd, 201);
});

route("DELETE", "/nodes/:id", "owner", ({ account }, match) => {
  const index = nodes.findIndex((node) => node.id === match.groups!.id);
  if (index < 0) return err(404, "not_found", "节点不存在");
  const node = nodes[index];
  const canDelete =
    node.status === "pending" &&
    !node.agent_version &&
    node.desired_generation === 0 &&
    node.applied_generation === 0;
  if (!canDelete) return err(409, "node_delete_conflict", "仅能删除尚未注册的待处理节点");
  nodes.splice(index, 1);
  addAudit({
    actor: account.username,
    actor_role: account.role,
    action: "node.delete",
    resource_type: "node",
    resource_id: node.id,
    result: "success",
    source_ip: "127.0.0.1",
    detail: { state: "pending" },
  });
  return new Response(null, { status: 204 });
});

route("PATCH", "/nodes/:id/protocol-blocks", "owner", ({ account, body }, match) => {
  const node = nodes.find((item) => item.id === match.groups!.id);
  if (!node) return err(404, "not_found", "节点不存在");
  if (node.status === "pending" || node.status === "revoked")
    return err(409, "invalid_state", "节点完成接入后才能设置协议拦截");
  const input = (body ?? {}) as { resource_version?: number; protocol_blocks?: Partial<typeof node.protocol_blocks> };
  if (input.resource_version !== node.resource_version)
    return err(409, "version_conflict", "数据已变化，请刷新后再编辑");
  const blocks = input.protocol_blocks;
  if (!blocks || [blocks.http, blocks.https, blocks.socks, blocks.tls].some((value) => typeof value !== "boolean"))
    return err(400, "validation_error", "协议拦截设置不完整");
  node.protocol_blocks = { http: blocks.http!, https: blocks.https!, socks: blocks.socks!, tls: blocks.tls! };
  node.resource_version += 1;
  node.desired_generation += 1;
  addAudit({
    actor: account.username,
    actor_role: account.role,
    action: "node.protocol_blocks.update",
    resource_type: "node",
    resource_id: node.id,
    result: "success",
    source_ip: "127.0.0.1",
    detail: { protocol_blocks: node.protocol_blocks },
  });
  return new Response(null, { status: 204 });
});

route("POST", "/nodes/:id/upgrade", "owner", ({ account }, match) => {
  const node = nodes.find((item) => item.id === match.groups!.id);
  if (!node) return err(404, "not_found", "节点不存在");
  if (node.status !== "online") return err(409, "node_offline", "节点当前离线，无法执行操作");
  node.agent_version = "beta.latest";
  node.last_seen_at = new Date().toISOString();
  addAudit({
    actor: account.username,
    actor_role: account.role,
    action: "node.upgrade",
    resource_type: "node",
    resource_id: node.id,
    result: "success",
    source_ip: "127.0.0.1",
    detail: {},
  });
  return ok({ node_id: node.id, status: "restarting", message: "新版 Agent 已校验并安装，节点正在重启" }, 202);
});

route("POST", "/nodes/:id/uninstall", "owner", ({ account }, match) => {
  const node = nodes.find((item) => item.id === match.groups!.id);
  if (!node) return err(404, "not_found", "节点不存在");
  if (node.status !== "online") return err(409, "node_offline", "节点当前离线，无法执行操作");
  if (forwards.some((forward) => forward.ingress_node_id === node.id || forward.exit_node_id === node.id))
    return err(409, "node_in_use", "请先迁移或删除这个节点承载的全部转发");
  if (node.desired_generation !== node.applied_generation)
    return err(409, "node_not_synced", "节点配置尚未同步完成，暂时不能卸载");
  node.status = "revoked";
  node.last_seen_at = null;
  addAudit({
    actor: account.username,
    actor_role: account.role,
    action: "node.uninstall",
    resource_type: "node",
    resource_id: node.id,
    result: "success",
    source_ip: "127.0.0.1",
    detail: { identity_revoked: true },
  });
  return ok({ node_id: node.id, status: "uninstalled", message: "Agent 已卸载，节点身份已吊销" }, 202);
});

/* --------------------------------- 转发 --------------------------------- */

function visibleForwards(account: Account): Forward[] {
  const all = account.role === "owner" ? forwards : forwards.filter((f) => f.tenant_id === account.tenant_id);
  return [...all].sort((a, b) => b.updated_at.localeCompare(a.updated_at));
}

route("GET", "/forwards", "session", ({ account, params }) => {
  if (account.role === "owner" && nodes.length === 0) {
    return err(409, "cluster_plan_not_configured", "节点网络尚未完成初始化");
  }
  const q: ForwardListQuery = {
    search: params.get("search") ?? "",
    status: (params.get("status") ?? "") as ForwardListQuery["status"],
    protocol: (params.get("protocol") ?? "") as ForwardListQuery["protocol"],
  };
  let items = visibleForwards(account);
  if (q.search) {
    const s = q.search.toLowerCase();
    items = items.filter((f) =>
      [f.id, f.target.address, f.listen.address, f.tenant_name, f.ingress_node_name]
        .join(" ")
        .toLowerCase()
        .includes(s),
    );
  }
  if (q.status) items = items.filter((f) => f.status === q.status);
  if (q.protocol) items = items.filter((f) => f.protocols.includes(q.protocol as Forward["protocols"][number]));
  return ok(paginate(items, params));
});

function findForwardForUser(account: Account, id: string): Forward | null {
  const f = forwards.find((x) => x.id === id);
  if (!f) return null;
  if (account.role !== "owner" && f.tenant_id !== account.tenant_id) return null;
  return f;
}

route("POST", "/forwards/:id/tcp-check", "session", ({ account }, match) => {
  const forward = findForwardForUser(account, match.groups!.id);
  if (!forward) return err(404, "not_found", "转发不存在或无权访问");
  if (!forward.protocols.includes("tcp")) return err(409, "tcp_not_enabled", "这条转发没有启用 TCP，无法执行 TCP 检查");
  const executionNodeId = forward.path_mode === "via_exit" ? forward.exit_node_id : forward.ingress_node_id;
  const node = nodes.find((item) => item.id === executionNodeId);
  if (!node || node.status !== "online") return err(409, "node_offline", "节点当前离线，无法执行操作");
  addAudit({
    actor: account.username,
    actor_role: account.role,
    action: "forward.tcp_check",
    resource_type: "forward",
    resource_id: forward.id,
    result: "success",
    source_ip: "127.0.0.1",
    detail: { reachable: true, latency_ms: 12.4, execution_node_id: executionNodeId },
  });
  return ok({
    forward_id: forward.id,
    reachable: true,
    latency_ms: 12.4,
    checked_at: new Date().toISOString(),
    execution_node_id: executionNodeId,
    message: "",
  });
});

route("GET", "/forwards/:id", "session", ({ account }, match) => {
  const f = findForwardForUser(account, match.groups!.id);
  if (!f) return err(404, "not_found", "转发不存在或无权访问");
  return ok(f);
});

/** 租户策略校验，返回错误消息或 null */
function checkPolicy(account: Account, tenantId: string, input: ForwardCreateInput): string | null {
  if (account.role === "owner") return null;
  const p = tenantPolicies[tenantId];
  if (!p) return "当前账号没有关联租户策略";
  const current = forwards.filter((f) => f.tenant_id === tenantId).length;
  if (current >= p.max_forwards) return `已达到转发数量上限（${p.max_forwards} 条），请联系管理员`;
  const badProto = input.protocols.filter((x) => !p.allowed_protocols.includes(x));
  if (badProto.length > 0) return `协议 ${badProto.join("/").toUpperCase()} 未在你的许可范围内`;
  if (!p.allowed_ingress_nodes.includes(input.ingress_node_id)) return "所选入口节点未分配给你";
  if (input.path_mode === "via_exit") {
    if (!p.allow_via_exit) return "你的账号未开通隧道转发";
    if (!input.exit_node_id || !p.allowed_exit_nodes.includes(input.exit_node_id)) return "所选出口节点未分配给你";
  }
  if (!p.allowed_listen_ips.includes(input.listen.address)) return "所选监听地址未分配给你";
  const inRange = p.allowed_port_ranges.some((r) => input.listen.port >= r.start && input.listen.port <= r.end);
  if (!inRange) return "监听端口不在分配给你的端口范围内";
  const resolvedTarget = mockResolvedTarget(input.target.address, p.allowed_target_cidrs);
  if (p.denied_target_cidrs.some((c) => ipInCidr(resolvedTarget, c)))
    return `目标地址 ${input.target.address} 位于禁止网段内`;
  if (!p.allowed_target_cidrs.some((c) => ipInCidr(resolvedTarget, c)))
    return `目标地址 ${input.target.address} 不在允许的目标网段内`;
  if (input.rate_limit !== null) {
    const cap = Math.min(p.ingress_rate_limit_bps ?? Infinity, p.egress_rate_limit_bps ?? Infinity);
    if (input.rate_limit > cap) return `限速不能超过你的带宽上限（${Math.round(cap / 1_000_000)} Mbps）`;
  }
  const tenant = tenants.find((t) => t.id === tenantId);
  if (input.expires_at && tenant?.expires_at && input.expires_at > tenant.expires_at)
    return "转发到期时间不能晚于你的账号到期时间";
  return null;
}

route("POST", "/forwards", "session", ({ account, body, headers }) => {
  if (nodes.length === 0) return err(409, "cluster_plan_not_configured", "节点网络尚未完成初始化");
  const idem = headers.get("Idempotency-Key");
  if (idem && idempotencyCache.has(idem)) {
    const cached = idempotencyCache.get(idem)!;
    return ok(cached.body, cached.status);
  }
  const input = (body ?? {}) as ForwardCreateInput;
  if (!Array.isArray(input.protocols) || input.protocols.length === 0)
    return err(400, "validation_error", "至少选择一种协议");

  const tenantId = account.role === "owner" ? (input.tenant_id || "owner") : account.tenant_id;
  const tenant = tenants.find((t) => t.id === tenantId);
  const ownerForward = account.role === "owner" && tenantId === "owner";
  if (!tenant && !ownerForward)
    return err(400, "validation_error", account.role === "owner" ? "请选择归属" : "当前账号没有关联租户");

  const policyError = checkPolicy(account, tenantId ?? "", input);
  if (policyError) return err(403, "policy_violation", policyError);

  const node = nodes.find((n) => n.id === input.ingress_node_id);
  if (!node) return err(400, "validation_error", "入口节点不存在");
  if (!node.listen_ips.includes(input.listen.address)) return err(400, "validation_error", "该监听地址不属于所选节点");
  const exit = input.exit_node_id ? nodes.find((n) => n.id === input.exit_node_id) : null;
  if (input.path_mode === "via_exit" && !exit) return err(400, "validation_error", "隧道转发需要选择出口节点");

  const conflict = forwards.some(
    (f) =>
      f.ingress_node_id === node.id &&
      f.listen.address === input.listen.address &&
      f.listen.port === input.listen.port &&
      f.status !== "force_deleting",
  );
  if (conflict) return err(409, "listen_conflict", "该监听地址与端口已被占用");

  const nowIso = new Date().toISOString();
  const created: Forward = {
    id: `fw-${Date.now().toString(36)}`,
    tenant_id: tenantId ?? "",
    tenant_name: ownerForward ? "管理员自用" : tenant!.display_name,
    protocols: input.protocols,
    listen: input.listen,
    target: input.target,
    path_mode: input.path_mode,
    ingress_node_id: node.id,
    ingress_node_name: node.id,
    exit_node_id: exit?.id ?? null,
    exit_node_name: exit?.id ?? null,
    status: input.enabled === false ? "paused" : "active",
    enabled: input.enabled !== false,
    rate_limit: input.rate_limit ?? null,
    traffic_quota_bytes: input.traffic_quota_bytes ?? null,
    expires_at: input.expires_at ?? null,
    editable: true,
    rollout: rolloutFor(node.id),
    created_at: nowIso,
    updated_at: nowIso,
    resource_version: 1,
  };
  forwards.unshift(created);
  if (tenant) tenant.forwards_count += 1;
  node.forwards_count += 1;
  addAudit({
    actor: account.username,
    actor_role: account.role,
    action: "forward.create",
    resource_type: "forward",
    resource_id: created.id,
    result: "success",
    source_ip: "127.0.0.1",
    detail: { listen: `${created.listen.address}:${created.listen.port}`, protocols: created.protocols },
  });
  if (idem) idempotencyCache.set(idem, { status: 201, body: created });
  return ok(created, 201);
});

route("PATCH", "/forwards/:id", "session", ({ account, body }, match) => {
  const f = findForwardForUser(account, match.groups!.id);
  if (!f) return err(404, "not_found", "转发不存在或无权访问");
  const input = (body ?? {}) as ForwardUpdateInput;
  if (input.resource_version !== f.resource_version)
    return err(409, "version_conflict", "数据已变化，请刷新后再编辑");
  if (f.status === "draining" || f.status === "force_deleting")
    return err(409, "invalid_state", "转发正在删除中，无法修改");

  const keys = Object.keys(input).filter((k) => k !== "resource_version");
  const configKeys = keys.filter((k) => k !== "enabled");
  if (!f.editable && configKeys.length > 0)
    return err(403, "not_editable", "此转发由外部配置管理，不能在网页中编辑");

  // enabled 切换：暂停 / 恢复
  if (input.enabled !== undefined && keys.length === 1) {
    if (input.enabled && f.status === "active") return err(409, "invalid_state", "转发已处于运行状态");
    if (!input.enabled && f.status === "paused") return err(409, "invalid_state", "转发已处于暂停状态");
    f.enabled = input.enabled;
    f.status = input.enabled ? "active" : "paused";
  } else {
    // 配置修改走策略校验（租户）
    if (account.role !== "owner") {
      const merged: ForwardCreateInput = {
        protocols: input.protocols ?? f.protocols,
        listen: input.listen ?? f.listen,
        target: input.target ?? f.target,
        path_mode: f.path_mode,
        ingress_node_id: f.ingress_node_id,
        exit_node_id: f.exit_node_id,
        rate_limit: input.rate_limit !== undefined ? input.rate_limit : f.rate_limit,
        traffic_quota_bytes: null,
        expires_at: input.expires_at !== undefined ? input.expires_at : f.expires_at,
        enabled: f.enabled,
      };
      const policyError = checkPolicy(account, f.tenant_id, merged);
      if (policyError) return err(403, "policy_violation", policyError);
    }
    if (input.listen) {
      const conflict = forwards.some(
        (x) =>
          x.id !== f.id &&
          x.ingress_node_id === f.ingress_node_id &&
          x.listen.address === input.listen!.address &&
          x.listen.port === input.listen!.port,
      );
      if (conflict) return err(409, "listen_conflict", "该监听地址与端口已被占用");
    }
    const { resource_version: _rv, enabled: _en, ...patch } = input;
    Object.assign(f, patch);
  }

  f.updated_at = new Date().toISOString();
  f.resource_version += 1;
  f.rollout = rolloutFor(f.ingress_node_id);
  addAudit({
    actor: account.username,
    actor_role: account.role,
    action: "forward.update",
    resource_type: "forward",
    resource_id: f.id,
    result: "success",
    source_ip: "127.0.0.1",
    detail: { changed: keys, enabled: f.enabled },
  });
  return ok(f);
});

route("DELETE", "/forwards/:id", "session", ({ account, params }, match) => {
  const f = findForwardForUser(account, match.groups!.id);
  if (!f) return err(404, "not_found", "转发不存在或无权访问");

  const rv = Number(params.get("resource_version"));
  if (!Number.isInteger(rv)) return err(400, "validation_error", "缺少 resource_version");
  if (rv !== f.resource_version) return err(409, "version_conflict", "数据已变化，请刷新后再编辑");

  const mode = params.get("mode") === "force" ? "force" : "drain";
  const drainSeconds = params.get("drain_seconds") !== null ? Number(params.get("drain_seconds")) : 300;
  if (mode === "drain" && (!Number.isInteger(drainSeconds) || drainSeconds < 30 || drainSeconds > 86400))
    return err(400, "validation_error", "drain_seconds 需在 30–86400 秒之间");
  if (f.status === "force_deleting") return err(409, "invalid_state", "转发正在强制删除中");

  f.resource_version += 1;
  f.updated_at = new Date().toISOString();

  if (mode === "drain") {
    if (f.status !== "draining") {
      f.status = "draining";
      f.enabled = false;
    }
    f.rollout = rolloutFor(f.ingress_node_id);
    addAudit({
      actor: account.username,
      actor_role: account.role,
      action: "forward.delete",
      resource_type: "forward",
      resource_id: f.id,
      result: "success",
      source_ip: "127.0.0.1",
      detail: { mode: "drain", drain_seconds: drainSeconds },
    });
    return ok(f);
  }

  // force：立即中断并清理 conntrack，稍后从列表移除
  f.status = "force_deleting";
  f.enabled = false;
  f.rollout = rolloutFor(f.ingress_node_id);
  const remove = () => {
    const idx = forwards.indexOf(f);
    if (idx >= 0) {
      forwards.splice(idx, 1);
      const tenant = tenants.find((t) => t.id === f.tenant_id);
      if (tenant) tenant.forwards_count = Math.max(0, tenant.forwards_count - 1);
      const node = nodes.find((n) => n.id === f.ingress_node_id);
      if (node) node.forwards_count = Math.max(0, node.forwards_count - 1);
    }
  };
  if (IS_TEST) remove();
  else setTimeout(remove, 4000);
  addAudit({
    actor: account.username,
    actor_role: account.role,
    action: "forward.delete",
    resource_type: "forward",
    resource_id: f.id,
    result: "success",
    source_ip: "127.0.0.1",
    detail: { mode: "force", conntrack_cleanup: true },
  });
  return ok(f);
});

/* --------------------------------- 审计 --------------------------------- */

route("GET", "/audit", "owner", ({ params }) => {
  const q: AuditListQuery = {
    action: params.get("action") ?? "",
    result: (params.get("result") ?? "") as AuditListQuery["result"],
    actor: params.get("actor") ?? "",
  };
  let items = [...auditEvents].sort((a, b) => b.created_at.localeCompare(a.created_at));
  if (q.action) items = items.filter((e) => e.action.startsWith(q.action!));
  if (q.result) items = items.filter((e) => e.result === q.result);
  if (q.actor) items = items.filter((e) => e.actor.toLowerCase().includes(q.actor!.toLowerCase()));
  return ok(paginate(items, params));
});

route("GET", "/usage", "session", ({ account, params }) => {
  const parsedDays = Number(params.get("days") ?? 30);
  const days = parsedDays === 7 || parsedDays === 90 ? parsedDays : 30;
  const visible = visibleForwards(account);
  const series = Array.from({ length: days }, (_, index) => {
    const ts = new Date(Date.now() - (days - index - 1) * 86_400_000);
    const bytes = visible.length === 0 ? 0 : Math.round((index + 1) * visible.length * 18_000_000);
    return { ts: ts.toISOString(), bytes };
  });
  const tenant = account.tenant_id ? tenants.find((item) => item.id === account.tenant_id) : null;
  const policy = account.tenant_id ? tenantPolicies[account.tenant_id] : null;
  const result: UsageSummary = {
    measurement: "L3 bytes including IP headers and retransmissions",
    range_days: days,
    series,
    by_forward: visible.slice(0, 8).map((forward, index) => ({
      forward_id: forward.id,
      name: `${forward.listen.address}:${forward.listen.port}`,
      protocol: forward.protocols[0] ?? "tcp",
      bytes: (index + 1) * 640_000_000,
    })),
    quota: {
      used_bytes: series.reduce((total, point) => total + point.bytes, 0),
      quota_bytes: policy?.traffic_quota_bytes ?? null,
    },
    rate_limit_mbps: policy?.ingress_rate_limit_bps ? policy.ingress_rate_limit_bps / 1_000_000 : null,
    expires_at: tenant?.expires_at ?? null,
  };
  return ok(result);
});

route("GET", "/system/status", "owner", () => {
  const result: SystemStatus = {
    controller_version: "dev",
    agent_min_version: "dev",
    encryption: "Noise IK / X25519 / AES-256-GCM / SHA-256",
    uptime_seconds: 86_400,
    sqlite: { path: "./state/flux.db", size_bytes: 2_621_440, wal_enabled: true, healthy: true },
    last_backup_at: latestMockBackup?.created_at ?? null,
    nodes_online: nodes.filter((node) => node.status === "online").length,
    nodes_total: nodes.length,
  };
  return ok(result);
});

route("POST", "/system/backup", "owner", () => {
  latestMockBackup = {
    backup_id: `flux-backup-${Date.now()}`,
    created_at: new Date().toISOString(),
    size_bytes: 2_621_440,
  };
  return ok(latestMockBackup, 201);
});

route("POST", "/system/backup/download", "owner", () => {
  if (!latestMockBackup) return err(404, "backup_not_found", "还没有可下载的备份");
  return new Response(new Blob(["flux mock backup"], { type: "application/gzip" }), {
    status: 200,
    headers: {
      "Content-Type": "application/gzip",
      "Content-Disposition": `attachment; filename="${latestMockBackup.backup_id}.tar.gz"`,
      "Cache-Control": "no-store",
    },
  });
});

/* -------------------------------- 路由器 -------------------------------- */

export async function mockFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  await latency();

  const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url, "http://mock.local");
  const path = url.pathname.replace(/^\/api\/v1/, "") || "/";
  const method = (init?.method ?? "GET").toUpperCase();
  const headers = new Headers(init?.headers);

  let body: unknown = undefined;
  if (typeof init?.body === "string" && init.body.length > 0) {
    try {
      body = JSON.parse(init.body);
    } catch {
      return err(400, "bad_json", "请求体不是合法 JSON");
    }
  }

  const matched = routes.find((r) => r.method === method && r.pattern.test(path));
  if (!matched) return err(404, "not_found", `接口不存在：${method} ${path}`);

  const session = getSession();

  if (matched.auth !== "public") {
    if (!session) return err(401, "unauthorized", "会话已失效，请重新登录");
    if (method !== "GET") {
      const token = headers.get("X-CSRF-Token");
      if (!token || token !== session.csrf) return err(403, "csrf_mismatch", "CSRF 校验失败，请刷新页面后重试");
    }
  }

  const stored = session ? (accounts.find((a) => a.id === session.accountId) ?? null) : null;
  if (matched.auth !== "public" && !stored) return err(401, "unauthorized", "会话已失效，请重新登录");
  if (matched.auth === "owner" && stored!.role !== "owner") return err(403, "forbidden", "该操作需要管理员权限");

  const match = path.match(matched.pattern)!;
  return matched.handler(
    { method, params: url.searchParams, headers, body, account: (stored ? publicAccount(stored) : null) as Account },
    match,
  );
}
