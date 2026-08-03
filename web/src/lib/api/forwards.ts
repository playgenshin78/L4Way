import { apiConfig, makeIdempotencyKey, request } from "./client";
import type {
  Forward,
  ForwardCreateInput,
  ForwardDeleteMode,
  ForwardListQuery,
  ForwardTCPCheck,
  ForwardUpdateInput,
  Paginated,
} from "./types";

interface RawRateLimit {
  ingress_bits_per_second: number;
  egress_bits_per_second: number;
  burst_bytes: number;
}

interface RawTrafficQuota {
  bytes: number;
  policy: "pause";
}

interface RawForward {
  id: string;
  tenant_id: string;
  tenant_name?: string;
  protocols: Forward["protocols"];
  listen: Forward["listen"];
  target: Forward["target"];
  path_mode: Forward["path_mode"];
  ingress_node_id: string;
  ingress_node_name?: string;
  exit_node_id?: string;
  exit_node_name?: string;
  rate_limit?: RawRateLimit;
  traffic_quota?: RawTrafficQuota;
  expires_at?: string;
  lifecycle: Forward["status"];
  resource_version: number;
  editable: boolean;
}

interface RawMutation {
  forward: RawForward;
  rollout: {
    scheduled?: boolean;
    revision?: number;
    last_error?: string;
  };
}

function qs(query: Record<string, string | number | undefined>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== "") p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

function rateLimit(value: number | null | undefined): RawRateLimit | undefined {
  if (value == null) return undefined;
  return {
    ingress_bits_per_second: value,
    egress_bits_per_second: value,
    burst_bytes: Math.max(64 * 1024, Math.ceil(value / 80)),
  };
}

function quota(value: number | null | undefined): RawTrafficQuota | undefined {
  return value == null ? undefined : { bytes: value, policy: "pause" };
}

function toForward(raw: RawForward): Forward {
  if ("status" in raw && "enabled" in raw) {
    return raw as unknown as Forward;
  }
  const rate = raw.rate_limit
    ? Math.max(raw.rate_limit.ingress_bits_per_second, raw.rate_limit.egress_bits_per_second)
    : null;
  return {
    ...raw,
    tenant_name: raw.tenant_name ?? (raw.tenant_id === "owner" ? "管理员" : raw.tenant_id),
    ingress_node_name: raw.ingress_node_name ?? raw.ingress_node_id,
    exit_node_id: raw.exit_node_id ?? null,
    exit_node_name: raw.exit_node_name ?? raw.exit_node_id ?? null,
    status: raw.lifecycle,
    enabled: raw.lifecycle === "active",
    rate_limit: rate,
    traffic_quota_bytes: raw.traffic_quota?.bytes ?? null,
    expires_at: raw.expires_at ?? null,
    created_at: "",
    updated_at: "",
  };
}

function toMutation(raw: RawMutation | RawForward): Forward {
  if (!("forward" in raw)) return toForward(raw);
  const forward = toForward(raw.forward);
  forward.rollout = {
    state: raw.rollout.last_error ? "error" : raw.rollout.scheduled ? "pending" : "acked",
    desired_generation: raw.rollout.revision ?? 0,
    last_error: raw.rollout.last_error ?? null,
  };
  return forward;
}

function createBody(input: ForwardCreateInput) {
  return {
    tenant_id: input.tenant_id,
    protocols: input.protocols,
    listen: input.listen,
    target: input.target,
    path_mode: input.path_mode,
    ingress_node_id: input.ingress_node_id,
    exit_node_id: input.exit_node_id ?? undefined,
    rate_limit: rateLimit(input.rate_limit),
    traffic_quota: quota(input.traffic_quota_bytes),
    expires_at: input.expires_at,
    enabled: input.enabled,
  };
}

export async function listForwards(query: ForwardListQuery): Promise<Paginated<Forward>> {
  if (apiConfig.USE_MOCK) {
    return request<Paginated<Forward>>(`/forwards${qs({ ...query })}`);
  }
  const raw = await request<{ items: RawForward[] }>("/forwards");
  const search = query.search?.trim().toLowerCase() ?? "";
  const filtered = raw.items.map(toForward).filter((item) => {
    if (query.status && item.status !== query.status) return false;
    if (query.protocol && !item.protocols.includes(query.protocol)) return false;
    if (!search) return true;
    return [
      item.id,
      item.tenant_name,
      item.listen.address,
      String(item.listen.port),
      item.target.address,
      String(item.target.port),
    ].some((value) => value.toLowerCase().includes(search));
  });
  const page = Math.max(1, query.page ?? 1);
  const pageSize = Math.max(1, query.page_size ?? 20);
  const start = (page - 1) * pageSize;
  return { items: filtered.slice(start, start + pageSize), total: filtered.length, page, page_size: pageSize };
}

async function getRawForward(id: string) {
  return request<RawForward>(`/forwards/${id}`);
}

export async function getForward(id: string) {
  return toForward(await getRawForward(id));
}

export async function createForward(input: ForwardCreateInput, idempotencyKey = makeIdempotencyKey()) {
  const result = await request<RawMutation | RawForward>("/forwards", {
    method: "POST",
    body: apiConfig.USE_MOCK ? input : createBody(input),
    idempotencyKey,
  });
  return toMutation(result);
}

export async function updateForward(id: string, input: ForwardUpdateInput) {
  if (apiConfig.USE_MOCK) {
    return request<Forward>(`/forwards/${id}`, { method: "PATCH", body: input });
  }
  const current = await getRawForward(id);
  const body = {
    tenant_id: current.tenant_id,
    protocols: input.protocols ?? current.protocols,
    listen: input.listen ?? current.listen,
    target: input.target ?? current.target,
    path_mode: current.path_mode,
    ingress_node_id: current.ingress_node_id,
    exit_node_id: current.exit_node_id,
    rate_limit:
      input.rate_limit === undefined ? current.rate_limit : rateLimit(input.rate_limit),
    traffic_quota:
      input.traffic_quota_bytes === undefined ? current.traffic_quota : quota(input.traffic_quota_bytes),
    expires_at: input.expires_at === undefined ? current.expires_at : input.expires_at,
    enabled: input.enabled,
    resource_version: input.resource_version,
  };
  return toMutation(await request<RawMutation>(`/forwards/${id}`, { method: "PATCH", body }));
}

/** 暂停 / 恢复通过 PATCH enabled 实现 */
export function setForwardEnabled(id: string, enabled: boolean, resourceVersion: number) {
  return updateForward(id, { enabled, resource_version: resourceVersion });
}

export interface DeleteForwardParams {
  id: string;
  mode: ForwardDeleteMode;
  resourceVersion: number;
  /** 仅 drain 模式：30–86400 秒 */
  drainSeconds?: number;
}

export function deleteForward({ id, mode, resourceVersion, drainSeconds }: DeleteForwardParams) {
  const q = qs({ mode, resource_version: resourceVersion, drain_seconds: mode === "drain" ? drainSeconds : undefined });
  if (apiConfig.USE_MOCK) {
    return request<Forward>(`/forwards/${id}${q}`, { method: "DELETE" });
  }
  return request<RawMutation>(`/forwards/${id}${q}`, { method: "DELETE" }).then(toMutation);
}

export function checkForwardTCP(id: string) {
  return request<ForwardTCPCheck>(`/forwards/${encodeURIComponent(id)}/tcp-check`, { method: "POST" });
}
