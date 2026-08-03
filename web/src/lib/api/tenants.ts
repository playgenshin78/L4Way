import { apiConfig, makeIdempotencyKey, request } from "./client";
import type {
  Paginated,
  Tenant,
  TenantCreateInput,
  TenantPolicyResponse,
  TenantPolicyUpdate,
  TenantUpdateInput,
} from "./types";

interface RawTenant {
  id: string;
  name?: string;
  username?: string;
  display_name?: string;
  status: Tenant["status"];
  forwards_count?: number;
  expires_at?: string;
  created_at: string;
  resource_version: number;
}

interface RawPolicy {
  tenant_id: string;
  resource_version: number;
  allowed_ingress_nodes: string[] | null;
  allowed_exit_nodes: string[] | null;
  allowed_listen_ips: string[] | null;
  allowed_port_ranges: TenantPolicyResponse["policy"]["allowed_port_ranges"] | null;
  allowed_protocols: TenantPolicyResponse["policy"]["allowed_protocols"] | null;
  allow_via_exit: boolean | null;
  max_forwards: number | null;
  ingress_rate_limit_bps: number | null;
  egress_rate_limit_bps: number | null;
  traffic_quota_bytes: number | null;
  allowed_target_cidrs: string[] | null;
  denied_target_cidrs: string[] | null;
}

function toTenant(raw: RawTenant): Tenant {
  return {
    id: raw.id,
    username: raw.username ?? raw.id,
    display_name: raw.display_name ?? raw.name ?? raw.id,
    status: raw.status,
    forwards_count: raw.forwards_count ?? 0,
    expires_at: raw.expires_at ?? null,
    created_at: raw.created_at,
    resource_version: raw.resource_version,
  };
}

function toPolicy(raw: RawPolicy): TenantPolicyResponse {
  return {
    tenant_id: raw.tenant_id,
    resource_version: raw.resource_version,
    policy: {
      allowed_ingress_nodes: raw.allowed_ingress_nodes ?? [],
      allowed_exit_nodes: raw.allowed_exit_nodes ?? [],
      allowed_listen_ips: raw.allowed_listen_ips ?? [],
      allowed_port_ranges: raw.allowed_port_ranges ?? [],
      allowed_protocols: raw.allowed_protocols ?? [],
      allow_via_exit: raw.allow_via_exit ?? false,
      max_forwards: raw.max_forwards ?? 0,
      ingress_rate_limit_bps: raw.ingress_rate_limit_bps || null,
      egress_rate_limit_bps: raw.egress_rate_limit_bps || null,
      traffic_quota_bytes: raw.traffic_quota_bytes || null,
      allowed_target_cidrs: raw.allowed_target_cidrs ?? [],
      denied_target_cidrs: raw.denied_target_cidrs ?? [],
    },
  };
}

function fromPolicy(resourceVersion: number, policy: TenantPolicyResponse["policy"]) {
  return {
    resource_version: resourceVersion,
    ...policy,
    ingress_rate_limit_bps: policy.ingress_rate_limit_bps ?? 0,
    egress_rate_limit_bps: policy.egress_rate_limit_bps ?? 0,
    traffic_quota_bytes: policy.traffic_quota_bytes ?? 0,
  };
}

export async function listTenants(): Promise<Paginated<Tenant>> {
  if (apiConfig.USE_MOCK) return request<Paginated<Tenant>>("/tenants");
  const raw = await request<{ items: RawTenant[]; total?: number }>("/tenants?limit=200");
  const items = raw.items.map(toTenant);
  return { items, total: raw.total ?? items.length, page: 1, page_size: 200 };
}

export async function getTenant(id: string) {
  return toTenant(await request<RawTenant>(`/tenants/${id}`));
}

export async function createTenant(input: TenantCreateInput, idempotencyKey = makeIdempotencyKey()) {
  if (apiConfig.USE_MOCK) {
    return request<Tenant>("/tenants", { method: "POST", body: input, idempotencyKey });
  }
  const raw = await request<{ tenant: RawTenant }>("/tenants", {
    method: "POST",
    body: { ...input, name: input.display_name },
    idempotencyKey,
  });
  return toTenant(raw.tenant);
}

export async function updateTenant(id: string, input: TenantUpdateInput) {
  return toTenant(await request<RawTenant>(`/tenants/${id}`, { method: "PATCH", body: input }));
}

export async function getTenantPolicy(id: string) {
  if (apiConfig.USE_MOCK) return request<TenantPolicyResponse>(`/tenants/${id}/policy`);
  return toPolicy(await request<RawPolicy>(`/tenants/${id}/policy`));
}

export async function updateTenantPolicy(id: string, input: TenantPolicyUpdate) {
  if (apiConfig.USE_MOCK) {
    return request<TenantPolicyResponse>(`/tenants/${id}/policy`, { method: "PATCH", body: input });
  }
  const current = await getTenantPolicy(id);
  const merged = { ...current.policy, ...input.policy };
  const raw = await request<RawPolicy>(`/tenants/${id}/policy`, {
    method: "PATCH",
    body: fromPolicy(input.resource_version, merged),
  });
  return toPolicy(raw);
}
