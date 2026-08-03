import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import * as api from "@/lib/api/tenants";
import { ApiError } from "@/lib/api/client";
import type { TenantCreateInput, TenantPolicyUpdate, TenantUpdateInput } from "@/lib/api/types";

export const tenantKeys = {
  all: ["tenants"] as const,
  detail: (id: string) => ["tenants", id] as const,
  policy: (id: string) => ["tenants", id, "policy"] as const,
};

export function useTenants(enabled = true) {
  return useQuery({ queryKey: tenantKeys.all, queryFn: api.listTenants, enabled });
}

export function useTenant(id: string, enabled = true) {
  return useQuery({
    queryKey: tenantKeys.detail(id),
    queryFn: () => api.getTenant(id),
    enabled: enabled && Boolean(id),
  });
}

export function useTenantPolicy(id: string, enabled = true) {
  return useQuery({
    queryKey: tenantKeys.policy(id),
    queryFn: () => api.getTenantPolicy(id),
    enabled: enabled && Boolean(id),
  });
}

export function useCreateTenant() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: TenantCreateInput) => api.createTenant(input),
    onSuccess: (t) => {
      toast.success(`租户「${t.display_name}」已创建`);
      void qc.invalidateQueries({ queryKey: tenantKeys.all });
    },
  });
}

export function useUpdateTenant(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: TenantUpdateInput) => api.updateTenant(id, input),
    onSuccess: (t) => {
      toast.success("租户信息已更新");
      qc.setQueryData(tenantKeys.detail(id), t);
      void qc.invalidateQueries({ queryKey: tenantKeys.all });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "操作失败"),
  });
}

export function useUpdateTenantPolicy(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: TenantPolicyUpdate) => api.updateTenantPolicy(id, input),
    onSuccess: (data) => {
      toast.success("权限设置已保存并立即生效");
      qc.setQueryData(tenantKeys.policy(id), data);
      void qc.invalidateQueries({ queryKey: tenantKeys.detail(id) });
    },
  });
}
