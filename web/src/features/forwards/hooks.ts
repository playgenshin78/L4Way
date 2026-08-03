import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import * as api from "@/lib/api/forwards";
import { ApiError } from "@/lib/api/client";
import type { Forward, ForwardCreateInput, ForwardListQuery, ForwardUpdateInput, Rollout } from "@/lib/api/types";

export const forwardKeys = {
  all: ["forwards"] as const,
  list: (q: ForwardListQuery) => ["forwards", "list", q] as const,
};

export function useForwards(query: ForwardListQuery) {
  return useQuery({
    queryKey: forwardKeys.list(query),
    queryFn: () => api.listForwards(query),
    placeholderData: (prev) => prev,
  });
}

/* ------------------------- rollout 客户端暂存 ------------------------- */
// 真实 API 没有 rollout 查询接口：仅保留变更响应中携带的 rollout，
// 用于短时间内展示"正在下发 / 等待 Agent ACK / last_error"。
const ROLLOUT_TTL_MS = 30_000;
const rolloutStore = new Map<string, { rollout: Rollout; at: number }>();

export function recordRollout(forward: Forward) {
  if (forward.rollout) {
    rolloutStore.set(forward.id, { rollout: forward.rollout, at: Date.now() });
  }
}

export function getRecentRollout(forwardId: string): Rollout | null {
  const entry = rolloutStore.get(forwardId);
  if (!entry) return null;
  if (Date.now() - entry.at > ROLLOUT_TTL_MS) {
    rolloutStore.delete(forwardId);
    return null;
  }
  return entry.rollout;
}

function invalidateForwards(qc: ReturnType<typeof useQueryClient>) {
  void qc.invalidateQueries({ queryKey: forwardKeys.all });
  void qc.invalidateQueries({ queryKey: ["nodes"] });
  void qc.invalidateQueries({ queryKey: ["tenants"] });
}

export function useCreateForward() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: ForwardCreateInput) => api.createForward(input),
    onSuccess: (f) => {
      recordRollout(f);
      toast.success(`转发 ${f.id} 已创建，正在同步`);
      invalidateForwards(qc);
    },
  });
}

export function useUpdateForward() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, input }: { id: string; input: ForwardUpdateInput }) => api.updateForward(id, input),
    onSuccess: (f) => {
      recordRollout(f);
      toast.success(`转发 ${f.id} 已更新，正在同步`);
      invalidateForwards(qc);
    },
  });
}

/** 暂停 / 恢复：PATCH enabled */
export function useSetForwardEnabled() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, enabled, resourceVersion }: { id: string; enabled: boolean; resourceVersion: number }) =>
      api.setForwardEnabled(id, enabled, resourceVersion),
    onSuccess: (f) => {
      recordRollout(f);
      toast.success(f.enabled ? `转发 ${f.id} 已恢复` : `转发 ${f.id} 已暂停`);
      invalidateForwards(qc);
    },
    onError: (e) => {
      toast.error(e instanceof ApiError ? e.message : "操作失败");
      // 版本冲突等场景下刷新列表以获取最新 resource_version
      invalidateForwards(qc);
    },
  });
}

export function useDeleteForward() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (params: api.DeleteForwardParams) => api.deleteForward(params),
    onSuccess: (f, vars) => {
      recordRollout(f);
      toast.success(
        vars.mode === "drain"
          ? `转发 ${f.id} 正在平滑删除，现有连接结束后会自动清除`
          : `转发 ${f.id} 已立即删除`,
      );
      invalidateForwards(qc);
    },
    onError: (e) => {
      toast.error(e instanceof ApiError ? e.message : "删除失败");
      invalidateForwards(qc);
    },
  });
}

export function useCheckForwardTCP() {
  return useMutation({
    mutationFn: (forwardId: string) => api.checkForwardTCP(forwardId),
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "TCP 检查失败"),
  });
}
