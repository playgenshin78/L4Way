import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import * as api from "@/lib/api/nodes";
import { ApiError } from "@/lib/api/client";
import type { InstallCommandRequest, NodeProtocolBlocksUpdate } from "@/lib/api/types";

export const nodeKeys = {
  all: ["nodes"] as const,
};

/** Owner 得到全部节点；Tenant 得到后端返回的授权子集 */
export function useNodes(enabled = true) {
  return useQuery({
    queryKey: nodeKeys.all,
    queryFn: api.listNodes,
    enabled,
    refetchInterval: 30_000,
  });
}

export function useInstallCommand() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: InstallCommandRequest) => api.createInstallCommand(input),
    onSuccess: () => void qc.invalidateQueries({ queryKey: nodeKeys.all }),
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "生成安装命令失败"),
  });
}

export function useDeletePendingNode() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (nodeId: string) => api.deletePendingNode(nodeId),
    onSuccess: (_data, nodeId) => {
      toast.success(`节点「${nodeId}」已删除`);
      void qc.invalidateQueries({ queryKey: nodeKeys.all });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "删除节点失败"),
  });
}

export function useUpdateNodeProtocolBlocks() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ nodeId, input }: { nodeId: string; input: NodeProtocolBlocksUpdate }) =>
      api.updateNodeProtocolBlocks(nodeId, input),
    onSuccess: async () => {
      toast.success("节点协议拦截已保存");
      await qc.invalidateQueries({ queryKey: nodeKeys.all });
    },
    onError: (e) => {
      toast.error(e instanceof ApiError ? e.message : "保存节点协议拦截失败");
      void qc.invalidateQueries({ queryKey: nodeKeys.all });
    },
  });
}

export function useUpgradeNode() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (nodeId: string) => api.upgradeNode(nodeId),
    onSuccess: (result) => {
      toast.success(result.message);
      void qc.invalidateQueries({ queryKey: nodeKeys.all });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "升级 Agent 失败"),
  });
}

export function useUninstallNode() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (nodeId: string) => api.uninstallNode(nodeId),
    onSuccess: (result) => {
      toast.success(result.message);
      void qc.invalidateQueries({ queryKey: nodeKeys.all });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "卸载 Agent 失败"),
  });
}
