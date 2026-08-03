import { AlertCircle, CheckCircle2, CloudUpload, Loader2 } from "lucide-react";

import type { FluxNode, Forward } from "@/lib/api/types";
import { getRecentRollout } from "./hooks";

/**
 * 下发同步状态：
 * 1. 优先消费变更响应中携带的 rollout（正在下发 / last_error）
 * 2. 否则由节点 desired/applied generation 推导（等待 Agent ACK / 已同步）
 */
export function SyncStatus({ forward, node }: { forward: Forward; node: FluxNode | undefined }) {
  const rollout = getRecentRollout(forward.id);

  if (rollout?.state === "error") {
    return (
      <span className="flex items-center gap-1 text-xs text-destructive">
        <AlertCircle className="h-3 w-3" aria-hidden />
        同步失败，请检查节点状态
      </span>
    );
  }

  if (rollout && rollout.state !== "acked") {
    return (
      <span className="flex items-center gap-1 text-xs text-muted-foreground">
        <CloudUpload className="h-3 w-3" aria-hidden />
        正在同步
      </span>
    );
  }

  if (node && node.desired_generation > node.applied_generation) {
    return (
      <span className="flex items-center gap-1 text-xs text-warning">
        <Loader2 className="h-3 w-3 animate-spin" aria-hidden />
        等待节点确认
      </span>
    );
  }

  if (forward.status === "active") {
    return (
      <span className="flex items-center gap-1 text-xs text-muted-foreground">
        <CheckCircle2 className="h-3 w-3 text-success" aria-hidden />
        已同步
      </span>
    );
  }

  return null;
}
