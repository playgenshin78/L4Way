import { Badge } from "@/components/ui/badge";
import type { ForwardStatus, NodeStatus, TenantStatus } from "@/lib/api/types";
import { cn } from "@/lib/utils";

const forwardMap: Record<ForwardStatus, { label: string; variant: "success" | "secondary" | "warning" | "destructive" }> = {
  active: { label: "运行中", variant: "success" },
  paused: { label: "已暂停", variant: "secondary" },
  draining: { label: "平滑删除中", variant: "warning" },
  force_deleting: { label: "立即删除中", variant: "destructive" },
};

const nodeMap: Record<NodeStatus, { label: string; variant: "success" | "secondary" | "warning" | "destructive"; dot: string }> = {
  pending: { label: "待注册", variant: "warning", dot: "bg-warning" },
  online: { label: "在线", variant: "success", dot: "bg-success" },
  offline: { label: "离线", variant: "secondary", dot: "bg-muted-foreground" },
  revoked: { label: "已停用", variant: "destructive", dot: "bg-destructive" },
};

const tenantMap: Record<TenantStatus, { label: string; variant: "success" | "secondary" }> = {
  active: { label: "正常", variant: "success" },
  disabled: { label: "已禁用", variant: "secondary" },
};

export function ForwardStatusBadge({ status }: { status: ForwardStatus }) {
  const m = forwardMap[status];
  return <Badge variant={m.variant}>{m.label}</Badge>;
}

export function NodeStatusBadge({ status }: { status: NodeStatus }) {
  const m = nodeMap[status];
  return (
    <Badge variant={m.variant}>
      <span className={cn("h-1.5 w-1.5 rounded-full", m.dot)} aria-hidden />
      {m.label}
    </Badge>
  );
}

export function TenantStatusBadge({ status }: { status: TenantStatus }) {
  const m = tenantMap[status];
  return <Badge variant={m.variant}>{m.label}</Badge>;
}
