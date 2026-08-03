import { Plus, Server } from "lucide-react";
import { useState } from "react";

import { EmptyState } from "@/components/shared/empty-state";
import { ErrorState } from "@/components/shared/error-state";
import { PageHeader } from "@/components/shared/page-header";
import { NodeStatusBadge } from "@/components/shared/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useMe } from "@/features/auth/hooks";
import type { FluxNode } from "@/lib/api/types";
import { useOnline } from "@/lib/hooks/use-online";
import { formatRelative } from "@/lib/utils";
import { useNodes } from "./hooks";
import { InstallCommandDialog } from "./install-command-dialog";
import { NodeDetailSheet } from "./node-detail-sheet";

function SyncBadge({ node }: { node: FluxNode }) {
  if (node.status === "pending") return <span className="text-xs text-muted-foreground">—</span>;
  if (node.desired_generation > node.applied_generation) {
    return <span className="text-xs font-medium text-warning">等待节点确认</span>;
  }
  return <span className="text-xs text-muted-foreground">已同步</span>;
}

export function NodesPage() {
  const { data: me } = useMe();
  const isOwner = me?.account.role === "owner";
  const online = useOnline();
  const nodes = useNodes();

  const [detail, setDetail] = useState<FluxNode | null>(null);
  const [addOpen, setAddOpen] = useState(false);

  const items = nodes.data?.items ?? [];

  const currentDetail = detail ? (items.find((node) => node.id === detail.id) ?? detail) : null;

  return (
    <div>
      <PageHeader
        title="节点"
        description={isOwner ? "管理已接入的 Linux 转发节点" : "查看分配给你的节点"}
        actions={
          isOwner ? (
            <Button onClick={() => setAddOpen(true)} disabled={!online}>
              <Plus aria-hidden />
              添加节点
            </Button>
          ) : undefined
        }
      />

      <Card>
        {nodes.isPending ? (
          <div className="space-y-2 p-4" aria-busy="true" aria-label="加载中">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-12 w-full" />
            ))}
          </div>
        ) : nodes.isError ? (
          <div className="p-4">
            <ErrorState error={nodes.error} onRetry={() => nodes.refetch()} />
          </div>
        ) : items.length === 0 ? (
          <div className="p-4">
            <EmptyState
              icon={Server}
              title={isOwner ? "还没有节点" : "还没有分配节点"}
              description={isOwner ? "生成一次性安装命令，接入第一台 Linux 主机" : "请联系管理员分配可用节点"}
              action={
                isOwner ? (
                  <Button size="sm" onClick={() => setAddOpen(true)} disabled={!online}>
                    <Plus aria-hidden />
                    添加节点
                  </Button>
                ) : undefined
              }
            />
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>节点名称</TableHead>
                <TableHead>状态</TableHead>
                <TableHead>节点程序版本</TableHead>
                <TableHead className="text-right">目标配置</TableHead>
                <TableHead className="text-right">当前配置</TableHead>
                <TableHead>同步</TableHead>
                <TableHead>最后在线时间</TableHead>
                <TableHead className="text-right">转发</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((n) => (
                <TableRow
                  key={n.id}
                  className="cursor-pointer"
                  onClick={() => setDetail(n)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") setDetail(n);
                  }}
                  tabIndex={0}
                  aria-label={`查看节点 ${n.id} 详情`}
                >
                  <TableCell>
                    <div className="font-mono text-[13px] font-medium">{n.id}</div>
                    <div className="mt-0.5 flex flex-wrap gap-1">
                      {n.labels.map((l) => (
                        <Badge key={l} variant="secondary" className="px-1.5 text-[11px] leading-4">
                          {l}
                        </Badge>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell>
                    <NodeStatusBadge status={n.status} />
                  </TableCell>
                  <TableCell className="font-mono text-xs">{n.agent_version ?? "—"}</TableCell>
                  <TableCell className="text-right tabular-nums">{n.desired_generation}</TableCell>
                  <TableCell className="text-right tabular-nums">{n.applied_generation}</TableCell>
                  <TableCell>
                    <SyncBadge node={n} />
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{formatRelative(n.last_seen_at)}</TableCell>
                  <TableCell className="text-right tabular-nums">{n.forwards_count}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Card>

      <NodeDetailSheet
        node={currentDetail}
        open={detail !== null}
        onOpenChange={(o) => !o && setDetail(null)}
        isOwner={isOwner}
      />
      {isOwner ? <InstallCommandDialog open={addOpen} onOpenChange={setAddOpen} /> : null}
    </div>
  );
}
