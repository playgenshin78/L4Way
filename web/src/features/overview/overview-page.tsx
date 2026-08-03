import { useQuery } from "@tanstack/react-query";
import { ArrowLeftRight, Server, Users } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";

import { ErrorState } from "@/components/shared/error-state";
import { PageHeader } from "@/components/shared/page-header";
import { ForwardStatusBadge, NodeStatusBadge } from "@/components/shared/status-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { listForwards } from "@/lib/api/forwards";
import { formatRelative } from "@/lib/utils";
import { useMe } from "@/features/auth/hooks";
import { useNodes } from "@/features/nodes/hooks";
import { useTenants } from "@/features/tenants/hooks";

function StatCard({
  icon: Icon,
  label,
  value,
  sub,
  loading,
}: {
  icon: LucideIcon;
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  loading?: boolean;
}) {
  return (
    <Card>
      <CardContent className="flex items-start gap-3 p-4">
        <div className="rounded-lg bg-primary/10 p-2">
          <Icon className="h-4 w-4 text-primary" aria-hidden />
        </div>
        <div className="min-w-0">
          <p className="text-xs text-muted-foreground">{label}</p>
          {loading ? (
            <Skeleton className="mt-1 h-6 w-20" />
          ) : (
            <p className="mt-0.5 truncate text-lg font-semibold tabular-nums">{value}</p>
          )}
          {sub ? <div className="mt-0.5 text-xs text-muted-foreground">{sub}</div> : null}
        </div>
      </CardContent>
    </Card>
  );
}

/**
 * 概览：只使用 tenants / forwards / nodes 的真实数据。
 * 后端暂无流量趋势接口，因此不绘制图表。
 */
export function OverviewPage() {
  const { data: me } = useMe();
  const account = me?.account;
  const isOwner = account?.role === "owner";

  const nodes = useNodes();
  const tenants = useTenants(isOwner);
  const forwards = useQuery({
    queryKey: ["forwards", "list", { page: 1, page_size: 5, search: "", status: "", protocol: "" }],
    queryFn: () => listForwards({ page: 1, page_size: 5 }),
  });
  const activeForwards = useQuery({
    queryKey: ["forwards", "list", { page: 1, page_size: 1, search: "", status: "active" as const, protocol: "" }],
    queryFn: () => listForwards({ page: 1, page_size: 1, status: "active" }),
  });

  const nodeItems = nodes.data?.items ?? [];
  const onlineNodes = nodeItems.filter((n) => n.status === "online").length;

  return (
    <div>
      <PageHeader
        title={`你好，${account?.display_name ?? ""}`}
        description={isOwner ? "平台运行状况一览" : "你可用的节点与转发"}
      />

      <div className={`grid grid-cols-2 gap-3 ${isOwner ? "lg:grid-cols-4" : "lg:grid-cols-3"}`}>
        {isOwner ? (
          <>
            <StatCard icon={Server} label="节点数" loading={nodes.isPending} value={nodes.data?.total ?? "-"} sub={`在线 ${onlineNodes}`} />
            <StatCard icon={Server} label="在线节点" loading={nodes.isPending} value={onlineNodes} sub={`共 ${nodes.data?.total ?? "-"} 台`} />
            <StatCard icon={Users} label="租户数" loading={tenants.isPending} value={tenants.data?.total ?? "-"} />
            <StatCard icon={ArrowLeftRight} label="转发数" loading={forwards.isPending} value={forwards.data?.total ?? "-"} sub={`运行中 ${activeForwards.data?.total ?? "-"}`} />
          </>
        ) : (
          <>
            <StatCard icon={Server} label="可用节点" loading={nodes.isPending} value={nodes.data?.total ?? "-"} sub={`在线 ${onlineNodes}`} />
            <StatCard icon={ArrowLeftRight} label="我的转发" loading={forwards.isPending} value={forwards.data?.total ?? "-"} />
            <StatCard icon={ArrowLeftRight} label="运行中" loading={activeForwards.isPending} value={activeForwards.data?.total ?? "-"} />
          </>
        )}
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle>最近转发</CardTitle>
            <Link to="/forwards" className="text-xs font-medium text-primary hover:underline">
              查看全部
            </Link>
          </CardHeader>
          <CardContent>
            {forwards.isPending ? (
              <div className="space-y-2">
                {Array.from({ length: 4 }).map((_, i) => (
                  <Skeleton key={i} className="h-8 w-full" />
                ))}
              </div>
            ) : forwards.isError ? (
              <ErrorState error={forwards.error} onRetry={() => forwards.refetch()} />
            ) : forwards.data.items.length === 0 ? (
              <p className="py-6 text-center text-sm text-muted-foreground">还没有转发</p>
            ) : (
              <ul className="divide-y">
                {forwards.data.items.map((f) => (
                  <li key={f.id} className="flex items-center justify-between gap-3 py-2 text-sm">
                    <div className="min-w-0">
                      <span className="font-mono text-[13px] font-medium">{f.id}</span>
                      <span className="ml-2 font-mono text-[13px] text-muted-foreground">
                        {f.listen.address}:{f.listen.port} → {f.target.address}:{f.target.port}
                      </span>
                    </div>
                    <ForwardStatusBadge status={f.status} />
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle>节点状态</CardTitle>
            <Link to="/nodes" className="text-xs font-medium text-primary hover:underline">
              查看全部
            </Link>
          </CardHeader>
          <CardContent>
            {nodes.isPending ? (
              <div className="space-y-2">
                {Array.from({ length: 4 }).map((_, i) => (
                  <Skeleton key={i} className="h-8 w-full" />
                ))}
              </div>
            ) : nodes.isError ? (
              <ErrorState error={nodes.error} onRetry={() => nodes.refetch()} />
            ) : nodeItems.length === 0 ? (
              <p className="py-6 text-center text-sm text-muted-foreground">
                {isOwner ? "还没有节点" : "还没有分配节点"}
              </p>
            ) : (
              <ul className="divide-y">
                {nodeItems.slice(0, 5).map((n) => (
                  <li key={n.id} className="flex items-center justify-between gap-3 py-2 text-sm">
                    <div className="min-w-0">
                      <span className="font-mono text-[13px] font-medium">{n.id}</span>
                      <span className="ml-2 text-xs text-muted-foreground">
                        {n.agent_version ?? "未注册"} · {formatRelative(n.last_seen_at)}
                      </span>
                    </div>
                    <NodeStatusBadge status={n.status} />
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
