import { Plus, Users } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";

import { EmptyState } from "@/components/shared/empty-state";
import { ErrorState } from "@/components/shared/error-state";
import { PageHeader } from "@/components/shared/page-header";
import { TenantStatusBadge } from "@/components/shared/status-badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useOnline } from "@/lib/hooks/use-online";
import type { Tenant } from "@/lib/api/types";
import { daysUntil, formatDate } from "@/lib/utils";
import { CreateTenantDialog } from "./create-tenant-dialog";
import { useTenants } from "./hooks";
import { TenantDetailSheet } from "./tenant-detail-sheet";

export function TenantsPage() {
  const online = useOnline();
  const navigate = useNavigate();
  const tenants = useTenants();
  const [createOpen, setCreateOpen] = useState(false);
  const [selectedTenant, setSelectedTenant] = useState<Tenant | null>(null);

  const items = tenants.data?.items ?? [];

  return (
    <div>
      <PageHeader
        title="租户"
        description="管理租户账号、使用权限和有效期"
        actions={
          <Button onClick={() => setCreateOpen(true)} disabled={!online}>
            <Plus aria-hidden />
            创建租户
          </Button>
        }
      />

      <Card>
        {tenants.isPending ? (
          <div className="space-y-2 p-4" aria-busy="true" aria-label="加载中">
            {Array.from({ length: 3 }).map((_, i) => (
              <Skeleton key={i} className="h-12 w-full" />
            ))}
          </div>
        ) : tenants.isError ? (
          <div className="p-4">
            <ErrorState error={tenants.error} onRetry={() => tenants.refetch()} />
          </div>
        ) : items.length === 0 ? (
          <div className="p-4">
            <EmptyState
              icon={Users}
              title="还没有租户"
              description="创建租户并设置可用节点、端口和流量额度"
              action={
                <Button size="sm" onClick={() => setCreateOpen(true)} disabled={!online}>
                  <Plus aria-hidden />
                  创建租户
                </Button>
              }
            />
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>租户</TableHead>
                <TableHead>状态</TableHead>
                <TableHead className="text-right">转发数</TableHead>
                <TableHead>到期时间</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((t) => {
                const left = daysUntil(t.expires_at);
                return (
                  <TableRow
                    key={t.id}
                    className="cursor-pointer"
                    onClick={() => setSelectedTenant(t)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        setSelectedTenant(t);
                      }
                    }}
                    tabIndex={0}
                    aria-label={`查看租户 ${t.display_name}`}
                  >
                    <TableCell>
                      <div className="font-medium">{t.display_name}</div>
                      <div className="text-xs text-muted-foreground">@{t.username}</div>
                    </TableCell>
                    <TableCell>
                      <TenantStatusBadge status={t.status} />
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{t.forwards_count}</TableCell>
                    <TableCell>
                      {t.expires_at ? (
                        <span className={left !== null && left <= 7 ? "text-xs font-medium text-destructive" : "text-xs text-muted-foreground"}>
                          {formatDate(t.expires_at)}
                          {left !== null ? `（${left} 天）` : ""}
                        </span>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </Card>

      <CreateTenantDialog open={createOpen} onOpenChange={setCreateOpen} />
      <TenantDetailSheet
        tenant={selectedTenant}
        open={selectedTenant !== null}
        onOpenChange={(open) => {
          if (!open) setSelectedTenant(null);
        }}
        onManage={(tenant) => {
          setSelectedTenant(null);
          navigate(`/tenants/${tenant.id}`);
        }}
      />
    </div>
  );
}
