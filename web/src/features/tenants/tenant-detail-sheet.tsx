import { Settings2 } from "lucide-react";

import { TenantStatusBadge } from "@/components/shared/status-badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import type { Tenant } from "@/lib/api/types";
import { formatDate, formatDateTime } from "@/lib/utils";

export function TenantDetailSheet({
  tenant,
  open,
  onOpenChange,
  onManage,
}: {
  tenant: Tenant | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onManage: (tenant: Tenant) => void;
}) {
  if (!tenant) return null;

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="overflow-y-auto sm:max-w-md">
        <SheetHeader>
          <SheetTitle className="flex items-center gap-2">
            <span>{tenant.display_name}</span>
            <TenantStatusBadge status={tenant.status} />
          </SheetTitle>
          <SheetDescription>@{tenant.username}</SheetDescription>
        </SheetHeader>

        <div className="mt-5 space-y-5">
          <section>
            <h3 className="mb-2 text-sm font-medium text-foreground">账号概况</h3>
            <dl className="space-y-2 text-sm">
              <div className="flex justify-between gap-4">
                <dt className="text-muted-foreground">转发数量</dt>
                <dd className="tabular-nums">{tenant.forwards_count}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-muted-foreground">到期时间</dt>
                <dd>{tenant.expires_at ? formatDate(tenant.expires_at) : "长期有效"}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-muted-foreground">创建时间</dt>
                <dd>{formatDateTime(tenant.created_at)}</dd>
              </div>
            </dl>
          </section>

          <Separator />

          <section>
            <h3 className="mb-2 text-sm font-medium text-foreground">权限与限额</h3>
            <p className="text-sm leading-6 text-muted-foreground">
              节点权限、监听地址、端口范围、带宽、流量配额和目标网段集中在租户设置中管理。
            </p>
          </section>

          <Separator />

          <section>
            <Button className="w-full" onClick={() => onManage(tenant)}>
              <Settings2 aria-hidden />
              管理租户设置
            </Button>
            <p className="mt-2 text-xs leading-5 text-muted-foreground">
              节点、端口、带宽和目标范围将在完整设置页中编辑。
            </p>
          </section>
        </div>
      </SheetContent>
    </Sheet>
  );
}
