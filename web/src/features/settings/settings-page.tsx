import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Archive, CheckCircle2, Database, Download, ShieldCheck } from "lucide-react";
import { toast } from "sonner";

import { ErrorState } from "@/components/shared/error-state";
import { PageHeader } from "@/components/shared/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { createBackup, downloadBackup, getSystemStatus } from "@/lib/api/system";
import { formatBytes, formatDateTime, formatDuration } from "@/lib/utils";

export function SettingsPage() {
  const queryClient = useQueryClient();
  const status = useQuery({ queryKey: ["system", "status"], queryFn: getSystemStatus });
  const create = useMutation({
    mutationFn: createBackup,
    onSuccess: () => {
      toast.success("备份已创建");
      void queryClient.invalidateQueries({ queryKey: ["system", "status"] });
    },
    onError: (error: Error) => toast.error(error.message),
  });
  const download = useMutation({
    mutationFn: downloadBackup,
    onSuccess: (result) => {
      const objectURL = URL.createObjectURL(result.blob);
      const anchor = document.createElement("a");
      anchor.href = objectURL;
      anchor.download = result.filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(objectURL), 0);
      toast.success("备份已开始下载");
    },
    onError: (error: Error) => toast.error(error.message),
  });
  const minimumNodeVersion =
    status.data?.agent_min_version && status.data.agent_min_version !== "dev"
      ? status.data.agent_min_version
      : "未限定";

  return (
    <div>
      <PageHeader title="设置" description="查看系统运行状态并管理数据备份" />

      {status.isPending ? (
        <div className="grid gap-3 md:grid-cols-2">
          <Skeleton className="h-44 w-full" />
          <Skeleton className="h-44 w-full" />
        </div>
      ) : status.isError ? (
        <ErrorState error={status.error} onRetry={() => status.refetch()} />
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-primary" />
                系统
              </CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="space-y-3 text-sm">
                {[
                  ["系统版本", status.data.controller_version],
                  ["节点程序最低版本", minimumNodeVersion],
                  ["已运行", formatDuration(status.data.uptime_seconds)],
                  ["节点状态", `${status.data.nodes_online} / ${status.data.nodes_total} 在线`],
                  ["节点连接", "已加密并验证身份"],
                ].map(([label, value]) => (
                  <div key={label} className="flex justify-between gap-4">
                    <dt className="text-muted-foreground">{label}</dt>
                    <dd className="text-right">{value}</dd>
                  </div>
                ))}
              </dl>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Database className="h-4 w-4 text-primary" />
                数据存储
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <Badge variant={status.data.sqlite.healthy ? "success" : "destructive"}>
                  {status.data.sqlite.healthy ? (
                    <>
                      <CheckCircle2 className="mr-1 h-3 w-3" /> 正常
                    </>
                  ) : (
                    "异常"
                  )}
                </Badge>
                <span className="text-sm tabular-nums">占用 {formatBytes(status.data.sqlite.size_bytes)}</span>
              </div>
              <p className="mt-3 text-xs leading-5 text-muted-foreground">
                写入保护{status.data.sqlite.wal_enabled ? "已开启" : "未开启"} · 最近备份{" "}
                {status.data.last_backup_at ? formatDateTime(status.data.last_backup_at) : "尚未创建"}
              </p>
              <div className="mt-4 grid grid-cols-2 gap-2">
                <Button onClick={() => create.mutate()} disabled={create.isPending}>
                  <Archive aria-hidden />
                  {create.isPending ? "正在创建…" : "创建备份"}
                </Button>
                <Button
                  variant="outline"
                  onClick={() => download.mutate()}
                  disabled={download.isPending || !status.data.last_backup_at}
                >
                  <Download aria-hidden />
                  {download.isPending ? "正在下载…" : "下载最近备份"}
                </Button>
              </div>
              <p className="mt-2 text-xs leading-5 text-muted-foreground">
                备份包含全部配置、账号和身份密钥。恢复前请先停止 Flux 服务。
              </p>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
