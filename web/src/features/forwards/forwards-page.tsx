import { ArrowLeftRight, CheckCircle2, LoaderCircle, Lock, MoreHorizontal, Pause, Pencil, Play, Plus, Search, Trash2, XCircle } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";

import { DataTablePagination } from "@/components/shared/data-table-pagination";
import { EmptyState } from "@/components/shared/empty-state";
import { ErrorState } from "@/components/shared/error-state";
import { PageHeader } from "@/components/shared/page-header";
import { ForwardStatusBadge } from "@/components/shared/status-badge";
import { ConfirmDialog } from "@/components/shared/confirm-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useMe } from "@/features/auth/hooks";
import { useNodes } from "@/features/nodes/hooks";
import { useTenantPolicy, useTenants } from "@/features/tenants/hooks";
import { ApiError } from "@/lib/api/client";
import type { Forward, ForwardStatus, ForwardTCPCheck, Protocol } from "@/lib/api/types";
import { useDebouncedValue } from "@/lib/hooks/use-debounce";
import { useOnline } from "@/lib/hooks/use-online";
import { daysUntil, formatBytes, formatDate } from "@/lib/utils";
import { DeleteForwardDialog } from "./delete-forward-dialog";
import { ForwardFormSheet } from "./forward-form-sheet";
import { useCheckForwardTCP, useForwards, useSetForwardEnabled } from "./hooks";
import { SyncStatus } from "./sync-status";

const PAGE_SIZE = 8;

function formatTCPingLatency(milliseconds: number) {
  if (!Number.isFinite(milliseconds) || milliseconds < 0) return "—";
  if (milliseconds < 1) return "<1 ms";
  if (milliseconds < 10) return `${milliseconds.toFixed(1)} ms`;
  return `${Math.round(milliseconds)} ms`;
}

function InitializationNotice() {
  return (
    <Card className="border-warning/40 bg-warning/5 p-6">
      <h3 className="text-sm font-semibold">节点网络尚未初始化</h3>
      <p className="mt-1 text-sm leading-6 text-muted-foreground">
        节点之间的连接方式尚未设置。请先在安装 Flux 的主机上完成网络初始化，再回来创建转发。此操作暂不支持在网页中完成。
      </p>
    </Card>
  );
}

export function ForwardsPage() {
  const { data: me } = useMe();
  const account = me?.account;
  const isOwner = account?.role === "owner";
  const online = useOnline();

  const [search, setSearch] = useState("");
  const [status, setStatus] = useState<ForwardStatus | "">("");
  const [protocol, setProtocol] = useState<Protocol | "">("");
  const [page, setPage] = useState(1);

  const debouncedSearch = useDebouncedValue(search, 300);
  const query = useMemo(
    () => ({ page, page_size: PAGE_SIZE, search: debouncedSearch, status, protocol }),
    [page, debouncedSearch, status, protocol],
  );
  const list = useForwards(query);
  const nodes = useNodes();
  const tenants = useTenants(isOwner);
  const policy = useTenantPolicy(account?.tenant_id ?? "", !isOwner && Boolean(account?.tenant_id));

  const [sheetOpen, setSheetOpen] = useState(false);
  const [editing, setEditing] = useState<Forward | null>(null);
  const [deleting, setDeleting] = useState<Forward | null>(null);
  const [pausing, setPausing] = useState<Forward | null>(null);
  const [tcpChecks, setTCPChecks] = useState<Record<string, ForwardTCPCheck>>({});

  const setEnabled = useSetForwardEnabled();
  const checkTCP = useCheckForwardTCP();

  async function runTCPCheck(forward: Forward) {
    try {
      const result = await checkTCP.mutateAsync(forward.id);
      setTCPChecks((current) => ({ ...current, [forward.id]: result }));
      if (result.reachable) toast.success(`目标 TCP 端口可连接，建连 ${formatTCPingLatency(result.latency_ms)}`);
      else toast.error(result.message || `转发 ${forward.id} 的目标 TCP 端口不可连接`);
    } catch {
      // 错误提示由 mutation 统一处理。
    }
  }

  function openCreate() {
    setEditing(null);
    setSheetOpen(true);
  }
  function openEdit(f: Forward) {
    setEditing(f);
    setSheetOpen(true);
  }
  function resetFilters() {
    setSearch("");
    setStatus("");
    setProtocol("");
    setPage(1);
  }
  const hasFilter = Boolean(debouncedSearch || status || protocol);

  const items = list.data?.items ?? [];
  const nodeById = new Map((nodes.data?.items ?? []).map((n) => [n.id, n]));
  const clusterPlanMissing =
    list.error instanceof ApiError && list.error.code === "cluster_plan_not_configured";

  return (
    <div>
      <PageHeader
        title={isOwner ? "转发" : "我的转发"}
        description={
          isOwner
            ? "管理全部租户的 TCP/UDP 转发"
            : "你只能使用分配给你的节点、监听地址、端口范围与协议"
        }
        actions={
          <Button onClick={openCreate} disabled={!online || clusterPlanMissing}>
            <Plus aria-hidden />
            新建转发
          </Button>
        }
      />

      {clusterPlanMissing ? (
        <InitializationNotice />
      ) : (
        <Card>
          <div className="flex flex-col gap-2 border-b p-3 sm:flex-row sm:items-center">
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
              <Input
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  setPage(1);
                }}
                placeholder="搜索编号、监听地址或目标…"
                className="pl-8"
                aria-label="搜索转发"
              />
            </div>
            <div className="flex gap-2">
              <Select
                value={status || "all"}
                onValueChange={(value) => {
                  setStatus(value === "all" ? "" : (value as ForwardStatus));
                  setPage(1);
                }}
              >
                <SelectTrigger className="w-32" aria-label="按状态筛选">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">全部状态</SelectItem>
                  <SelectItem value="active">运行中</SelectItem>
                  <SelectItem value="paused">已暂停</SelectItem>
                  <SelectItem value="draining">平滑删除中</SelectItem>
                  <SelectItem value="force_deleting">立即删除中</SelectItem>
                </SelectContent>
              </Select>
              <Select
                value={protocol || "all"}
                onValueChange={(value) => {
                  setProtocol(value === "all" ? "" : (value as Protocol));
                  setPage(1);
                }}
              >
                <SelectTrigger className="w-28" aria-label="按协议筛选">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">全部协议</SelectItem>
                  <SelectItem value="tcp">TCP</SelectItem>
                  <SelectItem value="udp">UDP</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          {list.isPending ? (
            <div className="space-y-2 p-4" aria-busy="true" aria-label="加载中">
              {Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : list.isError ? (
            <div className="p-4">
              <ErrorState error={list.error} onRetry={() => list.refetch()} />
            </div>
          ) : items.length === 0 ? (
            <div className="p-4">
              <EmptyState
                icon={ArrowLeftRight}
                title={hasFilter ? "没有匹配的转发" : "还没有转发"}
                description={hasFilter ? "尝试调整搜索或筛选条件" : "创建第一条转发，把流量安全地送达目标服务"}
                action={
                  hasFilter ? (
                    <Button variant="outline" size="sm" onClick={resetFilters}>
                      清除筛选
                    </Button>
                  ) : (
                    <Button size="sm" onClick={openCreate} disabled={!online}>
                      <Plus aria-hidden />
                      新建转发
                    </Button>
                  )
                }
              />
            </div>
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>编号</TableHead>
                    <TableHead>协议</TableHead>
                    <TableHead>监听地址</TableHead>
                    <TableHead>目标</TableHead>
                    <TableHead>入口节点</TableHead>
                    <TableHead>出口节点</TableHead>
                    <TableHead>状态</TableHead>
                    <TableHead>限速</TableHead>
                    <TableHead>配额</TableHead>
                    <TableHead>到期</TableHead>
                    <TableHead className="w-10">
                      <span className="sr-only">操作</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((f) => {
                    const left = daysUntil(f.expires_at);
                    const busy = f.status === "draining" || f.status === "force_deleting";
                    const tcpCheck = tcpChecks[f.id];
                    const checking = checkTCP.isPending && checkTCP.variables === f.id;
                    return (
                      <TableRow key={f.id}>
                        <TableCell>
                          <div className="font-mono text-[13px] font-medium">{f.id}</div>
                          {isOwner ? (
                            <div className="text-xs text-muted-foreground">
                              {f.tenant_id === "owner" ? "管理员自用" : f.tenant_name}
                            </div>
                          ) : null}
                          {!f.editable ? (
                            <div className="mt-0.5 flex items-center gap-1 text-xs text-muted-foreground">
                              <Lock className="h-3 w-3" aria-hidden />
                              由外部配置管理
                            </div>
                          ) : null}
                        </TableCell>
                        <TableCell>
                          <span className="flex gap-1">
                            {f.protocols.map((p) => (
                              <Badge key={p} variant="outline" className="font-mono uppercase">
                                {p}
                              </Badge>
                            ))}
                          </span>
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {f.listen.address}:{f.listen.port}
                        </TableCell>
                        <TableCell className="text-xs">
                          <div className="font-mono">{f.target.address}:{f.target.port}</div>
                          {f.protocols.includes("tcp") ? (
                            <div className="mt-1 flex items-center gap-1.5 font-sans">
                              <Button
                                type="button"
                                variant="ghost"
                                size="sm"
                                className="h-6 px-1.5 text-[11px]"
                                disabled={!online || checkTCP.isPending}
                                onClick={() => void runTCPCheck(f)}
                              >
                                {checking ? <LoaderCircle className="animate-spin" aria-hidden /> : null}
                                {checking ? "检查中" : "检查 TCP"}
                              </Button>
                              {tcpCheck ? (
                                <span
                                  className={tcpCheck.reachable ? "inline-flex items-center gap-1 text-success" : "inline-flex items-center gap-1 text-destructive"}
                                  aria-live="polite"
                                >
                                  {tcpCheck.reachable ? <CheckCircle2 className="h-3.5 w-3.5" aria-hidden /> : <XCircle className="h-3.5 w-3.5" aria-hidden />}
                                  <span>{tcpCheck.reachable ? "可连接" : "不可连接"}</span>
                                  {tcpCheck.reachable ? <span className="tabular-nums">· {formatTCPingLatency(tcpCheck.latency_ms)}</span> : null}
                                </span>
                              ) : null}
                            </div>
                          ) : (
                            <div className="mt-1 font-sans text-[11px] text-muted-foreground">仅 UDP，不执行 TCP 检查</div>
                          )}
                        </TableCell>
                        <TableCell className="text-xs">{f.ingress_node_id}</TableCell>
                        <TableCell className="text-xs">{f.exit_node_id ?? "—"}</TableCell>
                        <TableCell>
                          <ForwardStatusBadge status={f.status} />
                          <div className="mt-1">
                            <SyncStatus forward={f} node={nodeById.get(f.ingress_node_id)} />
                          </div>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {f.rate_limit !== null ? `${Math.round(f.rate_limit / 1_000_000)} Mbps` : "不限"}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {f.traffic_quota_bytes !== null ? formatBytes(f.traffic_quota_bytes) : "不限"}
                        </TableCell>
                        <TableCell>
                          {f.expires_at ? (
                            <span
                              className={
                                left !== null && left <= 3
                                  ? "text-xs font-medium text-destructive"
                                  : "text-xs text-muted-foreground"
                              }
                            >
                              {formatDate(f.expires_at)}
                              {left !== null && left <= 7 ? `（${left} 天）` : ""}
                            </span>
                          ) : (
                            <span className="text-xs text-muted-foreground">—</span>
                          )}
                        </TableCell>
                        <TableCell>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="icon" aria-label={`转发 ${f.id} 的操作`}>
                                <MoreHorizontal aria-hidden />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem onClick={() => openEdit(f)} disabled={!online || !f.editable || busy}>
                                <Pencil aria-hidden />
                                {f.editable ? "编辑" : "此转发不能在网页中编辑"}
                              </DropdownMenuItem>
                              <DropdownMenuItem
                                onClick={() => {
                                  void navigator.clipboard
                                    ?.writeText(`${f.listen.address}:${f.listen.port}`)
                                    .then(() => toast.success("监听地址已复制"))
                                    .catch(() => toast.error("复制失败"));
                                }}
                              >
                                复制监听地址
                              </DropdownMenuItem>
                              <DropdownMenuSeparator />
                              {f.status === "active" ? (
                                <DropdownMenuItem onClick={() => setPausing(f)} disabled={!online}>
                                  <Pause aria-hidden />
                                  暂停
                                </DropdownMenuItem>
                              ) : f.status === "paused" ? (
                                <DropdownMenuItem
                                  onClick={() =>
                                    setEnabled.mutate({ id: f.id, enabled: true, resourceVersion: f.resource_version })
                                  }
                                  disabled={!online || setEnabled.isPending}
                                >
                                  <Play aria-hidden />
                                  恢复
                                </DropdownMenuItem>
                              ) : null}
                              <DropdownMenuItem
                                className="text-destructive focus:text-destructive"
                                onClick={() => setDeleting(f)}
                                disabled={!online || f.status === "force_deleting"}
                              >
                                <Trash2 aria-hidden />
                                删除…
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
              <div className="border-t px-3">
                <DataTablePagination
                  page={list.data.page}
                  pageSize={list.data.page_size}
                  total={list.data.total}
                  onPageChange={setPage}
                />
              </div>
            </>
          )}
        </Card>
      )}

      <ForwardFormSheet
        open={sheetOpen}
        onOpenChange={setSheetOpen}
        forward={editing}
        nodes={nodes.data?.items ?? []}
        tenants={tenants.data?.items ?? []}
        policy={policy.data?.policy ?? null}
        policyExpiresAt={isOwner ? null : (tenants.data?.items.find((t) => t.id === account?.tenant_id)?.expires_at ?? null)}
        isOwner={isOwner}
      />
      <DeleteForwardDialog forward={deleting} open={deleting !== null} onOpenChange={(o) => !o && setDeleting(null)} />
      <ConfirmDialog
        open={pausing !== null}
        onOpenChange={(o) => !o && setPausing(null)}
        title={`暂停转发 ${pausing?.id}？`}
        description="暂停后，新连接会立即被拒绝；恢复后会自动重新启用。"
        confirmLabel="暂停转发"
        loading={setEnabled.isPending}
        onConfirm={async () => {
          if (!pausing) return;
          try {
            await setEnabled.mutateAsync({ id: pausing.id, enabled: false, resourceVersion: pausing.resource_version });
            setPausing(null);
          } catch {
            /* toast 已提示 */
          }
        }}
      />
    </div>
  );
}
