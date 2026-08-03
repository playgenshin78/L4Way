import { useQuery } from "@tanstack/react-query";
import { ScrollText } from "lucide-react";
import { useMemo, useState } from "react";

import { DataTablePagination } from "@/components/shared/data-table-pagination";
import { EmptyState } from "@/components/shared/empty-state";
import { ErrorState } from "@/components/shared/error-state";
import { PageHeader } from "@/components/shared/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { listAudit } from "@/lib/api/system";
import type { AuditEvent, AuditResult } from "@/lib/api/types";
import { useDebouncedValue } from "@/lib/hooks/use-debounce";
import { formatBytes, formatDateTime } from "@/lib/utils";

const resultVariant: Record<AuditResult, "success" | "destructive" | "warning"> = {
  success: "success",
  failure: "destructive",
  denied: "warning",
};
const resultLabel: Record<AuditResult, string> = { success: "成功", failure: "失败", denied: "拒绝" };

const actionLabels: Record<string, string> = {
  "auth.login": "登录",
  "auth.logout": "退出登录",
  "auth.password.change": "修改密码",
  "authorization.denied": "权限校验拒绝",
  "csrf.denied": "页面安全校验拒绝",
  "forward.create": "创建转发",
  "forward.update": "修改转发",
  "forward.delete": "删除转发",
  "forward.delete.drain": "平滑删除转发",
  "forward.delete.force": "立即删除转发",
  "forward.tcp_check": "检查 TCP 连通性",
  "node.install_command": "生成节点安装命令",
  "node.install_command.create": "生成节点安装命令",
  "node.revoke": "停用节点",
  "node.delete": "删除节点",
  "node.protocol_blocks.update": "修改节点协议拦截",
  "node.upgrade": "升级节点程序",
  "node.uninstall": "卸载节点程序",
  "tenant.create": "创建租户",
  "tenant.update": "修改租户账号",
  "tenant.policy.update": "修改租户权限",
  "tenant.policy.enforce": "自动执行租户权限",
  "tenant.password.reset": "重置租户密码",
  "traffic.quota.enforce": "流量配额触发暂停",
  "system.backup.create": "创建备份",
  "system.backup.download": "下载备份",
};

const resourceLabels: Record<string, string> = {
  account: "账号",
  backup: "备份",
  forward: "转发",
  node: "节点",
  route: "页面请求",
  session: "登录会话",
  tenant: "租户",
  tenant_policy: "租户权限",
};

const detailLabels: Record<string, string> = {
  attempts: "尝试次数",
  changed: "变更项目",
  conntrack_cleanup: "连接状态清理",
  drain_seconds: "最长等待时间",
  enabled: "是否启用",
  error_code: "检查结果代码",
  execution_node_id: "执行检查的节点",
  expires_at: "有效期",
  from: "修改前",
  listen: "监听地址",
  mode: "删除方式",
  note: "备注",
  protocols: "协议",
  reason: "原因",
  reachable: "TCP 是否可连接",
  latency_ms: "TCP 建连耗时（ms）",
  size_bytes: "文件大小",
  state: "节点状态",
  status: "账号状态",
  target: "目标地址",
  to: "修改后",
  token_ttl_seconds: "安装命令有效期",
  previous_version: "升级前版本",
  identity_revoked: "节点身份已吊销",
  username: "用户名",
};

const fieldLabels: Record<string, string> = {
  max_forwards: "转发数量上限",
  traffic_quota_bytes: "流量配额",
  allowed_ingress_nodes: "入口节点",
  allowed_exit_nodes: "出口节点",
  allowed_listen_ips: "监听地址",
  allowed_port_ranges: "端口范围",
  allowed_protocols: "协议",
  allowed_target_cidrs: "允许的目标网段",
  denied_target_cidrs: "禁止的目标网段",
};

function actionLabel(action: string): string {
  if (actionLabels[action]) return actionLabels[action];
  if (action.startsWith("auth.")) return "账号操作";
  if (action.startsWith("forward.")) return "转发操作";
  if (action.startsWith("node.")) return "节点操作";
  if (action.startsWith("tenant.")) return "租户操作";
  if (action.startsWith("system.")) return "系统操作";
  return "其他操作";
}

function actorRoleLabel(event: AuditEvent): string {
  return event.actor_role === "owner" ? "管理员" : "租户";
}

function isSystemActor(event: AuditEvent): boolean {
  return event.actor === "system" || event.actor.startsWith("system:");
}

function actorName(event: AuditEvent): string {
  return isSystemActor(event) ? "系统" : event.actor;
}

function actorDisplay(event: AuditEvent): string {
  return isSystemActor(event) ? "系统" : `${event.actor}（${actorRoleLabel(event)}）`;
}

function resourceName(event: AuditEvent): string {
  if (event.resource_type === "session") return "当前登录";
  if (event.resource_type === "route") return "受限页面";
  if (event.resource_type === "backup") return "数据备份";
  if (event.resource_type === "forward") {
    return typeof event.detail.listen === "string" ? `转发 ${event.detail.listen}` : "转发规则";
  }
  if (event.resource_type === "tenant" || event.resource_type === "tenant_policy") {
    return typeof event.detail.username === "string" ? `租户 ${event.detail.username}` : "租户账号";
  }
  if (event.resource_type === "node") {
    return event.resource_name ? `节点 ${event.resource_name}` : "节点";
  }
  if (event.resource_type === "account") {
    return typeof event.detail.username === "string" ? `账号 ${event.detail.username}` : "账号";
  }
  return resourceLabels[event.resource_type] || event.resource_name || "—";
}

function detailValue(key: string, value: unknown): string {
  if (value === null || value === undefined || value === "") return "无";
  if (key === "size_bytes" && typeof value === "number") return formatBytes(value);
  if (key === "expires_at" && typeof value === "string") return formatDateTime(value);
  if (key === "drain_seconds" || key === "token_ttl_seconds") return `${String(value)} 秒`;
  if (key === "mode") return value === "drain" ? "平滑删除" : value === "force" ? "立即删除" : String(value);
  if (key === "state" && value === "pending") return "待注册";
  if (key === "status") return value === "active" ? "正常" : value === "disabled" ? "已禁用" : String(value);
  if (key === "reason") {
    if (value === "invalid_credentials") return "用户名或密码错误";
    if (value === "cross_tenant_access") return "尝试访问其他租户的数据";
  }
  if (typeof value === "boolean") return value ? "是" : "否";
  if (Array.isArray(value)) {
    return value
      .map((item) => fieldLabels[String(item)] ?? (["tcp", "udp"].includes(String(item)) ? String(item).toUpperCase() : String(item)))
      .join("、");
  }
  if (typeof value === "object") return "已记录";
  return String(value);
}

function detailEntries(detail: Record<string, unknown>): Array<[string, string]> {
  return Object.entries(detail)
    .filter(([key]) => key !== "username" && detailLabels[key])
    .map(([key, value]) => [detailLabels[key]!, detailValue(key, value)] as [string, string]);
}

export function AuditPage() {
  const [actor, setActor] = useState("");
  const [action, setAction] = useState("");
  const [result, setResult] = useState<AuditResult | "">("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [detail, setDetail] = useState<AuditEvent | null>(null);

  const debouncedActor = useDebouncedValue(actor, 300);
  const query = useMemo(
    () => ({ page, page_size: pageSize, actor: debouncedActor, action, result }),
    [page, pageSize, debouncedActor, action, result],
  );
  const audit = useQuery({
    queryKey: ["audit", query],
    queryFn: () => listAudit(query),
    placeholderData: (prev) => prev,
  });

  const items = audit.data?.items ?? [];
  const selectedDetailEntries = detail ? detailEntries(detail.detail) : [];

  return (
    <div>
      <PageHeader title="审计" description="记录登录和管理操作，便于追踪变更与排查问题" />

      <Card>
        <div className="flex flex-col gap-2 border-b p-3 sm:flex-row sm:items-center">
          <Input
            value={actor}
            onChange={(e) => {
              setActor(e.target.value);
              setPage(1);
            }}
            placeholder="按操作者筛选…"
            className="sm:max-w-xs"
            aria-label="按操作者筛选"
          />
          <div className="flex gap-2">
            <Select
              value={action || "all"}
              onValueChange={(value) => {
                setAction(value === "all" ? "" : value);
                setPage(1);
              }}
            >
              <SelectTrigger className="w-40" aria-label="按动作筛选">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部动作</SelectItem>
                <SelectItem value="auth.">登录 / 登出</SelectItem>
                <SelectItem value="forward.">转发操作</SelectItem>
                <SelectItem value="node.">节点操作</SelectItem>
                <SelectItem value="tenant.">租户操作</SelectItem>
                <SelectItem value="system.">系统操作</SelectItem>
              </SelectContent>
            </Select>
            <Select
              value={result || "all"}
              onValueChange={(value) => {
                setResult(value === "all" ? "" : (value as AuditResult));
                setPage(1);
              }}
            >
              <SelectTrigger className="w-28" aria-label="按结果筛选">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部结果</SelectItem>
                <SelectItem value="success">成功</SelectItem>
                <SelectItem value="failure">失败</SelectItem>
                <SelectItem value="denied">拒绝</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        {audit.isPending ? (
          <div className="space-y-2 p-4" aria-busy="true" aria-label="加载中">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : audit.isError ? (
          <div className="p-4">
            <ErrorState error={audit.error} onRetry={() => audit.refetch()} />
          </div>
        ) : items.length === 0 ? (
          <div className="p-4">
            <EmptyState
              icon={ScrollText}
              title="没有匹配的审计记录"
              description="尝试调整筛选条件"
              action={
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setActor("");
                    setAction("");
                    setResult("");
                    setPage(1);
                  }}
                >
                  清除筛选
                </Button>
              }
            />
          </div>
        ) : (
          <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>时间</TableHead>
                  <TableHead>操作者</TableHead>
                  <TableHead>动作</TableHead>
                  <TableHead>操作对象</TableHead>
                  <TableHead>结果</TableHead>
                  <TableHead>来源 IP</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((e) => (
                  <TableRow
                    key={e.id}
                    className="cursor-pointer"
                    onClick={() => setDetail(e)}
                    onKeyDown={(ev) => {
                      if (ev.key === "Enter") setDetail(e);
                    }}
                    tabIndex={0}
                    aria-label={`查看审计详情 ${actionLabel(e.action)}`}
                  >
                    <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                      {formatDateTime(e.created_at)}
                    </TableCell>
                    <TableCell>
                      <span className="font-medium">{actorName(e)}</span>
                      {!isSystemActor(e) ? (
                        <span className="ml-1 text-xs text-muted-foreground">（{actorRoleLabel(e)}）</span>
                      ) : null}
                    </TableCell>
                    <TableCell className="text-sm">{actionLabel(e.action)}</TableCell>
                    <TableCell className="text-xs">{resourceName(e)}</TableCell>
                    <TableCell>
                      <Badge variant={resultVariant[e.result]}>{resultLabel[e.result]}</Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">{e.source_ip}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            <div className="border-t px-3">
              <DataTablePagination
                page={audit.data.page}
                pageSize={audit.data.page_size}
                total={audit.data.total}
                onPageChange={setPage}
                pageSizeOptions={[10, 20, 50, 100]}
                onPageSizeChange={(nextPageSize) => {
                  setPageSize(nextPageSize);
                  setPage(1);
                }}
              />
            </div>
          </>
        )}
      </Card>

      <Sheet open={detail !== null} onOpenChange={(o) => !o && setDetail(null)}>
        <SheetContent className="sm:max-w-md">
          <SheetHeader>
            <SheetTitle>{detail ? actionLabel(detail.action) : ""}</SheetTitle>
            <SheetDescription>{detail ? formatDateTime(detail.created_at) : ""}</SheetDescription>
          </SheetHeader>
          {detail ? (
            <dl className="mt-4 space-y-3 text-sm">
              {[
                ["操作者", actorDisplay(detail)],
                ["操作对象", resourceName(detail)],
                ["结果", resultLabel[detail.result]],
                ["来源 IP", detail.source_ip],
              ].map(([k, v]) => (
                <div key={k} className="flex justify-between gap-4">
                  <dt className="shrink-0 text-muted-foreground">{k}</dt>
                  <dd className="text-right">{v}</dd>
                </div>
              ))}
              {selectedDetailEntries.length > 0 ? (
                <>
                  <div className="pt-2 text-sm font-medium">补充信息</div>
                  {selectedDetailEntries.map(([label, value]) => (
                    <div key={label} className="flex justify-between gap-4">
                      <dt className="shrink-0 text-muted-foreground">{label}</dt>
                      <dd className="break-all text-right">{value}</dd>
                    </div>
                  ))}
                </>
              ) : null}
            </dl>
          ) : null}
        </SheetContent>
      </Sheet>
    </div>
  );
}
