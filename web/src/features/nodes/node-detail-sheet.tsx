import { useState } from "react";
import { RefreshCw, Trash2, Unplug } from "lucide-react";

import { ConfirmDialog } from "@/components/shared/confirm-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import type { FluxNode, NodeProtocolBlocks } from "@/lib/api/types";
import { formatDateTime, formatRelative } from "@/lib/utils";
import { NodeStatusBadge } from "@/components/shared/status-badge";
import { useDeletePendingNode, useUninstallNode, useUpdateNodeProtocolBlocks, useUpgradeNode } from "./hooks";

const protocolOptions: Array<{ key: keyof NodeProtocolBlocks; label: string; description: string }> = [
  { key: "http", label: "HTTP", description: "拦截 GET、POST 等明文网页请求" },
  { key: "https", label: "HTTPS", description: "拦截 CONNECT 和常见浏览器 TLS 中的 HTTP 标识" },
  { key: "socks", label: "SOCKS", description: "拦截 SOCKS4 和 SOCKS5 握手" },
  { key: "tls", label: "TLS", description: "拦截所有 TLS 握手，范围包含 HTTPS" },
];

export function NodeDetailSheet({
  node,
  open,
  onOpenChange,
  isOwner,
}: {
  node: FluxNode | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  isOwner: boolean;
}) {
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [confirmUpgrade, setConfirmUpgrade] = useState(false);
  const [confirmUninstall, setConfirmUninstall] = useState(false);
  const deleteNode = useDeletePendingNode();
  const updateProtocolBlocks = useUpdateNodeProtocolBlocks();
  const upgradeNode = useUpgradeNode();
  const uninstallNode = useUninstallNode();
  if (!node) return null;
  const synced = node.desired_generation === node.applied_generation;
  const canDelete =
    node.status === "pending" &&
    !node.agent_version &&
    node.desired_generation === 0 &&
    node.applied_generation === 0;
  const canUpgrade = node.status === "online" && Boolean(node.agent_version);
  const canUninstall = canUpgrade && node.forwards_count === 0 && synced;

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="overflow-y-auto sm:max-w-md">
        <SheetHeader>
          <SheetTitle className="flex items-center gap-2">
            <span className="font-mono">{node.id}</span>
            <NodeStatusBadge status={node.status} />
          </SheetTitle>
          <SheetDescription>
            节点程序 {node.agent_version ?? "尚未安装"} · 最后在线 {formatRelative(node.last_seen_at)}
          </SheetDescription>
        </SheetHeader>

        <div className="mt-4 space-y-5">
          <section>
            <h3 className="mb-2 text-sm font-medium text-foreground">配置同步</h3>
            <dl className="space-y-1.5 text-sm">
              <div className="flex justify-between gap-4">
                <dt className="text-muted-foreground">目标配置版本</dt>
                <dd className="tabular-nums">{node.desired_generation}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-muted-foreground">当前配置版本</dt>
                <dd className="tabular-nums">{node.applied_generation}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-muted-foreground">同步状态</dt>
                <dd className={synced ? "text-success" : "text-warning"}>{synced ? "已同步" : "等待节点确认"}</dd>
              </div>
            </dl>
          </section>

          <Separator />

          {isOwner ? (
            <>
              <section>
                <h3 className="mb-1 text-sm font-medium text-foreground">协议拦截（节点级）</h3>
                <p className="mb-3 text-xs leading-5 text-muted-foreground">
                  只识别此节点转发连接开头；随机 AES 数据不会因端口或高熵特征被拦截。
                </p>
                <div className="divide-y rounded-lg border">
                  {protocolOptions.map((option) => (
                    <div key={option.key} className="flex min-h-14 items-center justify-between gap-4 px-3 py-2.5">
                      <div className="min-w-0">
                        <div className="text-sm font-medium">{option.label}</div>
                        <p className="mt-0.5 text-xs leading-4 text-muted-foreground">{option.description}</p>
                      </div>
                      <Switch
                        checked={node.protocol_blocks[option.key]}
                        disabled={updateProtocolBlocks.isPending || node.status === "pending" || node.status === "revoked"}
                        aria-label={`拦截 ${option.label}`}
                        onCheckedChange={(checked) =>
                          updateProtocolBlocks.mutate({
                            nodeId: node.id,
                            input: {
                              resource_version: node.resource_version,
                              protocol_blocks: { ...node.protocol_blocks, [option.key]: checked },
                            },
                          })
                        }
                      />
                    </div>
                  ))}
                </div>
                {node.status === "pending" ? (
                  <p className="mt-2 text-xs leading-5 text-muted-foreground">节点完成接入后即可设置。</p>
                ) : null}
              </section>
              <Separator />
            </>
          ) : null}

          <section>
            <h3 className="mb-2 text-sm font-medium text-foreground">
              转发 <span className="tabular-nums">（{node.forwards_count}）</span>
            </h3>
            <p className="text-sm leading-6 text-muted-foreground">当前有 {node.forwards_count} 条转发使用这个节点。</p>
          </section>

          <Separator />

          <section>
            <h3 className="mb-2 text-sm font-medium text-foreground">可监听地址</h3>
            {node.listen_ips.length === 0 ? (
              <p className="text-sm leading-6 text-muted-foreground">暂无可用地址，节点可能尚未连接或已离线。</p>
            ) : (
              <ul className="space-y-1">
                {node.listen_ips.map((ip) => (
                  <li key={ip} className="font-mono text-sm">
                    {ip}
                  </li>
                ))}
              </ul>
            )}
          </section>

          <Separator />

          <section>
            <h3 className="mb-2 text-sm font-medium text-foreground">标签</h3>
            <div className="flex flex-wrap gap-1.5">
              {node.labels.length === 0 ? (
                <p className="text-sm text-muted-foreground">无标签</p>
              ) : (
                node.labels.map((l) => (
                  <Badge key={l} variant="secondary">
                    {l}
                  </Badge>
                ))
              )}
            </div>
          </section>

          <Separator />

          <section>
            <h3 className="mb-2 text-sm font-medium text-foreground">添加时间</h3>
            <p className="text-sm text-muted-foreground">{formatDateTime(node.created_at)}</p>
          </section>

          {isOwner ? (
            <>
              <Separator />
              <section className="space-y-2">
                {canDelete ? (
                  <Button
                    type="button"
                    variant="destructive"
                    className="w-full"
                    disabled={deleteNode.isPending}
                    onClick={() => setConfirmDelete(true)}
                  >
                    <Trash2 aria-hidden />
                    删除待处理节点
                  </Button>
                ) : node.status !== "revoked" ? (
                  <>
                    <Button
                      type="button"
                      variant="outline"
                      className="w-full"
                      disabled={!canUpgrade || upgradeNode.isPending || uninstallNode.isPending}
                      onClick={() => setConfirmUpgrade(true)}
                    >
                      <RefreshCw aria-hidden />
                      在线升级 Agent
                    </Button>
                    <Button
                      type="button"
                      variant="destructive"
                      className="w-full"
                      disabled={!canUninstall || upgradeNode.isPending || uninstallNode.isPending}
                      onClick={() => setConfirmUninstall(true)}
                    >
                      <Unplug aria-hidden />
                      卸载 Agent
                    </Button>
                    {!canUninstall ? (
                      <p className="text-xs leading-5 text-muted-foreground">
                        卸载前需要节点在线、配置已同步，并且不再承载任何入口或隧道转发。
                      </p>
                    ) : null}
                  </>
                ) : (
                  <p className="text-xs leading-5 text-muted-foreground">节点身份已吊销，不再接受远程操作。</p>
                )}
              </section>
            </>
          ) : null}
        </div>
      </SheetContent>
      <ConfirmDialog
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        title={`删除节点 ${node.id}？`}
        description="该节点尚未连接。删除后，现有安装命令会立即失效，节点也会从列表中移除。"
        confirmLabel="删除节点"
        loading={deleteNode.isPending}
        onConfirm={async () => {
          try {
            await deleteNode.mutateAsync(node.id);
            setConfirmDelete(false);
            onOpenChange(false);
          } catch {
            // 错误提示由 mutation 统一处理。
          }
        }}
      />
      <ConfirmDialog
        open={confirmUpgrade}
        onOpenChange={setConfirmUpgrade}
        title={`升级 ${node.id} 的 Agent？`}
        description="节点会下载并校验 Controller 预设的发行包，然后自动重启。现有内核转发在重启期间继续工作。"
        confirmLabel="开始升级"
        loading={upgradeNode.isPending}
        onConfirm={async () => {
          try {
            await upgradeNode.mutateAsync(node.id);
            setConfirmUpgrade(false);
          } catch {
            // 错误提示由 mutation 统一处理。
          }
        }}
      />
      <ConfirmDialog
        open={confirmUninstall}
        onOpenChange={setConfirmUninstall}
        title={`卸载 ${node.id} 的 Agent？`}
        description="将清理 Flux 管理的转发、限速和隧道资源，删除 Agent 程序与节点身份，并永久吊销该节点。"
        confirmLabel="确认卸载"
        loading={uninstallNode.isPending}
        onConfirm={async () => {
          try {
            await uninstallNode.mutateAsync(node.id);
            setConfirmUninstall(false);
            onOpenChange(false);
          } catch {
            // 错误提示由 mutation 统一处理。
          }
        }}
      />
    </Sheet>
  );
}
