import { RefreshCw, ShieldAlert, Timer } from "lucide-react";
import { useEffect, useState } from "react";

import { CopyButton } from "@/components/shared/copy-button";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ApiError } from "@/lib/api/client";
import type { InstallCommand } from "@/lib/api/types";
import { formatCountdown, useCountdownSeconds } from "@/lib/hooks/use-countdown";
import { useInstallCommand } from "./hooks";

const TTL_OPTIONS = [
  { label: "15 分钟", seconds: 900 },
  { label: "30 分钟", seconds: 1800 },
  { label: "1 小时", seconds: 3600 },
  { label: "6 小时", seconds: 21600 },
];

/**
 * 添加节点：输入 node_id 与 token 有效期，调用 install-command 接口生成一次性安装命令。
 */
export function InstallCommandDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [nodeId, setNodeId] = useState("");
  const [ttl, setTtl] = useState(900);
  const [formError, setFormError] = useState<string | null>(null);
  const [command, setCommand] = useState<InstallCommand | null>(null);

  const installCommand = useInstallCommand();
  const secondsLeft = useCountdownSeconds(command?.expires_at);
  const expired = command !== null && secondsLeft <= 0;

  useEffect(() => {
    if (open) {
      setNodeId("");
      setTtl(900);
      setFormError(null);
      setCommand(null);
    }
  }, [open]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setFormError(null);
    try {
      const cmd = await installCommand.mutateAsync({ node_id: nodeId.trim(), token_ttl_seconds: ttl });
      setCommand(cmd);
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : "生成失败，请稍后重试");
    }
  }

  async function regenerate() {
    if (!command) return;
    setFormError(null);
    try {
      const cmd = await installCommand.mutateAsync({ node_id: command.node_id, token_ttl_seconds: ttl });
      setCommand(cmd);
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : "生成失败，请稍后重试");
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-xl">
        {command === null ? (
          <>
            <DialogHeader>
              <DialogTitle>添加节点</DialogTitle>
              <DialogDescription>填写节点名称并设置安装命令的有效期。</DialogDescription>
            </DialogHeader>
            <form onSubmit={submit} className="space-y-4">
              {formError ? (
                <p role="alert" className="rounded-lg border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm text-destructive">
                  {formError}
                </p>
              ) : null}
              <div className="space-y-1.5">
                <Label htmlFor="node-id">节点名称</Label>
                <Input
                  id="node-id"
                  value={nodeId}
                  onChange={(e) => setNodeId(e.target.value)}
                  placeholder="例如 fra-03"
                  pattern="[a-z0-9][a-z0-9-]{1,30}"
                  title="2-31 位小写字母、数字或短横线"
                  required
                />
                <p className="text-xs leading-5 text-muted-foreground">
                  使用 2–31 位小写字母、数字或短横线；已接入的名称不能重复使用。
                </p>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="token-ttl">安装命令有效期</Label>
                <Select value={String(ttl)} onValueChange={(value) => setTtl(Number(value))}>
                  <SelectTrigger id="token-ttl">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                  {TTL_OPTIONS.map((o) => (
                    <SelectItem key={o.seconds} value={String(o.seconds)}>
                      {o.label}
                    </SelectItem>
                  ))}
                  </SelectContent>
                </Select>
              </div>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={installCommand.isPending}>
                  取消
                </Button>
                <Button type="submit" disabled={installCommand.isPending}>
                  {installCommand.isPending ? "生成中…" : "生成安装命令"}
                </Button>
              </DialogFooter>
            </form>
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>在「{command.node_id}」上执行安装命令</DialogTitle>
              <DialogDescription>在 Linux 节点终端粘贴执行，程序会自动下载、校验并完成接入。</DialogDescription>
            </DialogHeader>

            <div className="space-y-3">
              <div className="rounded-lg border bg-muted/50 p-3">
                <code className="block break-all font-mono text-xs leading-relaxed">{command.command}</code>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <CopyButton text={command.command} label="复制完整命令" />
                <CopyButton text={command.bundle_base64} label="只复制接入码" variant="ghost" />
                <Button type="button" variant="outline" size="sm" onClick={regenerate} disabled={installCommand.isPending}>
                  <RefreshCw aria-hidden />
                  重新生成
                </Button>
                <span
                  aria-live="polite"
                  className={
                    expired
                      ? "ml-auto text-sm font-medium text-destructive"
                      : "ml-auto flex items-center gap-1 text-sm tabular-nums text-muted-foreground"
                  }
                >
                  <Timer className="h-3.5 w-3.5" aria-hidden />
                  {expired ? "安装命令已过期，请重新生成" : `剩余 ${formatCountdown(secondsLeft)}`}
                </span>
              </div>

              <p className="flex items-start gap-1.5 rounded-lg bg-muted/60 p-3 text-xs leading-5 text-muted-foreground">
                <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-warning" aria-hidden />
                通常复制完整命令；如果已单独运行安装脚本，只需粘贴接入码。接入码只能使用一次，请勿公开分享。
              </p>
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
                完成
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
