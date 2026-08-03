import { useEffect, useState } from "react";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError } from "@/lib/api/client";
import type { ForwardDeleteMode } from "@/lib/api/types";
import type { Forward } from "@/lib/api/types";
import { cn } from "@/lib/utils";
import { useDeleteForward } from "./hooks";

/**
 * 删除转发（二次确认）：
 * - drain：停止接收新连接，等待存量连接结束后清除（drain_seconds 30–86400）
 * - force：立即中断全部连接并清理 conntrack，危险操作
 */
export function DeleteForwardDialog({
  forward,
  open,
  onOpenChange,
}: {
  forward: Forward | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [mode, setMode] = useState<ForwardDeleteMode>("drain");
  const [drainSeconds, setDrainSeconds] = useState(300);
  const [error, setError] = useState<string | null>(null);
  const del = useDeleteForward();

  useEffect(() => {
    if (open) {
      setMode("drain");
      setDrainSeconds(300);
      setError(null);
    }
  }, [open]);

  const drainInvalid = mode === "drain" && (!Number.isInteger(drainSeconds) || drainSeconds < 30 || drainSeconds > 86400);

  async function confirm() {
    if (!forward) return;
    setError(null);
    try {
      await del.mutateAsync({
        id: forward.id,
        mode,
        resourceVersion: forward.resource_version,
        drainSeconds: mode === "drain" ? drainSeconds : undefined,
      });
      onOpenChange(false);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "删除失败，请稍后重试");
    }
  }

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>删除转发 {forward?.id}？</AlertDialogTitle>
          <AlertDialogDescription>
            监听地址 {forward?.listen.address}:{forward?.listen.port} 将被释放。请选择删除方式：
          </AlertDialogDescription>
        </AlertDialogHeader>

        {error ? (
          <p role="alert" className="rounded-lg border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm text-destructive">
            {error}
          </p>
        ) : null}

        <div role="radiogroup" aria-label="删除方式" className="space-y-2">
          <label
            className={cn(
              "flex cursor-pointer gap-3 rounded-lg border p-3 transition-colors duration-200 hover:bg-accent/50",
              mode === "drain" && "border-primary bg-primary/5",
            )}
          >
            <input
              type="radio"
              name="delete-mode"
              value="drain"
              checked={mode === "drain"}
              onChange={() => setMode("drain")}
              className="mt-1 h-4 w-4 accent-[hsl(var(--primary))]"
            />
            <span className="flex-1">
              <span className="block text-sm font-medium">平滑删除（推荐）</span>
              <span className="mt-0.5 block text-xs leading-5 text-muted-foreground">
                停止接收新连接，等待现有连接自然结束后再删除。适合游戏和 SSH 等长连接服务。
              </span>
              {mode === "drain" ? (
                <span className="mt-2 flex items-center gap-2">
                  <Label htmlFor="drain-seconds" className="text-xs text-muted-foreground">
                    最长等待时间（秒）
                  </Label>
                  <Input
                    id="drain-seconds"
                    type="number"
                    min={30}
                    max={86400}
                    value={drainSeconds}
                    onChange={(e) => setDrainSeconds(Number(e.target.value))}
                    className="h-7 w-28 text-xs"
                  />
                </span>
              ) : null}
              {mode === "drain" && drainInvalid ? (
                <span className="mt-1 block text-xs text-destructive">需在 30–86400 秒之间</span>
              ) : null}
            </span>
          </label>

          <label
            className={cn(
              "flex cursor-pointer gap-3 rounded-lg border border-destructive/40 p-3 transition-colors duration-200 hover:bg-destructive/5",
              mode === "force" && "border-destructive bg-destructive/10",
            )}
          >
            <input
              type="radio"
              name="delete-mode"
              value="force"
              checked={mode === "force"}
              onChange={() => setMode("force")}
              className="mt-1 h-4 w-4 accent-[hsl(var(--destructive))]"
            />
            <span>
              <span className="block text-sm font-medium text-destructive">立即删除（会断开连接）</span>
              <span className="mt-0.5 block text-xs leading-5 text-muted-foreground">
                立即中断所有现有连接并彻底删除转发。适合紧急下线或修正错误配置，在线用户会立刻断开。
              </span>
            </span>
          </label>
        </div>

        <AlertDialogFooter>
          <AlertDialogCancel disabled={del.isPending}>取消</AlertDialogCancel>
          <AlertDialogAction
            disabled={del.isPending || drainInvalid}
            className={mode === "force" ? "bg-destructive text-destructive-foreground hover:bg-destructive/90" : undefined}
            onClick={(e) => {
              e.preventDefault();
              void confirm();
            }}
          >
            {del.isPending ? "处理中…" : mode === "drain" ? "开始平滑删除" : "立即删除"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
