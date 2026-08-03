import { zodResolver } from "@hookform/resolvers/zod";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { ApiError } from "@/lib/api/client";
import type { TenantPolicy } from "@/lib/api/types";
import { useCreateTenant } from "./hooks";

const schema = z.object({
  username: z.string().regex(/^[a-z0-9_]{3,24}$/, "3-24 位小写字母、数字或下划线"),
  display_name: z.string().min(1, "请输入显示名称").max(40),
  password: z.string().min(12, "初始密码至少 12 位"),
  max_forwards: z.coerce.number().int().min(1).max(1000),
  quota_gb: z.preprocess(
    (v) => (v === "" || v === undefined || v === null ? null : Number(v)),
    z.number().int().min(1).max(1_000_000).nullable(),
  ),
});

type Values = z.infer<typeof schema>;

/** 新租户的默认策略：收敛最小权限，随后在详情页细化 */
export function defaultPolicy(): TenantPolicy {
  return {
    allowed_ingress_nodes: [],
    allowed_exit_nodes: [],
    allowed_listen_ips: [],
    allowed_port_ranges: [{ start: 20000, end: 29999 }],
    allowed_protocols: ["tcp", "udp"],
    allow_via_exit: false,
    max_forwards: 5,
    ingress_rate_limit_bps: null,
    egress_rate_limit_bps: null,
    traffic_quota_bytes: 100 * 2 ** 30,
    allowed_target_cidrs: [],
    denied_target_cidrs: [],
  };
}

export function CreateTenantDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const create = useCreateTenant();
  const [serverError, setServerError] = useState<string | null>(null);

  const form = useForm<Values>({
    resolver: zodResolver(schema),
    defaultValues: { username: "", display_name: "", password: "", max_forwards: 5, quota_gb: 100 },
  });

  async function onSubmit(values: Values) {
    setServerError(null);
    const policy = defaultPolicy();
    policy.max_forwards = values.max_forwards;
    policy.traffic_quota_bytes = values.quota_gb !== null ? values.quota_gb * 2 ** 30 : null;
    try {
      await create.mutateAsync({
        username: values.username,
        display_name: values.display_name,
        password: values.password,
        policy,
      });
      form.reset();
      onOpenChange(false);
    } catch (e) {
      setServerError(e instanceof ApiError ? e.message : "创建失败，请稍后重试");
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) form.reset();
        onOpenChange(o);
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>创建租户</DialogTitle>
          <DialogDescription>
            账号创建后默认没有可用节点和监听地址，请继续设置它的使用范围。
          </DialogDescription>
        </DialogHeader>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4" noValidate>
            {serverError ? (
              <p role="alert" className="rounded-lg border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm text-destructive">
                {serverError}
              </p>
            ) : null}
            <FormField
              control={form.control}
              name="username"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>登录用户名</FormLabel>
                  <FormControl>
                    <Input placeholder="例如 alice" autoComplete="off" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="display_name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>显示名称</FormLabel>
                  <FormControl>
                    <Input placeholder="例如 Acme 游戏加速" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="password"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>初始密码</FormLabel>
                  <FormControl>
                    <Input type="password" autoComplete="new-password" placeholder="至少 12 位" {...field} />
                  </FormControl>
                  <FormDescription>请通过安全渠道发送给租户，并提醒首次登录后修改</FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
            <div className="grid grid-cols-2 gap-3">
              <FormField
                control={form.control}
                name="max_forwards"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>转发数量上限</FormLabel>
                    <FormControl>
                      <Input type="number" inputMode="numeric" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="quota_gb"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>流量额度（GB，可空）</FormLabel>
                    <FormControl>
                      <Input type="number" inputMode="numeric" {...field} value={field.value ?? ""} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={create.isPending}>
                取消
              </Button>
              <Button type="submit" disabled={create.isPending}>
                {create.isPending ? "创建中…" : "创建租户"}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
