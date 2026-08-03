import { zodResolver } from "@hookform/resolvers/zod";
import { useEffect, useMemo, useState } from "react";
import { useForm } from "react-hook-form";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { ApiError } from "@/lib/api/client";
import type { Forward, FluxNode, Protocol, Tenant, TenantPolicy } from "@/lib/api/types";
import { formatDate } from "@/lib/utils";
import { useCreateForward, useUpdateForward } from "./hooks";
import { BPS_PER_MBPS, BYTES_PER_GB, forwardFormSchema, type ForwardFormValues } from "./schema";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** null 表示创建；否则为编辑 */
  forward: Forward | null;
  nodes: FluxNode[];
  tenants: Tenant[];
  /** tenant 的策略（owner 为 null，不限制） */
  policy: TenantPolicy | null;
  policyExpiresAt: string | null;
  isOwner: boolean;
}

function toDateInputValue(iso: string | null): string {
  if (!iso) return "";
  return iso.slice(0, 10);
}

export function ForwardFormSheet({ open, onOpenChange, forward, nodes, tenants, policy, policyExpiresAt, isOwner }: Props) {
  const isEdit = forward !== null;
  const create = useCreateForward();
  const update = useUpdateForward();
  const [serverError, setServerError] = useState<string | null>(null);

  const form = useForm<ForwardFormValues>({
    resolver: zodResolver(forwardFormSchema),
    defaultValues: {
      tenant_id: "",
      protocols: ["tcp"],
      listen_address: "",
      listen_port: undefined as unknown as number,
      target_address: "",
      target_port: undefined as unknown as number,
      path_mode: "direct",
      ingress_node_id: "",
      exit_node_id: null,
      rate_limit_mbps: null,
      traffic_quota_gb: null,
      expires_at: "",
      enabled: true,
    },
  });

  const watchPathMode = form.watch("path_mode");
  const watchIngress = form.watch("ingress_node_id");

  useEffect(() => {
    if (!open) return;
    setServerError(null);
    if (forward) {
      form.reset({
        tenant_id: forward.tenant_id,
        protocols: forward.protocols,
        listen_address: forward.listen.address,
        listen_port: forward.listen.port,
        target_address: forward.target.address,
        target_port: forward.target.port,
        path_mode: forward.path_mode,
        ingress_node_id: forward.ingress_node_id,
        exit_node_id: forward.exit_node_id,
        rate_limit_mbps: forward.rate_limit !== null ? forward.rate_limit / BPS_PER_MBPS : null,
        traffic_quota_gb: forward.traffic_quota_bytes !== null ? forward.traffic_quota_bytes / BYTES_PER_GB : null,
        expires_at: toDateInputValue(forward.expires_at),
        enabled: forward.enabled,
      });
    } else {
      form.reset({
        // 管理员的自用转发不归属任何租户；后端以 owner 作为保留归属标识。
        tenant_id: isOwner ? "owner" : (tenants[0]?.id ?? ""),
        protocols: policy?.allowed_protocols?.slice(0, 1) ?? ["tcp"],
        listen_address: "",
        listen_port: undefined as unknown as number,
        target_address: "",
        target_port: undefined as unknown as number,
        path_mode: "direct",
        ingress_node_id: "",
        exit_node_id: null,
        rate_limit_mbps: null,
        traffic_quota_gb: null,
        expires_at: "",
        enabled: true,
      });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, forward?.id, isOwner]);

  /** tenant 的入口节点由 /nodes（已授权子集）提供；监听地址再结合策略过滤 */
  const ingressNodes = useMemo(() => {
    if (isOwner || !policy) return nodes;
    return nodes.filter((n) => policy.allowed_ingress_nodes.includes(n.id));
  }, [nodes, policy, isOwner]);

  const exitNodes = useMemo(() => {
    if (isOwner || !policy) return nodes;
    return nodes.filter((n) => policy.allowed_exit_nodes.includes(n.id));
  }, [nodes, policy, isOwner]);

  const selectedNode = useMemo(() => nodes.find((n) => n.id === watchIngress), [nodes, watchIngress]);

  const listenAddressOptions = useMemo(() => {
    if (!selectedNode) return [];
    if (isOwner || !policy) return selectedNode.listen_ips;
    return selectedNode.listen_ips.filter((ip) => policy.allowed_listen_ips.includes(ip));
  }, [selectedNode, policy, isOwner]);

  // 切换入口节点时，若当前监听地址不再可选则清空
  useEffect(() => {
    const addr = form.getValues("listen_address");
    if (addr && !listenAddressOptions.includes(addr)) form.setValue("listen_address", "");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [watchIngress, listenAddressOptions]);

  const pending = create.isPending || update.isPending;

  async function onSubmit(values: ForwardFormValues) {
    setServerError(null);
    const base = {
      protocols: values.protocols,
      listen: { address: values.listen_address, port: values.listen_port },
      target: { address: values.target_address, port: values.target_port },
      rate_limit: values.rate_limit_mbps !== null ? Math.round(values.rate_limit_mbps * BPS_PER_MBPS) : null,
      traffic_quota_bytes: values.traffic_quota_gb !== null ? Math.round(values.traffic_quota_gb * BYTES_PER_GB) : null,
      expires_at: values.expires_at ? new Date(`${values.expires_at}T23:59:59`).toISOString() : null,
      enabled: values.enabled,
    };
    try {
      if (isEdit && forward) {
        await update.mutateAsync({ id: forward.id, input: { ...base, resource_version: forward.resource_version } });
      } else {
        await create.mutateAsync({
          ...base,
          tenant_id: values.tenant_id || undefined,
          path_mode: values.path_mode,
          ingress_node_id: values.ingress_node_id,
          exit_node_id: values.path_mode === "via_exit" ? values.exit_node_id : null,
        });
      }
      onOpenChange(false);
    } catch (e) {
      setServerError(e instanceof ApiError ? e.message : "提交失败，请稍后重试");
    }
  }

  const portHint = policy
    ? `可用端口范围：${policy.allowed_port_ranges.map((r) => (r.start === r.end ? r.start : `${r.start}–${r.end}`)).join("，")}`
    : null;
  const cidrHint = policy ? `允许的目标网段：${policy.allowed_target_cidrs.join("，") || "（未配置）"}` : null;
  const rateCap = policy
    ? Math.min(policy.ingress_rate_limit_bps ?? Infinity, policy.egress_rate_limit_bps ?? Infinity)
    : null;
  const protocols = policy?.allowed_protocols ?? (["tcp", "udp"] as Protocol[]);

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="flex flex-col overflow-y-auto sm:max-w-md">
        <SheetHeader>
          <SheetTitle>{isEdit ? `编辑转发 ${forward.id}` : "新建转发"}</SheetTitle>
          <SheetDescription>
            {isEdit
              ? "路径和节点创建后不能修改；保存后会自动同步到入口节点。"
              : "保存后会自动同步到入口节点。"}
          </SheetDescription>
        </SheetHeader>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="mt-2 flex flex-1 flex-col gap-4 pb-2" noValidate>
            {serverError ? (
              <p role="alert" className="rounded-lg border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm text-destructive">
                {serverError}
              </p>
            ) : null}

            {isOwner && !isEdit ? (
              <FormField
                control={form.control}
                name="tenant_id"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>归属</FormLabel>
                    <Select name={field.name} value={field.value} onValueChange={field.onChange}>
                      <FormControl>
                        <SelectTrigger>
                          <SelectValue placeholder="请选择归属" />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        <SelectItem value="owner">管理员自用</SelectItem>
                        {tenants.map((t) => (
                          <SelectItem key={t.id} value={t.id}>
                            {t.display_name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <FormDescription>管理员自用的转发不归属任何租户。</FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
            ) : null}

            <FormField
              control={form.control}
              name="protocols"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>协议（可多选）</FormLabel>
                  <div className="flex gap-4">
                    {(["tcp", "udp"] as Protocol[]).map((p) => {
                      const allowed = protocols.includes(p);
                      const checked = field.value.includes(p);
                      return (
                        <label key={p} className="flex cursor-pointer items-center gap-2 text-sm uppercase">
                          <Checkbox
                            checked={checked}
                            disabled={!allowed}
                            onCheckedChange={(v) => {
                              const next = v === true ? [...field.value, p] : field.value.filter((x) => x !== p);
                              field.onChange(next);
                            }}
                            aria-label={`协议 ${p}`}
                          />
                          {p}
                          {!allowed ? <span className="text-xs text-muted-foreground">（未授权）</span> : null}
                        </label>
                      );
                    })}
                  </div>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="ingress_node_id"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>入口节点</FormLabel>
                  <Select name={field.name} value={field.value} onValueChange={field.onChange} disabled={isEdit}>
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder="请选择节点" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      {ingressNodes.map((n) => (
                        <SelectItem key={n.id} value={n.id}>
                          {n.id}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="path_mode"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>转发类型</FormLabel>
                  <Select name={field.name} value={field.value} onValueChange={field.onChange} disabled={isEdit}>
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="direct">端口转发</SelectItem>
                      <SelectItem value="via_exit" disabled={!isOwner && !policy?.allow_via_exit}>
                        隧道转发
                      </SelectItem>
                    </SelectContent>
                  </Select>
                  <FormDescription>
                    {watchPathMode === "via_exit"
                      ? "经出口节点转发到目标；链路是否加密取决于节点网络配置。"
                      : "入口节点直接将端口转发到目标地址。"}
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            {watchPathMode === "via_exit" ? (
              <FormField
                control={form.control}
                name="exit_node_id"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>出口节点</FormLabel>
                    <Select
                      name={field.name}
                      value={field.value ?? ""}
                      onValueChange={field.onChange}
                      disabled={isEdit}
                    >
                      <FormControl>
                        <SelectTrigger>
                          <SelectValue placeholder="请选择出口节点" />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        {exitNodes.map((n) => (
                          <SelectItem key={n.id} value={n.id}>
                            {n.id}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />
            ) : null}

            <div className="grid grid-cols-2 gap-3">
              <FormField
                control={form.control}
                name="listen_address"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>监听地址</FormLabel>
                    <Select
                      name={field.name}
                      value={field.value}
                      onValueChange={field.onChange}
                      disabled={!selectedNode || listenAddressOptions.length === 0}
                    >
                      <FormControl>
                        <SelectTrigger>
                          <SelectValue
                            placeholder={
                              !selectedNode
                                ? "先选择节点"
                                : listenAddressOptions.length === 0
                                  ? "该节点无可用地址"
                                  : "请选择地址"
                            }
                          />
                        </SelectTrigger>
                      </FormControl>
                      {listenAddressOptions.length > 0 ? (
                        <SelectContent>
                          {listenAddressOptions.map((ip) => (
                            <SelectItem key={ip} value={ip}>
                              {ip}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      ) : null}
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="listen_port"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>监听端口</FormLabel>
                    <FormControl>
                      <Input type="number" inputMode="numeric" placeholder="20001" {...field} value={field.value ?? ""} />
                    </FormControl>
                    {portHint ? <FormDescription>{portHint}</FormDescription> : null}
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <FormField
                control={form.control}
                name="target_address"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>目标地址或域名</FormLabel>
                    <FormControl>
                      <Input placeholder="10.0.1.15 或 example.com" {...field} />
                    </FormControl>
                    {cidrHint ? <FormDescription>域名解析出的 IPv4 也必须符合：{cidrHint}</FormDescription> : null}
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="target_port"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>目标端口</FormLabel>
                    <FormControl>
                      <Input type="number" inputMode="numeric" placeholder="25565" {...field} value={field.value ?? ""} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <FormField
                control={form.control}
                name="rate_limit_mbps"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>带宽上限（Mbps，可空）</FormLabel>
                    <FormControl>
                      <Input type="number" inputMode="numeric" placeholder="不限" {...field} value={field.value ?? ""} />
                    </FormControl>
                    {rateCap !== null && Number.isFinite(rateCap) ? (
                      <FormDescription>带宽上限 {Math.round(rateCap / BPS_PER_MBPS)} Mbps</FormDescription>
                    ) : null}
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="traffic_quota_gb"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>流量配额（GB，可空）</FormLabel>
                    <FormControl>
                      <Input type="number" inputMode="numeric" placeholder="不限" {...field} value={field.value ?? ""} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            <FormField
              control={form.control}
              name="expires_at"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>到期时间（可空）</FormLabel>
                  <FormControl>
                    <Input
                      type="date"
                      {...field}
                      value={field.value ?? ""}
                      max={toDateInputValue(policyExpiresAt) || undefined}
                    />
                  </FormControl>
                  {policyExpiresAt ? <FormDescription>账号到期日：{formatDate(policyExpiresAt)}</FormDescription> : null}
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="enabled"
              render={({ field }) => (
                <FormItem className="flex items-center justify-between gap-4 rounded-lg border p-3">
                  <div>
                    <FormLabel className="text-sm font-medium">立即启用</FormLabel>
                    <FormDescription>关闭后仅保存配置，不会启用转发</FormDescription>
                  </div>
                  <FormControl>
                    <Switch checked={field.value} onCheckedChange={field.onChange} aria-label="立即启用" />
                  </FormControl>
                </FormItem>
              )}
            />

            <div className="mt-auto flex justify-end gap-2 border-t pt-4">
              <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={pending}>
                取消
              </Button>
              <Button type="submit" disabled={pending}>
                {pending ? "提交中…" : isEdit ? "保存修改" : "创建转发"}
              </Button>
            </div>
          </form>
        </Form>
      </SheetContent>
    </Sheet>
  );
}
