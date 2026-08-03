import { ArrowLeft, Info, Plus, ShieldAlert, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { ErrorState } from "@/components/shared/error-state";
import { PageHeader } from "@/components/shared/page-header";
import { TenantStatusBadge } from "@/components/shared/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { ApiError } from "@/lib/api/client";
import type { TenantPolicy } from "@/lib/api/types";
import { useNodes } from "@/features/nodes/hooks";
import { formatDateTime } from "@/lib/utils";
import { useTenant, useTenantPolicy, useUpdateTenant, useUpdateTenantPolicy } from "./hooks";

const CIDR_RE = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
const BPS_PER_MBPS = 1_000_000;
const BYTES_PER_GB = 2 ** 30;

function parseCidrs(text: string): string[] {
  return text
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
}

function invalidCidrLines(text: string): string[] {
  return parseCidrs(text).filter((s) => !CIDR_RE.test(s));
}

export function TenantDetailPage() {
  const { id = "" } = useParams();
  const tenantQuery = useTenant(id);
  const nodes = useNodes();
  const policyQuery = useTenantPolicy(id);
  const updatePolicy = useUpdateTenantPolicy(id);
  const updateTenant = useUpdateTenant(id);

  const tenant = tenantQuery.data;

  const [draft, setDraft] = useState<TenantPolicy | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  useEffect(() => {
    if (policyQuery.data) setDraft(policyQuery.data.policy);
  }, [policyQuery.data]);

  const dirty = useMemo(
    () => draft !== null && policyQuery.data !== undefined && JSON.stringify(draft) !== JSON.stringify(policyQuery.data.policy),
    [draft, policyQuery.data],
  );

  if (policyQuery.isPending || tenantQuery.isPending) {
    return (
      <div className="space-y-4" aria-busy="true">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-64 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (policyQuery.isError || tenantQuery.isError || !draft || !tenant) {
    return <ErrorState error={policyQuery.error ?? tenantQuery.error} onRetry={() => {
      void policyQuery.refetch();
      void tenantQuery.refetch();
    }} />;
  }

  const patch = (p: Partial<TenantPolicy>) => {
    setDraft((d) => (d ? { ...d, ...p } : d));
    setSaveError(null);
  };

  function toggle<T>(list: T[], value: T, on: boolean): T[] {
    return on ? [...new Set([...list, value])] : list.filter((v) => v !== value);
  }

  const allowedCidrText = draft.allowed_target_cidrs.join("\n");
  const deniedCidrText = draft.denied_target_cidrs.join("\n");
  const badAllowed = invalidCidrLines(allowedCidrText);
  const badDenied = invalidCidrLines(deniedCidrText);

  const invalidRanges = draft.allowed_port_ranges.some(
    (r) => !Number.isInteger(r.start) || !Number.isInteger(r.end) || r.start < 1 || r.end > 65535 || r.start > r.end,
  );

  async function save() {
    if (!draft || !policyQuery.data) return;
    setSaveError(null);
    try {
      await updatePolicy.mutateAsync({ resource_version: policyQuery.data.resource_version, policy: draft });
    } catch (e) {
      if (e instanceof ApiError && e.isConflict) {
        setSaveError("数据已变化，请刷新后再编辑。");
      } else {
        setSaveError(e instanceof ApiError ? e.message : "保存失败，请稍后重试");
      }
    }
  }

  return (
    <div>
      <div className="mb-4">
        <Button asChild variant="ghost" size="sm" className="-ml-2">
          <Link to="/tenants">
            <ArrowLeft aria-hidden />
            返回租户列表
          </Link>
        </Button>
      </div>

      <PageHeader
        title={tenant.display_name}
        description={`@${tenant.username} · 创建于 ${formatDateTime(tenant.created_at)}`}
        actions={<TenantStatusBadge status={tenant.status} />}
      />

      {saveError ? (
        <p role="alert" className="mb-4 flex items-center justify-between rounded-lg border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm text-destructive">
          {saveError}
          <Button variant="outline" size="sm" onClick={() => policyQuery.refetch()}>
            刷新数据
          </Button>
        </p>
      ) : null}

      <div className="mb-4 flex items-start gap-2 rounded-xl border border-warning/40 bg-warning/5 p-3 text-xs leading-5 text-muted-foreground">
        <Info className="mt-[3px] h-3.5 w-3.5 shrink-0 text-warning" aria-hidden />
        <p className="min-w-0">禁用账号、账号到期或收紧权限时，不再符合要求的转发会自动暂停；放宽权限后需由租户手动恢复。</p>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle>账号</CardTitle>
              <CardDescription>账号状态和有效期的修改会立即生效</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <Label htmlFor="tenant-enabled" className="text-sm font-medium">
                    启用账号
                  </Label>
                  <p className="mt-0.5 text-xs leading-5 text-muted-foreground">禁用后该租户无法登录，现有转发会自动暂停</p>
                </div>
                <Switch
                  id="tenant-enabled"
                  checked={tenant.status === "active"}
                  disabled={updateTenant.isPending}
                  onCheckedChange={(v) =>
                    updateTenant.mutate({ status: v ? "active" : "disabled", resource_version: tenant.resource_version })
                  }
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="tenant-expires">账号有效期</Label>
                <p className="text-xs leading-5 text-muted-foreground">留空表示长期有效</p>
                <div className="flex gap-2">
                  <Input
                    id="tenant-expires"
                    type="date"
                    value={tenant.expires_at ? tenant.expires_at.slice(0, 10) : ""}
                    disabled={updateTenant.isPending}
                    onChange={(e) =>
                      updateTenant.mutate({
                        expires_at: e.target.value ? new Date(`${e.target.value}T23:59:59`).toISOString() : null,
                        resource_version: tenant.resource_version,
                      })
                    }
                  />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle>节点与监听</CardTitle>
              <CardDescription>设置租户可用的入口节点、出口节点、监听地址和端口范围</CardDescription>
            </CardHeader>
            <CardContent className="space-y-5">
              <fieldset>
                <legend className="mb-2 text-sm font-medium">可用入口节点</legend>
                <div className="space-y-2">
                  {(nodes.data?.items ?? [])
                    .filter((n) => n.status !== "revoked")
                    .map((n) => (
                      <label key={n.id} className="flex cursor-pointer items-center gap-2 text-sm">
                        <Checkbox
                          checked={draft.allowed_ingress_nodes.includes(n.id)}
                          onCheckedChange={(v) => patch({ allowed_ingress_nodes: toggle(draft.allowed_ingress_nodes, n.id, v === true) })}
                          aria-label={`入口节点 ${n.id}`}
                        />
                        <span className="font-mono text-xs">{n.id}</span>
                        <span className="text-xs text-muted-foreground">（{n.listen_ips.join("、") || "无可用地址"}）</span>
                      </label>
                    ))}
                </div>
              </fieldset>

              <fieldset>
                <legend className="mb-2 text-sm font-medium">可用出口节点</legend>
                <div className="space-y-2">
                  {(nodes.data?.items ?? [])
                    .filter((n) => n.status !== "revoked")
                    .map((n) => (
                      <label key={n.id} className="flex cursor-pointer items-center gap-2 text-sm">
                        <Checkbox
                          checked={draft.allowed_exit_nodes.includes(n.id)}
                          onCheckedChange={(v) => patch({ allowed_exit_nodes: toggle(draft.allowed_exit_nodes, n.id, v === true) })}
                          aria-label={`出口节点 ${n.id}`}
                        />
                        <span className="font-mono text-xs">{n.id}</span>
                      </label>
                    ))}
                </div>
              </fieldset>

              <fieldset>
                <legend className="mb-2 text-sm font-medium">可监听地址</legend>
                <div className="flex flex-wrap gap-x-4 gap-y-2">
                  {(nodes.data?.items ?? [])
                    .filter((n) => draft.allowed_ingress_nodes.includes(n.id))
                    .flatMap((n) => n.listen_ips)
                    .map((ip) => (
                      <label key={ip} className="flex cursor-pointer items-center gap-2 font-mono text-sm">
                        <Checkbox
                          checked={draft.allowed_listen_ips.includes(ip)}
                          onCheckedChange={(v) => patch({ allowed_listen_ips: toggle(draft.allowed_listen_ips, ip, v === true) })}
                        aria-label={`监听地址 ${ip}`}
                        />
                        {ip}
                      </label>
                    ))}
                  {draft.allowed_ingress_nodes.length === 0 ? (
                    <p className="text-xs text-muted-foreground">先选择入口节点</p>
                  ) : null}
                </div>
              </fieldset>

              <fieldset>
                <legend className="mb-2 text-sm font-medium">可用端口范围</legend>
                <div className="space-y-2">
                  {draft.allowed_port_ranges.map((r, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <Input
                        type="number"
                        value={r.start}
                        min={1}
                        max={65535}
                        aria-label={`端口范围 ${i + 1} 起始`}
                        className="w-28"
                        onChange={(e) => {
                          const next = [...draft.allowed_port_ranges];
                          next[i] = { ...r, start: Number(e.target.value) };
                          patch({ allowed_port_ranges: next });
                        }}
                      />
                      <span className="text-muted-foreground">–</span>
                      <Input
                        type="number"
                        value={r.end}
                        min={1}
                        max={65535}
                        aria-label={`端口范围 ${i + 1} 结束`}
                        className="w-28"
                        onChange={(e) => {
                          const next = [...draft.allowed_port_ranges];
                          next[i] = { ...r, end: Number(e.target.value) };
                          patch({ allowed_port_ranges: next });
                        }}
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        aria-label={`删除端口范围 ${i + 1}`}
                        onClick={() => patch({ allowed_port_ranges: draft.allowed_port_ranges.filter((_, j) => j !== i) })}
                      >
                        <Trash2 aria-hidden />
                      </Button>
                    </div>
                  ))}
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => patch({ allowed_port_ranges: [...draft.allowed_port_ranges, { start: 30000, end: 30100 }] })}
                  >
                    <Plus aria-hidden />
                    添加范围
                  </Button>
                  {invalidRanges ? <p className="text-xs text-destructive">端口范围需在 1-65535 内且起始不大于结束</p> : null}
                </div>
              </fieldset>
            </CardContent>
          </Card>
        </div>

        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle>协议与转发类型</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <fieldset>
                <legend className="mb-2 text-sm font-medium">允许的协议</legend>
                <div className="flex gap-4">
                  {(["tcp", "udp"] as const).map((p) => (
                    <label key={p} className="flex cursor-pointer items-center gap-2 text-sm uppercase">
                      <Checkbox
                        checked={draft.allowed_protocols.includes(p)}
                        onCheckedChange={(v) => patch({ allowed_protocols: toggle(draft.allowed_protocols, p, v === true) })}
                        aria-label={`协议 ${p}`}
                      />
                      {p}
                    </label>
                  ))}
                </div>
              </fieldset>
              <div className="flex items-center justify-between gap-4">
                <div>
                  <Label htmlFor="allow-via-exit" className="text-sm font-medium">
                    允许隧道转发
                  </Label>
                  <p className="mt-0.5 text-xs leading-5 text-muted-foreground">开启后，租户可以通过另一台节点转发到目标</p>
                </div>
                <Switch
                  id="allow-via-exit"
                  checked={draft.allow_via_exit}
                  onCheckedChange={(v) => patch({ allow_via_exit: v })}
                />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle>限额</CardTitle>
              <CardDescription>留空表示不限制</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <Label htmlFor="max-forwards">转发数量上限（条）</Label>
                  <Input
                    id="max-forwards"
                    type="number"
                    min={0}
                    value={draft.max_forwards}
                    onChange={(e) => patch({ max_forwards: Number(e.target.value) })}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="quota-gb">流量配额（GB）</Label>
                  <Input
                    id="quota-gb"
                    type="number"
                    min={1}
                    value={draft.traffic_quota_bytes !== null ? Math.round(draft.traffic_quota_bytes / BYTES_PER_GB) : ""}
                    onChange={(e) =>
                      patch({ traffic_quota_bytes: e.target.value === "" ? null : Number(e.target.value) * BYTES_PER_GB })
                    }
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="ingress-rate">入口带宽上限（Mbps）</Label>
                  <Input
                    id="ingress-rate"
                    type="number"
                    min={1}
                    value={draft.ingress_rate_limit_bps !== null ? draft.ingress_rate_limit_bps / BPS_PER_MBPS : ""}
                    onChange={(e) =>
                      patch({ ingress_rate_limit_bps: e.target.value === "" ? null : Number(e.target.value) * BPS_PER_MBPS })
                    }
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="egress-rate">出口带宽上限（Mbps）</Label>
                  <Input
                    id="egress-rate"
                    type="number"
                    min={1}
                    value={draft.egress_rate_limit_bps !== null ? draft.egress_rate_limit_bps / BPS_PER_MBPS : ""}
                    onChange={(e) =>
                      patch({ egress_rate_limit_bps: e.target.value === "" ? null : Number(e.target.value) * BPS_PER_MBPS })
                    }
                  />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle>目标网段</CardTitle>
              <CardDescription>每行填写一个网段，例如 10.0.0.0/8</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="allowed-cidrs">允许的目标网段</Label>
                <Textarea
                  id="allowed-cidrs"
                  value={allowedCidrText}
                  onChange={(e) => patch({ allowed_target_cidrs: parseCidrs(e.target.value) })}
                  rows={3}
                  className="font-mono text-xs"
                  placeholder={"10.0.0.0/8\n192.168.0.0/16"}
                />
                {badAllowed.length > 0 ? <p className="text-xs text-destructive">格式不正确：{badAllowed.join("、")}</p> : null}
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="denied-cidrs">禁止的目标网段（优先生效）</Label>
                <Textarea
                  id="denied-cidrs"
                  value={deniedCidrText}
                  onChange={(e) => patch({ denied_target_cidrs: parseCidrs(e.target.value) })}
                  rows={3}
                  className="font-mono text-xs"
                  placeholder={"10.255.0.0/16"}
                />
                {badDenied.length > 0 ? <p className="text-xs text-destructive">格式不正确：{badDenied.join("、")}</p> : null}
              </div>
              <p className="flex items-start gap-1.5 text-xs leading-5 text-muted-foreground">
                <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-warning" aria-hidden />
                平台会自动阻止管理网络、本机地址、链路本地地址和云平台元数据地址，无需手动填写。
              </p>
            </CardContent>
          </Card>
        </div>
      </div>

      <div className="sticky bottom-4 mt-6 flex justify-end">
        <div className="flex items-center gap-2 rounded-xl border bg-card p-2 shadow-lift">
          {dirty ? <span className="px-2 text-xs text-muted-foreground">有未保存的修改</span> : null}
          <Button
            variant="outline"
            size="sm"
            disabled={!dirty || updatePolicy.isPending}
            onClick={() => {
              setDraft(policyQuery.data.policy);
              setSaveError(null);
            }}
          >
            放弃修改
          </Button>
          <Button
            size="sm"
            disabled={!dirty || invalidRanges || badAllowed.length > 0 || badDenied.length > 0 || updatePolicy.isPending}
            onClick={save}
          >
            {updatePolicy.isPending ? "保存中…" : "保存设置"}
          </Button>
        </div>
      </div>
    </div>
  );
}
