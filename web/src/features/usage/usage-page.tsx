import { useQuery } from "@tanstack/react-query";
import { Activity } from "lucide-react";
import { useState } from "react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { EmptyState } from "@/components/shared/empty-state";
import { ErrorState } from "@/components/shared/error-state";
import { PageHeader } from "@/components/shared/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { getUsage } from "@/lib/api/system";
import { formatBytes, formatDate } from "@/lib/utils";

type RangeDays = 7 | 30 | 90;

function UsageChartTooltip({
  active,
  label,
  payload,
}: {
  active?: boolean;
  label?: string;
  payload?: Array<{ value?: number | string }>;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div className="min-w-32 rounded-lg border bg-popover px-3 py-2 text-popover-foreground shadow-lift">
      <p className="text-xs text-muted-foreground">{formatDate(label)}</p>
      <div className="mt-1 flex items-center justify-between gap-4 text-sm">
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-primary" aria-hidden />
          流量
        </span>
        <span className="font-mono font-medium tabular-nums">{formatBytes(Number(payload[0]?.value ?? 0))}</span>
      </div>
    </div>
  );
}

export function UsagePage() {
  const [days, setDays] = useState<RangeDays>(30);
  const usage = useQuery({
    queryKey: ["usage", days],
    queryFn: () => getUsage(days),
  });

  const data = usage.data;
  const quotaPercent =
    data?.quota.quota_bytes && data.quota.quota_bytes > 0
      ? Math.min(100, (data.quota.used_bytes / data.quota.quota_bytes) * 100)
      : 0;

  return (
    <div>
      <PageHeader
        title="流量"
        description="按网络实际传输量统计，包含协议开销和重传流量"
        actions={
          <div className="flex gap-1">
            {([7, 30, 90] as RangeDays[]).map((value) => (
              <Button
                key={value}
                size="sm"
                variant={days === value ? "default" : "outline"}
                onClick={() => setDays(value)}
              >
                {value} 天
              </Button>
            ))}
          </div>
        }
      />

      {usage.isPending ? (
        <div className="space-y-3">
          <Skeleton className="h-56 w-full" />
          <Skeleton className="h-40 w-full" />
        </div>
      ) : usage.isError ? (
        <ErrorState error={usage.error} onRetry={() => usage.refetch()} />
      ) : data ? (
        <>
          <div className="grid gap-3 md:grid-cols-3">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">累计用量</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-semibold tabular-nums">{formatBytes(data.quota.used_bytes)}</div>
                {data.quota.quota_bytes ? (
                  <>
                    <Progress className="mt-3" value={quotaPercent} />
                    <p className="mt-2 text-xs text-muted-foreground">
                      配额 {formatBytes(data.quota.quota_bytes)} · {quotaPercent.toFixed(1)}%
                    </p>
                  </>
                ) : (
                  <p className="mt-2 text-xs text-muted-foreground">未设置流量配额</p>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">带宽上限</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-semibold tabular-nums">
                  {data.rate_limit_mbps === null ? "不限" : `${data.rate_limit_mbps} Mbps`}
                </div>
                <p className="mt-2 text-xs leading-5 text-muted-foreground">账号可用的最高上下行带宽</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">账号到期</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-semibold">{data.expires_at ? formatDate(data.expires_at) : "长期有效"}</div>
                <p className="mt-2 text-xs text-muted-foreground">到期后转发会自动暂停</p>
              </CardContent>
            </Card>
          </div>

          <Card className="mt-4">
            <CardHeader>
              <CardTitle>流量趋势</CardTitle>
            </CardHeader>
            <CardContent className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data.series}>
                  <defs>
                    <linearGradient id="usage-fill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity={0.28} />
                      <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="hsl(var(--border))" />
                  <XAxis
                    dataKey="ts"
                    tickFormatter={(value) => new Date(value).toLocaleDateString("zh-CN", { month: "2-digit", day: "2-digit" })}
                    tick={{ fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <YAxis tickFormatter={(value) => formatBytes(Number(value))} tick={{ fontSize: 11 }} axisLine={false} tickLine={false} width={72} />
                  <Tooltip
                    content={<UsageChartTooltip />}
                    cursor={{ stroke: "hsl(var(--primary))", strokeDasharray: "4 4", strokeOpacity: 0.45 }}
                  />
                  <Area
                    type="monotone"
                    dataKey="bytes"
                    stroke="hsl(var(--primary))"
                    fill="url(#usage-fill)"
                    strokeWidth={2}
                    activeDot={{
                      r: 4,
                      fill: "hsl(var(--primary))",
                      stroke: "hsl(var(--background))",
                      strokeWidth: 2,
                    }}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          <Card className="mt-4">
            <CardHeader>
              <CardTitle>按转发统计</CardTitle>
            </CardHeader>
            {data.by_forward.length === 0 ? (
              <div className="px-4 pb-4">
                <EmptyState icon={Activity} title="暂无流量" description="节点上报数据后，会在这里显示每条转发的用量" />
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>转发</TableHead>
                    <TableHead>协议</TableHead>
                    <TableHead className="text-right">流量</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.by_forward.map((item) => (
                    <TableRow key={`${item.forward_id}-${item.protocol}`}>
                      <TableCell>
                        <div className="font-medium">{item.name}</div>
                        <div className="font-mono text-xs text-muted-foreground">{item.forward_id}</div>
                      </TableCell>
                      <TableCell className="uppercase">{item.protocol}</TableCell>
                      <TableCell className="text-right font-mono">{formatBytes(item.bytes)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </Card>
        </>
      ) : null}
    </div>
  );
}
