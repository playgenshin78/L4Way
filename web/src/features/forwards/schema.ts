import { z } from "zod";

function isIPv4(value: string): boolean {
  const parts = value.split(".");
  return (
    parts.length === 4 &&
    parts.every((part) => /^\d{1,3}$/.test(part) && (part === "0" || !part.startsWith("0")) && Number(part) <= 255)
  );
}

function isHostname(value: string): boolean {
  const normalized = value.trim().replace(/\.$/, "").toLowerCase();
  if (!normalized || normalized.length > 253) return false;
  return normalized.split(".").every(
    (label) =>
      label.length >= 1 &&
      label.length <= 63 &&
      /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
  );
}

const nullableNumber = (msg: string) =>
  z.preprocess(
    (v) => (v === "" || v === undefined || v === null ? null : Number(v)),
    z.number({ invalid_type_error: msg }).positive(msg).nullable(),
  );

export const forwardFormSchema = z
  .object({
    tenant_id: z.string().optional(),
    protocols: z.array(z.enum(["tcp", "udp"])).min(1, "至少选择一种协议"),
    listen_address: z.string().min(1, "请选择监听地址"),
    listen_port: z.coerce
      .number({ invalid_type_error: "端口需为数字" })
      .int("端口需为整数")
      .min(1, "端口范围 1-65535")
      .max(65535, "端口范围 1-65535"),
    target_address: z
      .string()
      .trim()
      .min(1, "请输入目标地址或域名")
      .refine((value) => isIPv4(value) || isHostname(value), "请输入有效的 IPv4 地址或域名"),
    target_port: z.coerce
      .number({ invalid_type_error: "端口需为数字" })
      .int("端口需为整数")
      .min(1, "端口范围 1-65535")
      .max(65535, "端口范围 1-65535"),
    path_mode: z.enum(["direct", "via_exit"]),
    ingress_node_id: z.string().min(1, "请选择入口节点"),
    exit_node_id: z.string().nullable(),
    /** UI 以 Mbps 输入，提交时换算为 bps */
    rate_limit_mbps: nullableNumber("限速需为数字"),
    /** UI 以 GB 输入，提交时换算为 bytes */
    traffic_quota_gb: nullableNumber("配额需为数字"),
    expires_at: z.string().nullable(),
    enabled: z.boolean(),
  })
  .superRefine((values, ctx) => {
    if (values.path_mode === "via_exit" && !values.exit_node_id) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["exit_node_id"], message: "隧道转发需要选择出口节点" });
    }
  });

export type ForwardFormValues = z.infer<typeof forwardFormSchema>;

export const BPS_PER_MBPS = 1_000_000;
export const BYTES_PER_GB = 2 ** 30;
