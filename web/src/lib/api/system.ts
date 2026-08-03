import { apiConfig, request, requestDownload } from "./client";
import type {
  AuditEvent,
  AuditListQuery,
  AuditResult,
  BackupResult,
  Paginated,
  SystemStatus,
  UsageSummary,
} from "./types";

interface RawAuditEvent {
  id: number | string;
  created_at: string;
  actor_username: string;
  actor_role?: "owner" | "tenant";
  action: string;
  resource_type: string;
  resource_id?: string;
  outcome: "success" | "denied" | "error";
  source_ip?: string;
  detail?: Record<string, unknown>;
}

export async function listAudit(query: AuditListQuery): Promise<Paginated<AuditEvent>> {
  if (apiConfig.USE_MOCK) {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== "") params.set(key, String(value));
    }
    const encoded = params.toString();
    return request<Paginated<AuditEvent>>(`/audit${encoded ? `?${encoded}` : ""}`);
  }
  const raw = await request<{ items: RawAuditEvent[] }>("/audit?limit=200");
  const actor = query.actor?.trim().toLowerCase() ?? "";
  const items = raw.items
    .map((event): AuditEvent => ({
      id: String(event.id),
      created_at: event.created_at,
      actor: event.actor_username || "system",
      actor_role: event.actor_role === "tenant" ? "tenant" : "owner",
      action: event.action,
      resource_type: event.resource_type,
      resource_id: event.resource_id ?? "",
      resource_name: event.resource_id || event.resource_type,
      result: (event.outcome === "error" ? "failure" : event.outcome) as AuditResult,
      source_ip: event.source_ip ?? "",
      detail: event.detail ?? {},
    }))
    .filter((event) => {
      if (actor && !event.actor.toLowerCase().includes(actor)) return false;
      if (query.action && !event.action.startsWith(query.action)) return false;
      if (query.result && event.result !== query.result) return false;
      return true;
    });
  const page = Math.max(1, query.page ?? 1);
  const pageSize = Math.max(1, query.page_size ?? 20);
  const start = (page - 1) * pageSize;
  return { items: items.slice(start, start + pageSize), total: items.length, page, page_size: pageSize };
}

export function getUsage(days: 7 | 30 | 90) {
  return request<UsageSummary>(`/usage?days=${days}`);
}

export function getSystemStatus() {
  return request<SystemStatus>("/system/status");
}

export function createBackup() {
  return request<BackupResult>("/system/backup", { method: "POST", body: {} });
}

export function downloadBackup() {
  return requestDownload("/system/backup/download", "flux-backup.tar.gz");
}
