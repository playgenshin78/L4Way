import { apiConfig, request } from "./client";
import type { FluxNode, InstallCommand, InstallCommandRequest, NodeActionResponse, NodeProtocolBlocksUpdate, Paginated } from "./types";

const emptyProtocolBlocks = () => ({ http: false, https: false, socks: false, tls: false });

export function listNodes() {
  return request<{ items: FluxNode[]; total: number }>("/nodes?limit=200").then((raw) => ({
    items: raw.items.map((node) => ({
      ...node,
      labels: node.labels ?? [],
      listen_ips: node.listen_ips ?? [],
      forwards_count: node.forwards_count ?? 0,
      protocol_blocks: { ...emptyProtocolBlocks(), ...(node.protocol_blocks ?? {}) },
      resource_version: node.resource_version ?? 1,
    })),
    total: raw.total,
    page: 1,
    page_size: 200,
  } satisfies Paginated<FluxNode>));
}

export async function createInstallCommand(input: InstallCommandRequest) {
  if (apiConfig.USE_MOCK) {
    return request<InstallCommand>("/nodes/install-command", { method: "POST", body: input });
  }
  const raw = await request<{
    node_id: string;
    token_id?: string;
    install_command: string;
    bundle_base64: string;
    expires_at: string;
  }>("/nodes/install-command", {
    method: "POST",
    body: { node_id: input.node_id, ttl_seconds: input.token_ttl_seconds },
  });
  return {
    node_id: raw.node_id,
    token_id: raw.token_id ?? raw.node_id,
    command: raw.install_command,
    bundle_base64: raw.bundle_base64,
    expires_at: raw.expires_at,
  } satisfies InstallCommand;
}

export function deletePendingNode(nodeId: string) {
  return request<void>(`/nodes/${encodeURIComponent(nodeId)}`, { method: "DELETE" });
}

export function updateNodeProtocolBlocks(nodeId: string, input: NodeProtocolBlocksUpdate) {
  return request<void>(`/nodes/${encodeURIComponent(nodeId)}/protocol-blocks`, { method: "PATCH", body: input });
}

export function upgradeNode(nodeId: string) {
  return request<NodeActionResponse>(`/nodes/${encodeURIComponent(nodeId)}/upgrade`, { method: "POST" });
}

export function uninstallNode(nodeId: string) {
  return request<NodeActionResponse>(`/nodes/${encodeURIComponent(nodeId)}/uninstall`, { method: "POST" });
}
