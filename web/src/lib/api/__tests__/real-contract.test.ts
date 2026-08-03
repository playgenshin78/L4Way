import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { logout } from "@/lib/api/auth";
import { apiConfig, __setFetcherForTest, setCsrfToken } from "@/lib/api/client";
import { listForwards, updateForward } from "@/lib/api/forwards";
import { createInstallCommand } from "@/lib/api/nodes";
import { createTenant, getTenantPolicy } from "@/lib/api/tenants";
import type { TenantPolicy } from "@/lib/api/types";

const originalMock = apiConfig.USE_MOCK;

function data(value: unknown, status = 200) {
  return new Response(JSON.stringify({ data: value }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

beforeEach(() => {
  apiConfig.USE_MOCK = false;
  setCsrfToken("csrf-test");
});

afterEach(() => {
  apiConfig.USE_MOCK = originalMock;
  __setFetcherForTest(null);
  setCsrfToken("");
});

describe("真实 Controller 契约适配", () => {
  it("接受 204 无响应体", async () => {
    __setFetcherForTest(async () => new Response(null, { status: 204 }));
    await expect(logout()).resolves.toBeUndefined();
  });

  it("映射 Cluster Plan 转发并在 PATCH 前合并完整结构", async () => {
    const requests: Array<{ method: string; body: unknown }> = [];
    const rawForward = {
      id: "fwd_a",
      tenant_id: "tenant_a",
      protocols: ["tcp"],
      listen: { address: "198.51.100.10", port: 20000 },
      target: { address: "192.0.2.10", port: 443 },
      path_mode: "direct",
      ingress_node_id: "node_a",
      lifecycle: "active",
      resource_version: 3,
      editable: true,
      rate_limit: {
        ingress_bits_per_second: 10_000_000,
        egress_bits_per_second: 10_000_000,
        burst_bytes: 125_000,
      },
      traffic_quota: { bytes: 1_000_000, policy: "pause" },
    };
    __setFetcherForTest(async (_input, init) => {
      const method = init?.method ?? "GET";
      requests.push({ method, body: init?.body ? JSON.parse(String(init.body)) : null });
      if (method === "GET") return data(rawForward);
      return data({ forward: { ...rawForward, lifecycle: "paused", resource_version: 4 }, rollout: { scheduled: true, revision: 8 } });
    });

    const updated = await updateForward("fwd_a", { enabled: false, resource_version: 3 });
    expect(updated.status).toBe("paused");
    expect(updated.rollout?.state).toBe("pending");
    expect(requests[1].body).toMatchObject({
      protocols: ["tcp"],
      path_mode: "direct",
      ingress_node_id: "node_a",
      enabled: false,
      resource_version: 3,
    });
  });

  it("在客户端完成真实列表分页和筛选", async () => {
    __setFetcherForTest(async () =>
      data({
        items: [
          {
            id: "fwd_tcp",
            tenant_id: "tenant_a",
            protocols: ["tcp"],
            listen: { address: "198.51.100.10", port: 20000 },
            target: { address: "192.0.2.10", port: 443 },
            path_mode: "direct",
            ingress_node_id: "node_a",
            lifecycle: "active",
            resource_version: 1,
            editable: true,
          },
          {
            id: "fwd_udp",
            tenant_id: "tenant_a",
            protocols: ["udp"],
            listen: { address: "198.51.100.10", port: 20001 },
            target: { address: "192.0.2.11", port: 53 },
            path_mode: "direct",
            ingress_node_id: "node_a",
            lifecycle: "paused",
            resource_version: 1,
            editable: true,
          },
        ],
      }),
    );
    const result = await listForwards({ page: 1, page_size: 10, protocol: "udp" });
    expect(result.total).toBe(1);
    expect(result.items[0].id).toBe("fwd_udp");
  });

  it("将租户初始策略原子发送，并适配节点安装命令字段", async () => {
    const bodies: unknown[] = [];
    const policy: TenantPolicy = {
      allowed_ingress_nodes: [],
      allowed_exit_nodes: [],
      allowed_listen_ips: [],
      allowed_port_ranges: [{ start: 20000, end: 29999 }],
      allowed_protocols: ["tcp", "udp"],
      allow_via_exit: false,
      max_forwards: 5,
      ingress_rate_limit_bps: null,
      egress_rate_limit_bps: null,
      traffic_quota_bytes: null,
      allowed_target_cidrs: [],
      denied_target_cidrs: [],
    };
    __setFetcherForTest(async (input, init) => {
      bodies.push(init?.body ? JSON.parse(String(init.body)) : null);
      const path = String(input);
      if (path.endsWith("/tenants")) {
        return data({
          tenant: {
            id: "tenant_a",
            name: "Alice",
            username: "alice",
            display_name: "Alice",
            status: "active",
            forwards_count: 0,
            created_at: "2026-01-01T00:00:00Z",
            resource_version: 1,
          },
        }, 201);
      }
      return data({
        node_id: "node_a",
        install_command: "sudo ./flux-agent install --bundle-base64 'abc'",
        bundle_base64: "abc",
        expires_at: "2026-01-01T00:15:00Z",
      }, 201);
    });

    const tenant = await createTenant({ username: "alice", display_name: "Alice", password: "long-password", policy });
    const command = await createInstallCommand({ node_id: "node_a", token_ttl_seconds: 900 });
    expect(tenant.username).toBe("alice");
    expect(bodies[0]).toMatchObject({ name: "Alice", policy: { max_forwards: 5 } });
    expect(bodies[1]).toEqual({ node_id: "node_a", ttl_seconds: 900 });
    expect(command.command).toContain("--bundle-base64");
    expect(command.bundle_base64).toBe("abc");
  });

  it("将 Controller 返回的空租户策略字段归一化为空数组", async () => {
    __setFetcherForTest(async () =>
      data({
        tenant_id: "tenant_a",
        resource_version: 1,
        allowed_ingress_nodes: null,
        allowed_exit_nodes: null,
        allowed_listen_ips: null,
        allowed_port_ranges: null,
        allowed_protocols: null,
        allow_via_exit: null,
        max_forwards: null,
        ingress_rate_limit_bps: null,
        egress_rate_limit_bps: null,
        traffic_quota_bytes: null,
        allowed_target_cidrs: null,
        denied_target_cidrs: null,
      }),
    );

    const result = await getTenantPolicy("tenant_a");
    expect(result.policy).toMatchObject({
      allowed_ingress_nodes: [],
      allowed_exit_nodes: [],
      allowed_listen_ips: [],
      allowed_port_ranges: [],
      allowed_protocols: [],
      allowed_target_cidrs: [],
      denied_target_cidrs: [],
    });
  });
});
