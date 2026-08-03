import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { navForRole } from "@/components/layout/nav-config";
import { SidebarNav } from "@/components/layout/sidebar";
import type { User } from "@/lib/api/types";

const owner: User = { id: "u-owner", username: "owner", display_name: "平台管理员", role: "owner", tenant_id: null };
const tenant: User = { id: "u-alice", username: "alice", display_name: "Alice", role: "tenant", tenant_id: "t-acme" };

describe("角色导航", () => {
  it("owner 拥有全部导航项", () => {
    const labels = navForRole("owner").map((i) => i.label);
    expect(labels).toEqual(["概览", "转发", "节点", "租户", "流量", "审计", "设置"]);
  });

  it("tenant 只有概览、转发、流量", () => {
    const labels = navForRole("tenant").map((i) => i.label);
    expect(labels).toEqual(["概览", "转发", "流量"]);
  });

  it("侧边栏按角色渲染导航", () => {
    const { unmount } = render(
      <MemoryRouter>
        <SidebarNav account={owner} />
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: /节点/ })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /租户/ })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /审计/ })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /设置/ })).toBeInTheDocument();
    unmount();

    render(
      <MemoryRouter>
        <SidebarNav account={tenant} />
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: /概览/ })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /转发/ })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /流量/ })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /节点/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /租户/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /审计/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /设置/ })).not.toBeInTheDocument();
  });
});
