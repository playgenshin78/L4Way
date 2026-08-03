import { screen } from "@testing-library/react";
import { Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";

import { ApiError } from "@/lib/api/client";
import { listNodes } from "@/lib/api/nodes";
import { listForwards } from "@/lib/api/forwards";
import { listAudit } from "@/lib/api/system";
import { RequireOwner } from "@/features/auth/guards";
import { loginAs, renderApp, resetTestState } from "@/test/utils";

describe("Tenant 权限边界", () => {
  beforeEach(resetTestState);

  it("tenant 访问 owner 页面时展示 403 界面", async () => {
    await loginAs("alice");
    renderApp(
      <Routes>
        <Route
          path="/nodes"
          element={
            <RequireOwner>
              <div>节点页面内容</div>
            </RequireOwner>
          }
        />
      </Routes>,
      { route: "/nodes" },
    );

    expect(await screen.findByText("没有访问权限")).toBeInTheDocument();
    expect(screen.queryByText("节点页面内容")).not.toBeInTheDocument();
  });

  it("owner 访问 owner 页面时正常渲染", async () => {
    await loginAs("owner");
    renderApp(
      <Routes>
        <Route
          path="/nodes"
          element={
            <RequireOwner>
              <div>节点页面内容</div>
            </RequireOwner>
          }
        />
      </Routes>,
      { route: "/nodes" },
    );

    expect(await screen.findByText("节点页面内容")).toBeInTheDocument();
  });

  it("后端才是安全边界：tenant 只能读取授权节点，不能读取审计", async () => {
    await loginAs("alice");
    const visibleNodes = await listNodes();
    expect(visibleNodes.items.map((node) => node.id)).toEqual(["fra-01", "fra-02", "nyc-01"]);
    await expect(listAudit({})).rejects.toMatchObject({ status: 403 });
    await expect(listAudit({})).rejects.toBeInstanceOf(ApiError);
  });

  it("tenant 只能看到自己的转发", async () => {
    await loginAs("alice");
    const res = await listForwards({ page: 1, page_size: 100 });
    expect(res.total).toBeGreaterThan(0);
    for (const f of res.items) {
      expect(f.tenant_id).toBe("t-acme");
    }
  });
});
