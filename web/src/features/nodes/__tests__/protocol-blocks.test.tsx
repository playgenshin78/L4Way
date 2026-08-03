import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it } from "vitest";

import { NodeDetailSheet } from "@/features/nodes/node-detail-sheet";
import { listNodes } from "@/lib/api/nodes";
import { loginAs, renderApp, resetTestState } from "@/test/utils";

describe("节点协议拦截", () => {
  beforeEach(resetTestState);

  it("仅管理员可见，并保存节点级开关", async () => {
    await loginAs("owner");
    const node = (await listNodes()).items.find((item) => item.id === "fra-01")!;
    const user = userEvent.setup();

    const view = renderApp(<NodeDetailSheet node={node} open onOpenChange={() => {}} isOwner />);
    expect(screen.getByText("协议拦截（节点级）")).toBeInTheDocument();
    expect(screen.getByText(/随机 AES 数据不会因端口或高熵特征被拦截/)).toBeInTheDocument();

    await user.click(screen.getByRole("switch", { name: "拦截 HTTP" }));
    await waitFor(async () => {
      const updated = (await listNodes()).items.find((item) => item.id === "fra-01")!;
      expect(updated.protocol_blocks.http).toBe(true);
    });

    view.unmount();
    renderApp(<NodeDetailSheet node={node} open onOpenChange={() => {}} isOwner={false} />);
    expect(screen.queryByText("协议拦截（节点级）")).not.toBeInTheDocument();
  });

  it("为在线节点提供升级，并在节点仍承载转发时阻止卸载", async () => {
	  await loginAs("owner");
	  const node = (await listNodes()).items.find((item) => item.id === "fra-01")!;
	  renderApp(<NodeDetailSheet node={node} open onOpenChange={() => {}} isOwner />);

	  expect(screen.getByRole("button", { name: "在线升级 Agent" })).toBeEnabled();
	  expect(screen.getByRole("button", { name: "卸载 Agent" })).toBeDisabled();
	  expect(screen.getByText(/不再承载任何入口或隧道转发/)).toBeInTheDocument();
  });
});
