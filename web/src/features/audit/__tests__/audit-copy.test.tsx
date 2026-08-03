import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it } from "vitest";

import { AuditPage } from "@/features/audit/audit-page";
import { loginAs, renderApp, resetTestState } from "@/test/utils";

describe("审计文案", () => {
  beforeEach(resetTestState);

  it("用可读中文展示操作和详情，不暴露内部字段", async () => {
    await loginAs("owner");
    const user = userEvent.setup();
    renderApp(<AuditPage />);

    const row = await screen.findByRole("row", { name: "查看审计详情 修改租户权限" });
    expect(within(row).getByText("修改租户权限")).toBeInTheDocument();
    expect(within(row).getByText("租户账号")).toBeInTheDocument();
    expect(within(row).queryByText("t-acme")).not.toBeInTheDocument();
    expect(screen.queryByText("tenant.policy.update")).not.toBeInTheDocument();

    await user.click(row);
    const dialog = await screen.findByRole("dialog", { name: "修改租户权限" });
    expect(within(dialog).getByText("转发数量上限")).toBeInTheDocument();
    expect(within(dialog).queryByText("max_forwards")).not.toBeInTheDocument();
    expect(within(dialog).queryByText("t-acme")).not.toBeInTheDocument();
  });
});
