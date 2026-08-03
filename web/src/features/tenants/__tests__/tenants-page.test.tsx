import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it } from "vitest";

import { TenantsPage } from "@/features/tenants/tenants-page";
import { loginAs, renderApp, resetTestState } from "@/test/utils";

describe("租户列表交互", () => {
  beforeEach(resetTestState);

  it("点击租户行先打开详情抽屉，不直接跳转页面", async () => {
    await loginAs("owner");
    const user = userEvent.setup();
    renderApp(<TenantsPage />);

    await user.click(await screen.findByRole("row", { name: "查看租户 Acme 游戏加速" }));

    const dialog = await screen.findByRole("dialog", { name: /Acme 游戏加速/ });
    expect(within(dialog).getByText("@alice")).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "管理租户设置" })).toBeInTheDocument();
  });
});
