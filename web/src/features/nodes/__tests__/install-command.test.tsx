import { fireEvent, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it } from "vitest";

import { InstallCommandDialog } from "@/features/nodes/install-command-dialog";
import { loginAs, renderApp, resetTestState } from "@/test/utils";

describe("一次性安装命令", () => {
  beforeEach(resetTestState);

  it("生成命令并展示短时 token 安全提示", async () => {
    await loginAs("owner");
    const user = userEvent.setup();
    renderApp(<InstallCommandDialog open onOpenChange={() => {}} />);

    const dialog = await screen.findByRole("dialog");
    await user.type(screen.getByLabelText("节点名称"), "test-node-1");
    await user.click(screen.getByRole("button", { name: "生成安装命令" }));

    expect(await screen.findByText(/curl --fail.*bash -s -- agent/)).toBeInTheDocument();
    expect(screen.getByText(/接入码只能使用一次/)).toBeInTheDocument();
    expect(screen.getByText(/剩余 (14:5\d|15:0[01])/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /复制完整命令/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /只复制接入码/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /重新生成/ })).toBeInTheDocument();
    expect(dialog).toBeInTheDocument();
  });

  it("支持选择六小时有效期并重新生成", async () => {
    await loginAs("owner");
    const user = userEvent.setup();
    renderApp(<InstallCommandDialog open onOpenChange={() => {}} />);

    await user.type(screen.getByLabelText("节点名称"), "test-node-2");
    const trigger = screen.getByLabelText("安装命令有效期");
    const nativeSelect = trigger.parentElement?.querySelector("select");
    expect(nativeSelect).toBeInstanceOf(HTMLSelectElement);
    fireEvent.change(nativeSelect as HTMLSelectElement, { target: { value: "21600" } });
    await user.click(screen.getByRole("button", { name: "生成安装命令" }));

    expect(await screen.findByText(/剩余 (359:5\d|360:0[01])/)).toBeInTheDocument();
    const commandBefore = screen.getByText(/curl --fail.*bash -s -- agent/).textContent;
    await user.click(screen.getByRole("button", { name: /重新生成/ }));
    expect(await screen.findByText(/剩余 (359:5\d|360:0[01])/)).toBeInTheDocument();
    expect(screen.getByText(/curl --fail.*bash -s -- agent/).textContent).not.toBe(commandBefore);
  });
});
