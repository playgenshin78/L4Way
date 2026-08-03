import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it } from "vitest";

import { ForwardsPage } from "@/features/forwards/forwards-page";
import { loginAs, renderApp, resetTestState } from "@/test/utils";

async function openCreateSheet(user: ReturnType<typeof userEvent.setup>) {
  const btn = await screen.findByRole("button", { name: /新建转发/ });
  await waitFor(() => expect(btn).toBeEnabled());
  await user.click(btn);
  return await screen.findByRole("dialog");
}

async function selectOption(
  _user: ReturnType<typeof userEvent.setup>,
  trigger: HTMLElement,
  value: string,
) {
  const nativeSelect = trigger.parentElement?.querySelector("select");
  expect(nativeSelect).toBeInstanceOf(HTMLSelectElement);
  fireEvent.change(nativeSelect as HTMLSelectElement, { target: { value } });
}

describe("创建转发表单", () => {
  beforeEach(resetTestState);

  it("必填校验：空表单提交显示错误", async () => {
    await loginAs("alice");
    const user = userEvent.setup();
    renderApp(<ForwardsPage />);

    await openCreateSheet(user);
    await user.click(screen.getByRole("button", { name: "创建转发" }));

    expect(screen.getByText("请选择入口节点")).toBeInTheDocument();
    expect(screen.getByText("请选择监听地址")).toBeInTheDocument();
    expect(screen.getByText("请输入目标地址或域名")).toBeInTheDocument();
  });

  it("tenant 完整填写后创建成功并出现在列表中", async () => {
    await loginAs("alice");
    const user = userEvent.setup();
    renderApp(<ForwardsPage />);

    // 等待列表加载
    expect(await screen.findByText("203.0.113.10:20001")).toBeInTheDocument();

    const dialog = await openCreateSheet(user);

    await selectOption(user, within(dialog).getByLabelText("入口节点"), "fra-01");
    await selectOption(user, within(dialog).getByLabelText("监听地址"), "203.0.113.10");
    await user.type(within(dialog).getByLabelText("监听端口"), "20050");
    await user.type(within(dialog).getByLabelText("目标地址或域名"), "10.0.9.9");
    await user.type(within(dialog).getByLabelText("目标端口"), "8080");

    await user.click(within(dialog).getByRole("button", { name: "创建转发" }));

    // Sheet 关闭，新转发出现在列表第一行（按更新时间排序）
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(await screen.findByText("203.0.113.10:20050")).toBeInTheDocument();
  });

  it("违反策略（端口超出范围）时显示服务端错误", async () => {
    await loginAs("alice");
    const user = userEvent.setup();
    renderApp(<ForwardsPage />);
    expect(await screen.findByText("203.0.113.10:20001")).toBeInTheDocument();

    const dialog = await openCreateSheet(user);
    await selectOption(user, within(dialog).getByLabelText("入口节点"), "fra-01");
    await selectOption(user, within(dialog).getByLabelText("监听地址"), "203.0.113.10");
    await user.type(within(dialog).getByLabelText("监听端口"), "9999"); // 不在 20000-20100 / 30000-30100
    await user.type(within(dialog).getByLabelText("目标地址或域名"), "10.0.9.9");
    await user.type(within(dialog).getByLabelText("目标端口"), "8080");

    await user.click(within(dialog).getByRole("button", { name: "创建转发" }));

    expect(await within(dialog).findByRole("alert")).toHaveTextContent("监听端口不在分配给你的端口范围内");
  });

  it("tenant 的表单选项由策略裁剪：看不到未分配的节点", async () => {
    await loginAs("alice");
    const user = userEvent.setup();
    renderApp(<ForwardsPage />);
    expect(await screen.findByText("203.0.113.10:20001")).toBeInTheDocument();

    const dialog = await openCreateSheet(user);
    const nodeSelect = within(dialog).getByLabelText("入口节点");
    const nativeSelect = nodeSelect.parentElement?.querySelector("select");
    expect(nativeSelect).toBeInstanceOf(HTMLSelectElement);
    const optionTexts = Array.from((nativeSelect as HTMLSelectElement).options).map((o) => o.textContent);

    expect(optionTexts).toContain("fra-01");
    expect(optionTexts).toContain("fra-02");
    // alice 的策略只允许 fra-01 / fra-02 作为入口
    expect(optionTexts).not.toContain("nyc-01");
    expect(optionTexts).not.toContain("lon-01");
  });

  it("支持使用域名作为 IPv4 目标", async () => {
    await loginAs("alice");
    const user = userEvent.setup();
    renderApp(<ForwardsPage />);
    expect(await screen.findByText("203.0.113.10:20001")).toBeInTheDocument();

    const dialog = await openCreateSheet(user);
    await selectOption(user, within(dialog).getByLabelText("入口节点"), "fra-01");
    await selectOption(user, within(dialog).getByLabelText("监听地址"), "203.0.113.10");
    await user.type(within(dialog).getByLabelText("监听端口"), "20051");
    await user.type(within(dialog).getByLabelText("目标地址或域名"), "example.com");
    await user.type(within(dialog).getByLabelText("目标端口"), "443");

    await user.click(within(dialog).getByRole("button", { name: "创建转发" }));

    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(await screen.findByText("example.com:443")).toBeInTheDocument();
  });

  it("管理员可以创建自用转发，并能选择端口或隧道转发", async () => {
    await loginAs("owner");
    const user = userEvent.setup();
    renderApp(<ForwardsPage />);

    const dialog = await openCreateSheet(user);
    const ownerSelect = within(dialog).getByLabelText("归属");
    const ownerNativeSelect = ownerSelect.parentElement?.querySelector("select");
    expect(ownerNativeSelect).toBeInstanceOf(HTMLSelectElement);
    expect(Array.from((ownerNativeSelect as HTMLSelectElement).options).map((option) => option.textContent)).toContain("管理员自用");

    const pathSelect = within(dialog).getByLabelText("转发类型");
    const pathNativeSelect = pathSelect.parentElement?.querySelector("select");
    expect(pathNativeSelect).toBeInstanceOf(HTMLSelectElement);
    expect(Array.from((pathNativeSelect as HTMLSelectElement).options).map((option) => option.textContent)).toEqual(
      expect.arrayContaining(["端口转发", "隧道转发"]),
    );
  });

  it("只在点击后执行一次 TCP 连通检查", async () => {
	  await loginAs("alice");
	  const user = userEvent.setup();
	  renderApp(<ForwardsPage />);

	  const checks = await screen.findAllByRole("button", { name: "检查 TCP" });
	  expect(screen.queryByText("可连接")).not.toBeInTheDocument();
	  await user.click(checks[0]);
	  expect(await screen.findByText("可连接")).toBeInTheDocument();
  });
});
