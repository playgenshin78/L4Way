import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";

import { LoginPage } from "@/features/auth/login-page";
import { renderApp, resetTestState } from "@/test/utils";

function renderLogin() {
  return renderApp(
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/overview" element={<div>概览页内容</div>} />
      <Route path="/forwards" element={<div>转发页内容</div>} />
    </Routes>,
    { route: "/login" },
  );
}

describe("登录页", () => {
  beforeEach(resetTestState);

  it("空表单提交时显示校验错误", async () => {
    const user = userEvent.setup();
    renderLogin();

    await user.click(screen.getByRole("button", { name: "登录" }));

    expect(await screen.findByText("请输入用户名")).toBeInTheDocument();
    expect(screen.getByText("请输入密码")).toBeInTheDocument();
  });

  it("密码错误时显示错误提示", async () => {
    const user = userEvent.setup();
    renderLogin();

    await user.type(screen.getByLabelText("用户名"), "owner");
    await user.type(screen.getByLabelText("密码"), "wrong-password");
    await user.click(screen.getByRole("button", { name: "登录" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("用户名或密码错误");
    // 停留在登录页
    expect(screen.getByRole("button", { name: "登录" })).toBeInTheDocument();
  });

  it("连续失败触发限流提示", async () => {
    const user = userEvent.setup();
    renderLogin();

    for (let i = 0; i < 5; i++) {
      await user.clear(screen.getByLabelText("用户名"));
      await user.type(screen.getByLabelText("用户名"), "owner");
      await user.clear(screen.getByLabelText("密码"));
      await user.type(screen.getByLabelText("密码"), `bad-${i}`);
      await user.click(screen.getByRole("button", { name: "登录" }));
      await screen.findByRole("alert");
    }

    await user.clear(screen.getByLabelText("用户名"));
    await user.type(screen.getByLabelText("用户名"), "owner");
    await user.clear(screen.getByLabelText("密码"));
    await user.type(screen.getByLabelText("密码"), "bad-final");
    await user.click(screen.getByRole("button", { name: "登录" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("尝试次数过多");
  });

  it("租户登录成功后跳转到转发页", async () => {
    const user = userEvent.setup();
    renderLogin();

    await user.type(screen.getByLabelText("用户名"), "alice");
    await user.type(screen.getByLabelText("密码"), "alice123");
    await user.click(screen.getByRole("button", { name: "登录" }));

    await waitFor(() => expect(screen.getByText("转发页内容")).toBeInTheDocument());
  });
});
