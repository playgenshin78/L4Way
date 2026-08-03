import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, type RenderOptions } from "@testing-library/react";
import type { ReactElement, ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";

import { ThemeProvider } from "@/components/shared/theme-provider";
import * as authApi from "@/lib/api/auth";
import { setCsrfToken } from "@/lib/api/client";
import { resetMockRuntime } from "@/lib/api/mock/db";

export function makeTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0, staleTime: 0 },
      mutations: { retry: false },
    },
  });
}

interface RenderAppOptions extends Omit<RenderOptions, "wrapper"> {
  route?: string;
  queryClient?: QueryClient;
}

export function renderApp(ui: ReactElement, { route = "/", queryClient, ...options }: RenderAppOptions = {}) {
  const client = queryClient ?? makeTestQueryClient();
  function Wrapper({ children }: { children: ReactNode }) {
    return (
      <ThemeProvider>
        <QueryClientProvider client={client}>
          <MemoryRouter initialEntries={[route]}>{children}</MemoryRouter>
        </QueryClientProvider>
      </ThemeProvider>
    );
  }
  return { ...render(ui, { wrapper: Wrapper, ...options }), queryClient: client };
}

/** 通过真实 mock 登录流程建立会话（会设置 CSRF cookie） */
export async function loginAs(username: "owner" | "alice" | "bob", password?: string) {
  const passwords = { owner: "owner123", alice: "alice123", bob: "bob123" } as const;
  const session = await authApi.login({ username, password: password ?? passwords[username] });
  setCsrfToken(session.csrf_token);
  return session;
}

/** 每个用例前调用，隔离 mock 状态与 fake timers */
export function resetTestState() {
  resetMockRuntime();
  setCsrfToken("");
  vi.restoreAllMocks();
}
