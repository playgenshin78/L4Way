import { QueryClient, QueryClientProvider, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { Toaster } from "sonner";

import { ThemeProvider, useTheme } from "@/components/shared/theme-provider";
import { setCsrfToken, setUnauthorizedHandler } from "@/lib/api/client";
import { sessionKeys } from "@/features/auth/hooks";

export function makeQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: 1,
        refetchOnWindowFocus: false,
        staleTime: 15_000,
      },
    },
  });
}

function ThemedToaster() {
  const { resolvedTheme } = useTheme();
  return (
    <Toaster
      theme={resolvedTheme}
      position="bottom-right"
      toastOptions={{
        classNames: {
          toast: "!rounded-lg !border !bg-card !text-card-foreground !shadow-lift",
        },
      }}
    />
  );
}

/** 全局 401：清空会话缓存与内存 CSRF，由路由守卫跳转登录页 */
function UnauthorizedHandler() {
  const client = useQueryClient();
  useEffect(() => {
    setUnauthorizedHandler(() => {
      setCsrfToken("");
      client.setQueryData(sessionKeys.me, null);
    });
    return () => setUnauthorizedHandler(null);
  }, [client]);
  return null;
}

export function AppProviders({ children }: { children: React.ReactNode }) {
  return (
    <ThemeProvider>
      <QueryClientProvider client={makeQueryClient()}>
        <UnauthorizedHandler />
        {children}
      </QueryClientProvider>
      <ThemedToaster />
    </ThemeProvider>
  );
}
