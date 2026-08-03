import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as authApi from "@/lib/api/auth";
import { ApiError, setCsrfToken } from "@/lib/api/client";

export const sessionKeys = {
  me: ["auth", "me"] as const,
};

/** 当前会话。401 视为未登录而不是错误；CSRF 随响应写入内存。 */
export function useMe() {
  return useQuery({
    queryKey: sessionKeys.me,
    queryFn: async () => {
      const data = await authApi.me();
      setCsrfToken(data.csrf_token);
      return data;
    },
    staleTime: 60_000,
    retry: (failureCount, error) => {
      if (error instanceof ApiError && error.status === 401) return false;
      return failureCount < 2;
    },
  });
}

export function useLogin() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: authApi.login,
    onSuccess: (data) => {
      setCsrfToken(data.csrf_token);
      qc.setQueryData(sessionKeys.me, data);
    },
  });
}

export function useLogout() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: authApi.logout,
    onSettled: () => {
      setCsrfToken("");
      qc.clear();
    },
  });
}
