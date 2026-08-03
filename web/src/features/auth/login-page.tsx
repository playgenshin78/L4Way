import { zodResolver } from "@hookform/resolvers/zod";
import { Waypoints } from "lucide-react";
import { useEffect, useRef } from "react";
import { useForm } from "react-hook-form";
import { useLocation, useNavigate } from "react-router-dom";
import { z } from "zod";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { ApiError } from "@/lib/api/client";
import { useLogin, useMe } from "./hooks";

const loginSchema = z.object({
  username: z.string().min(1, "请输入用户名"),
  password: z.string().min(1, "请输入密码"),
});

type LoginValues = z.infer<typeof loginSchema>;

/** 按账号角色决定落地页 */
export function homeForRole(role: "owner" | "tenant"): string {
  return role === "owner" ? "/overview" : "/forwards";
}

export function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const { data } = useMe();
  const login = useLogin();
  const errorRef = useRef<HTMLParagraphElement>(null);

  const from = (location.state as { from?: string } | null)?.from;

  const form = useForm<LoginValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: { username: "", password: "" },
  });

  useEffect(() => {
    if (data?.account) navigate(from ?? homeForRole(data.account.role), { replace: true });
  }, [data, navigate, from]);

  useEffect(() => {
    if (login.isError) errorRef.current?.focus();
  }, [login.isError]);

  async function onSubmit(values: LoginValues) {
    try {
      const res = await login.mutateAsync(values);
      navigate(from ?? homeForRole(res.account.role), { replace: true });
    } catch {
      /* 错误在下方展示 */
    }
  }

  const errorMessage =
    login.error instanceof ApiError
      ? login.error.message
      : login.isError
        ? "服务不可用，请稍后重试"
        : null;

  return (
    <div className="flex min-h-screen items-center justify-center px-4 py-10">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center gap-2 text-center">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary text-primary-foreground">
            <Waypoints className="h-5 w-5" aria-hidden />
          </div>
          <h1 className="text-xl font-semibold leading-8">登录 Flux 控制台</h1>
          <p className="text-sm leading-6 text-muted-foreground">自托管 TCP/UDP 四层转发平台</p>
        </div>

        <Card>
          <CardHeader className="pb-4">
            <CardTitle className="text-base">账号登录</CardTitle>
            <CardDescription>使用管理员分配的账号登录</CardDescription>
          </CardHeader>
          <CardContent>
            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4" noValidate>
                {errorMessage ? (
                  <p
                    ref={errorRef}
                    tabIndex={-1}
                    role="alert"
                    className="rounded-lg border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm text-destructive focus-visible:outline-none"
                  >
                    {errorMessage}
                  </p>
                ) : null}

                <FormField
                  control={form.control}
                  name="username"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>用户名</FormLabel>
                      <FormControl>
                        <Input autoComplete="username" autoFocus placeholder="owner 或 alice" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="password"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>密码</FormLabel>
                      <FormControl>
                        <Input type="password" autoComplete="current-password" placeholder="••••••••" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <Button type="submit" className="w-full" disabled={login.isPending}>
                  {login.isPending ? "登录中…" : "登录"}
                </Button>
              </form>
            </Form>
          </CardContent>
        </Card>

        <p className="mt-4 text-center text-xs leading-5 text-muted-foreground">
          登录状态会被安全保存，多次输错密码将暂时限制登录。
        </p>
      </div>
    </div>
  );
}
