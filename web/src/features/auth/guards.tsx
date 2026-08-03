import type { ReactNode } from "react";
import { Navigate, Outlet, useLocation } from "react-router-dom";

import { ForbiddenPage } from "@/components/shared/forbidden";
import { Skeleton } from "@/components/ui/skeleton";
import { useMe } from "./hooks";

function FullPageLoading() {
  return (
    <div className="flex min-h-screen flex-col gap-4 p-8" aria-busy="true" aria-label="加载中">
      <Skeleton className="h-10 w-48" />
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-24" />
        ))}
      </div>
      <Skeleton className="h-64" />
    </div>
  );
}

/**
 * 登录守卫：仅改善体验。真正的权限校验永远在后端。
 */
export function RequireAuth({ children }: { children?: ReactNode }) {
  const { data, isPending, isError } = useMe();
  const location = useLocation();

  if (isPending) return <FullPageLoading />;
  if (isError || !data) {
    return <Navigate to="/login" state={{ from: location.pathname }} replace />;
  }
  return children ? <>{children}</> : <Outlet />;
}

/**
 * Owner 角色守卫：tenant 访问 owner 页面时展示 403。
 */
export function RequireOwner({ children }: { children?: ReactNode }) {
  const { data, isPending } = useMe();
  if (isPending) return <FullPageLoading />;
  if (data?.account.role !== "owner") return <ForbiddenPage />;
  return children ? <>{children}</> : <Outlet />;
}
