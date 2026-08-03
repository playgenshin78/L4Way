import { Navigate, Outlet } from "react-router-dom";

import { OfflineBanner } from "@/components/shared/offline-banner";
import { useMe } from "@/features/auth/hooks";
import { SidebarBrand, SidebarNav } from "./sidebar";
import { Topbar } from "./topbar";

/**
 * 应用外壳：侧边导航（桌面）+ 顶栏 + 内容区。
 * 导航根据后端返回的角色裁剪（体验层）。
 */
export function AppShell() {
  const { data } = useMe();
  if (!data) return <Navigate to="/login" replace />;
  const account = data.account;

  return (
    <div className="min-h-screen">
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-60 flex-col border-r bg-card lg:flex">
        <SidebarBrand />
        <SidebarNav account={account} />
        <div className="mt-auto px-6 py-4">
          <p className="text-xs leading-5 text-muted-foreground">所有操作都会验证账号权限。</p>
        </div>
      </aside>

      <div className="flex min-h-screen flex-col lg:pl-60">
        <OfflineBanner />
        <Topbar account={account} />
        <main className="flex-1 px-4 py-6 sm:px-6 lg:px-8">
          <div className="mx-auto w-full max-w-6xl">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
