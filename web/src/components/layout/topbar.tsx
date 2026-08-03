import { LogOut, Menu, Moon, Sun, UserRound } from "lucide-react";
import { useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Sheet, SheetContent, SheetTitle } from "@/components/ui/sheet";
import { Badge } from "@/components/ui/badge";
import { useTheme } from "@/components/shared/theme-provider";
import { useLogout } from "@/features/auth/hooks";
import type { Account } from "@/lib/api/types";
import { pageTitles } from "./nav-config";
import { SidebarBrand, SidebarNav } from "./sidebar";

export function Topbar({ account }: { account: Account }) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();
  const { theme, setTheme, resolvedTheme } = useTheme();
  const logout = useLogout();

  const title =
    Object.entries(pageTitles).find(([path]) => location.pathname.startsWith(path))?.[1] ?? "控制台";

  async function handleLogout() {
    try {
      await logout.mutateAsync();
    } finally {
      navigate("/login", { replace: true });
    }
  }

  return (
    <header className="sticky top-0 z-40 border-b bg-background/80 backdrop-blur-sm">
      <div className="flex h-14 items-center gap-2 px-4 sm:px-6">
        <Button
          variant="ghost"
          size="icon"
          className="lg:hidden"
          onClick={() => setMobileOpen(true)}
          aria-label="打开导航菜单"
        >
          <Menu aria-hidden />
        </Button>
        <h2 className="text-sm font-semibold">{title}</h2>

        <div className="ml-auto flex items-center gap-1">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" aria-label="切换主题">
                {resolvedTheme === "dark" ? <Moon aria-hidden /> : <Sun aria-hidden />}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>主题</DropdownMenuLabel>
              <DropdownMenuRadioGroup value={theme} onValueChange={(v) => setTheme(v as "light" | "dark" | "system")}>
                <DropdownMenuRadioItem value="light">浅色</DropdownMenuRadioItem>
                <DropdownMenuRadioItem value="dark">深色</DropdownMenuRadioItem>
                <DropdownMenuRadioItem value="system">跟随系统</DropdownMenuRadioItem>
              </DropdownMenuRadioGroup>
            </DropdownMenuContent>
          </DropdownMenu>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" className="gap-2 px-2" aria-label="账号菜单">
                <span className="flex h-7 w-7 items-center justify-center rounded-full bg-secondary">
                  <UserRound className="h-4 w-4" aria-hidden />
                </span>
                <span className="hidden max-w-[10rem] truncate text-sm sm:inline">{account.display_name}</span>
                <Badge variant={account.role === "owner" ? "default" : "secondary"} className="hidden sm:inline-flex">
                  {account.role === "owner" ? "管理员" : "租户"}
                </Badge>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56">
              <DropdownMenuLabel>
                <div className="flex flex-col">
                  <span>{account.display_name}</span>
                  <span className="text-xs font-normal text-muted-foreground">@{account.username}</span>
                </div>
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={handleLogout} disabled={logout.isPending}>
                <LogOut aria-hidden />
                退出登录
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
        <SheetContent side="left" className="w-64 p-0" aria-label="导航菜单">
          <SheetTitle className="sr-only">导航菜单</SheetTitle>
          <SidebarBrand />
          <SidebarNav account={account} onNavigate={() => setMobileOpen(false)} />
        </SheetContent>
      </Sheet>
    </header>
  );
}
