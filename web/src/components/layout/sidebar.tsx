import { Waypoints } from "lucide-react";
import { NavLink } from "react-router-dom";

import { cn } from "@/lib/utils";
import type { Account } from "@/lib/api/types";
import { navForRole } from "./nav-config";

export function SidebarNav({ account, onNavigate }: { account: Account; onNavigate?: () => void }) {
  const items = navForRole(account.role);
  return (
    <nav aria-label="主导航" className="flex flex-col gap-0.5 px-3">
      {items.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          onClick={onNavigate}
          className={({ isActive }) =>
            cn(
              "flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium text-muted-foreground transition-colors duration-200 hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
              isActive && "bg-accent text-foreground",
            )
          }
        >
          <item.icon className="h-4 w-4" aria-hidden />
          {item.label}
        </NavLink>
      ))}
    </nav>
  );
}

export function SidebarBrand() {
  return (
    <div className="flex items-center gap-2.5 px-6 py-5">
      <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-primary text-primary-foreground">
        <Waypoints className="h-4 w-4" aria-hidden />
      </div>
      <div className="leading-tight">
        <p className="text-sm font-semibold leading-5">Flux</p>
        <p className="text-xs leading-5 text-muted-foreground">四层转发控制台</p>
      </div>
    </div>
  );
}
