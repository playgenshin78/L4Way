import {
  ArrowLeftRight,
  BarChart3,
  LayoutDashboard,
  ScrollText,
  Server,
  Settings,
  Users,
  type LucideIcon,
} from "lucide-react";

import type { Role } from "@/lib/api/types";

export interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  roles: Role[];
}

export const navItems: NavItem[] = [
  { to: "/overview", label: "概览", icon: LayoutDashboard, roles: ["owner", "tenant"] },
  { to: "/forwards", label: "转发", icon: ArrowLeftRight, roles: ["owner", "tenant"] },
  { to: "/nodes", label: "节点", icon: Server, roles: ["owner"] },
  { to: "/tenants", label: "租户", icon: Users, roles: ["owner"] },
  { to: "/usage", label: "流量", icon: BarChart3, roles: ["owner", "tenant"] },
  { to: "/audit", label: "审计", icon: ScrollText, roles: ["owner"] },
  { to: "/settings", label: "设置", icon: Settings, roles: ["owner"] },
];

/** 根据后端返回的角色裁剪导航（纯体验层，后端仍是安全边界） */
export function navForRole(role: Role): NavItem[] {
  return navItems.filter((item) => item.roles.includes(role));
}

export const pageTitles: Record<string, string> = {
  "/overview": "概览",
  "/forwards": "转发",
  "/nodes": "节点",
  "/tenants": "租户",
  "/usage": "流量",
  "/audit": "审计",
  "/settings": "设置",
};
