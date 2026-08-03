import { createBrowserRouter, Navigate } from "react-router-dom";

import { AppShell } from "@/components/layout/app-shell";
import { AuditPage } from "@/features/audit/audit-page";
import { RequireAuth, RequireOwner } from "@/features/auth/guards";
import { LoginPage } from "@/features/auth/login-page";
import { ForwardsPage } from "@/features/forwards/forwards-page";
import { NodesPage } from "@/features/nodes/nodes-page";
import { OverviewPage } from "@/features/overview/overview-page";
import { SettingsPage } from "@/features/settings/settings-page";
import { TenantDetailPage } from "@/features/tenants/tenant-detail-page";
import { TenantsPage } from "@/features/tenants/tenants-page";
import { UsagePage } from "@/features/usage/usage-page";

export const router = createBrowserRouter([
  { path: "/login", element: <LoginPage /> },
  {
    element: (
      <RequireAuth>
        <AppShell />
      </RequireAuth>
    ),
    children: [
      { path: "/", element: <Navigate to="/overview" replace /> },
      { path: "/overview", element: <OverviewPage /> },
      { path: "/forwards", element: <ForwardsPage /> },
      {
        element: <RequireOwner />,
        children: [
          { path: "/nodes", element: <NodesPage /> },
          { path: "/tenants", element: <TenantsPage /> },
          { path: "/tenants/:id", element: <TenantDetailPage /> },
          { path: "/audit", element: <AuditPage /> },
          { path: "/settings", element: <SettingsPage /> },
        ],
      },
      { path: "/usage", element: <UsagePage /> },
    ],
  },
  { path: "*", element: <Navigate to="/overview" replace /> },
]);
