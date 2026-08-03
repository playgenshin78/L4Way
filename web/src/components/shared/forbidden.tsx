import { ShieldX } from "lucide-react";
import { Link } from "react-router-dom";

import { Button } from "@/components/ui/button";

/**
 * 403 页面：前端路由守卫仅用于体验，真正的权限边界在后端。
 */
export function ForbiddenPage() {
  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center gap-3 px-6 text-center">
      <div className="rounded-full bg-destructive/10 p-4">
        <ShieldX className="h-6 w-6 text-destructive" aria-hidden />
      </div>
      <h1 className="text-lg font-semibold">没有访问权限</h1>
      <p className="max-w-sm text-sm text-muted-foreground">
        当前账号无权查看此页面。如需访问，请联系管理员调整权限。
      </p>
      <Button asChild variant="outline" className="mt-2">
        <Link to="/overview">返回概览</Link>
      </Button>
    </div>
  );
}
