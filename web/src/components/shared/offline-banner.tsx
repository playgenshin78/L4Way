import { WifiOff } from "lucide-react";

import { useOnline } from "@/lib/hooks/use-online";

export function OfflineBanner() {
  const online = useOnline();
  if (online) return null;
  return (
    <div
      role="status"
      className="flex items-center justify-center gap-2 bg-warning px-4 py-1.5 text-xs font-medium text-warning-foreground"
    >
      <WifiOff className="h-3.5 w-3.5" aria-hidden />
      网络已断开。数据可能不是最新，写操作暂不可用。
    </div>
  );
}
