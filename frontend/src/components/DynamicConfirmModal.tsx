import React from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Cpu, Clock, Sparkles } from "lucide-react";

interface DynamicConfirmModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  filename: string;
  creditSpent?: boolean;
  hasCredentials?: boolean;
  credentialUsername?: string | null;
  isStarting?: boolean;
}

export const DynamicConfirmModal: React.FC<DynamicConfirmModalProps> = ({
  isOpen,
  onClose,
  onConfirm,
  filename,
  creditSpent,
  hasCredentials,
  credentialUsername,
  isStarting,
}) => {
  return (
    <Dialog open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <div className="flex items-center gap-2">
            <div className="flex h-10 w-10 items-center justify-center rounded-full bg-blue-500/10 text-blue-500">
              <Cpu className="h-5 w-5" />
            </div>
            <div>
              <DialogTitle className="text-lg">啟動雲端動態沙箱分析</DialogTitle>
              <DialogDescription className="text-xs text-muted-foreground mt-0.5">
                Cloud-Native ARM64 Dynamic Execution & Frida Runtime Sampling
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <div className="space-y-3 py-2 text-sm">
          {/* Target File & Cost Info */}
          <div className="rounded-lg border border-border/60 bg-muted/30 p-3 space-y-1.5">
            <div className="flex justify-between items-center">
              <span className="text-muted-foreground text-xs">目標應用程式:</span>
              <span className="font-mono text-xs font-semibold truncate max-w-[280px]" title={filename}>
                {filename}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-muted-foreground text-xs">點數扣抵:</span>
              {creditSpent ? (
                <Badge variant="secondary" className="text-xs bg-emerald-500/15 text-emerald-600 dark:text-emerald-400">
                  免費重測 (已扣點)
                </Badge>
              ) : (
                <Badge variant="default" className="text-xs bg-blue-600 hover:bg-blue-600">
                  扣除 1 點額度
                </Badge>
              )}
            </div>
            {hasCredentials && credentialUsername && (
              <div className="flex justify-between items-center">
                <span className="text-muted-foreground text-xs">測試登入帳號:</span>
                <span className="text-xs font-mono text-muted-foreground">{credentialUsername}</span>
              </div>
            )}
          </div>

          {/* Time Estimate */}
          <div className="flex items-start gap-2.5 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-amber-700 dark:text-amber-400">
            <Clock className="h-4 w-4 mt-0.5 shrink-0" />
            <div className="space-y-0.5 text-xs">
              <p className="font-semibold">預估檢測耗時 8 ~ 10 分鐘</p>
              <p className="text-muted-foreground leading-relaxed">
                包含雲端專屬 ARM64 沙箱冷開機 (約 1~2 分鐘)、系統環境初始化、自動安裝啟動與 Frida 執行期行為深度採樣。
              </p>
            </div>
          </div>

          {/* Offline Pickup Hint */}
          <div className="flex items-start gap-2.5 rounded-lg border border-blue-500/30 bg-blue-500/5 p-3 text-blue-700 dark:text-blue-400">
            <Sparkles className="h-4 w-4 mt-0.5 shrink-0" />
            <div className="space-y-0.5 text-xs">
              <p className="font-semibold">支援全自動離線取件</p>
              <p className="text-muted-foreground leading-relaxed">
                分析將於 AWS 雲端背景全自動執行並於完成後自動關機。您可以<b>安心關閉此視窗</b>，稍後返回此頁面即可隨時查看進度或下載報告！
              </p>
            </div>
          </div>
        </div>

        <DialogFooter className="gap-2 sm:gap-0">
          <Button variant="outline" size="sm" onClick={onClose} disabled={isStarting}>
            取消
          </Button>
          <Button
            size="sm"
            className="bg-blue-600 hover:bg-blue-700 text-white"
            onClick={onConfirm}
            disabled={isStarting}
          >
            {isStarting ? "啟動中..." : "確認並開始檢測"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};
