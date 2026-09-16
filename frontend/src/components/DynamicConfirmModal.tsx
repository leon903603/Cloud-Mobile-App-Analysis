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
import { Cpu, Clock, Sparkles, ShieldAlert } from "lucide-react";

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
      <DialogContent className="sm:max-w-[520px]">
        <DialogHeader>
          <div className="flex items-center gap-2.5">
            <div className="flex h-10 w-10 items-center justify-center rounded-full bg-blue-500/10 text-blue-500">
              <Cpu className="h-5 w-5" />
            </div>
            <div>
              <DialogTitle className="text-lg font-semibold">
                Launch Dynamic Sandbox Analysis
              </DialogTitle>
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
              <span className="text-muted-foreground text-xs">Target Application:</span>
              <span className="font-mono text-xs font-semibold truncate max-w-[280px]" title={filename}>
                {filename}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-muted-foreground text-xs">Cost:</span>
              {creditSpent ? (
                <Badge variant="secondary" className="text-xs bg-emerald-500/15 text-emerald-600 dark:text-emerald-400">
                  Free Retry (Already Credited)
                </Badge>
              ) : (
                <Badge variant="default" className="text-xs bg-blue-600 hover:bg-blue-600">
                  1 Credit
                </Badge>
              )}
            </div>
            {hasCredentials && credentialUsername && (
              <div className="flex justify-between items-center">
                <span className="text-muted-foreground text-xs">Test Account:</span>
                <span className="text-xs font-mono text-muted-foreground">{credentialUsername}</span>
              </div>
            )}
          </div>

          {/* Time Estimate */}
          <div className="flex items-start gap-2.5 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-amber-700 dark:text-amber-400">
            <Clock className="h-4 w-4 mt-0.5 shrink-0" />
            <div className="space-y-0.5 text-xs">
              <p className="font-semibold">Estimated Duration: 8 ~ 10 Minutes</p>
              <p className="text-muted-foreground leading-relaxed">
                Includes dedicated ARM64 cloud sandbox cold boot (~1-2 min), system environment initialization, automated app launch, and deep Frida runtime behavior sampling.
              </p>
            </div>
          </div>

          {/* Offline Pickup Hint */}
          <div className="flex items-start gap-2.5 rounded-lg border border-blue-500/30 bg-blue-500/5 p-3 text-blue-700 dark:text-blue-400">
            <Sparkles className="h-4 w-4 mt-0.5 shrink-0" />
            <div className="space-y-0.5 text-xs">
              <p className="font-semibold">Offline Pickup Supported</p>
              <p className="text-muted-foreground leading-relaxed">
                The analysis executes autonomously in the cloud background and automatically powers off the instance when done. You can <b>safely close this window</b> and check progress or download your report anytime later.
              </p>
            </div>
          </div>

          {/* SMS OTP / 2FA Notice */}
          <div className="flex items-start gap-2.5 rounded-lg border border-border/80 bg-muted/40 p-3 text-muted-foreground">
            <ShieldAlert className="h-4 w-4 mt-0.5 shrink-0 text-amber-500" />
            <div className="space-y-0.5 text-xs">
              <p className="font-semibold text-foreground">SMS OTP / 2FA Login Notice</p>
              <p className="leading-relaxed">
                Automated sandboxes only inspect pre-login screens. If your application requires SMS OTP, 2FA, or biometric verification, automated login cannot bypass these controls. Please contact our team at <a href="mailto:nthu.islab.appsec@gmail.com" className="text-primary underline font-medium">nthu.islab.appsec@gmail.com</a> for dedicated Concierge Assisted Testing.
              </p>
            </div>
          </div>
        </div>

        <DialogFooter className="gap-2 sm:gap-0">
          <Button variant="outline" size="sm" onClick={onClose} disabled={isStarting}>
            Cancel
          </Button>
          <Button
            size="sm"
            className="bg-blue-600 hover:bg-blue-700 text-white"
            onClick={onConfirm}
            disabled={isStarting}
          >
            {isStarting ? "Starting..." : "Confirm & Start Analysis"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};
