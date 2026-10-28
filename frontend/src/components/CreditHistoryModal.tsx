import React, { useState, useEffect, useCallback } from "react";
import type { User } from "firebase/auth";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Receipt,
  ArrowDownLeft,
  ArrowUpRight,
  ExternalLink,
  Copy,
  Check,
  Loader2,
  AlertCircle,
  FileCode,
  ShieldCheck,
  Building,
  RefreshCw,
} from "lucide-react";

export interface CreditAddition {
  id: number;
  createdAt: string;
  delta: number;
  reason: "purchase" | "signup" | "refund" | "admin_adjust" | "reconcile_correction" | string;
  note?: string;
  orderNo?: string;
  amt?: number;
  usdAmt?: number;
  tradeNo?: string;
  buyerName?: string | null;
  receiptIssuedAt?: string | null;
  receiptUrl?: string | null;
}

export interface CreditDeduction {
  id: number;
  createdAt: string;
  delta: number;
  reason: "consume" | "admin_adjust" | string;
  ref: string;
  fileId?: number | null;
  filename?: string | null;
  analysisType?: string | null;
  note?: string;
}

export interface CreditHistoryResponse {
  balance: number;
  additions: CreditAddition[];
  deductions: CreditDeduction[];
}

interface Props {
  user: User;
  isOpen: boolean;
  onClose: () => void;
  onBalanceUpdated?: () => void;
}

export const CreditHistoryModal: React.FC<Props> = ({
  user,
  isOpen,
  onClose,
  onBalanceUpdated,
}) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<CreditHistoryResponse | null>(null);

  // Claim receipt state
  const [activeClaimOrder, setActiveClaimOrder] = useState<CreditAddition | null>(null);
  const [companyName, setCompanyName] = useState<string>("");
  const [claimLoading, setClaimLoading] = useState<boolean>(false);
  const [claimError, setClaimError] = useState<string | null>(null);

  // Copied feedback state (keyed by orderNo)
  const [copiedOrderNo, setCopiedOrderNo] = useState<string | null>(null);

  const fetchHistory = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const token = await user.getIdToken();
      const res = await fetch(
        `${import.meta.env.VITE_BACKEND_URL}/api/member/credits/history`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error || `HTTP ${res.status}: Failed to load credit history`);
      }

      const json: CreditHistoryResponse = await res.json();
      setData(json);
    } catch (err: any) {
      console.error("Failed to load credit history:", err);
      setError(err.message || "Failed to load credit history");
    } finally {
      setLoading(false);
    }
  }, [user]);

  useEffect(() => {
    if (isOpen) {
      fetchHistory();
      setActiveClaimOrder(null);
      setClaimError(null);
      setCompanyName("");
    }
  }, [isOpen, fetchHistory]);

  const handleCopyLink = async (orderNo: string, url: string) => {
    try {
      await navigator.clipboard.writeText(url);
      setCopiedOrderNo(orderNo);
      setTimeout(() => setCopiedOrderNo(null), 2500);
    } catch (err) {
      console.error("Failed to copy link to clipboard", err);
    }
  };

  const handleClaimSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeClaimOrder?.orderNo) return;

    const trimmed = companyName.trim();
    if (trimmed.length < 2 || trimmed.length > 120) {
      setClaimError("Company or institution name must be between 2 and 120 characters.");
      return;
    }

    setClaimLoading(true);
    setClaimError(null);

    try {
      const token = await user.getIdToken();
      const res = await fetch(
        `${import.meta.env.VITE_BACKEND_URL}/api/orders/${activeClaimOrder.orderNo}/receipt/claim`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ companyName: trimmed }),
        }
      );

      const resData = await res.json().catch(() => ({}));

      if (!res.ok) {
        if (res.status === 409) {
          throw new Error("An official receipt has already been issued for this order.");
        }
        throw new Error(resData.error || `Failed to claim receipt (HTTP ${res.status})`);
      }

      // Optimistically update the additions entry in state
      if (data) {
        setData({
          ...data,
          additions: data.additions.map((item) =>
            item.orderNo === activeClaimOrder.orderNo
              ? {
                  ...item,
                  buyerName: resData.buyerName,
                  receiptIssuedAt: resData.receiptIssuedAt,
                  receiptUrl: resData.receiptUrl,
                }
              : item
          ),
        });
      }

      const claimedUrl = resData.receiptUrl;
      setActiveClaimOrder(null);
      setCompanyName("");
      onBalanceUpdated?.();

      // Open the newly generated receipt in a new tab
      if (claimedUrl) {
        window.open(claimedUrl, "_blank", "noopener,noreferrer");
      }
    } catch (err: any) {
      setClaimError(err.message || "Failed to generate receipt");
    } finally {
      setClaimLoading(false);
    }
  };

  const formatTimestamp = (isoStr: string) => {
    try {
      const d = new Date(isoStr);
      if (isNaN(d.getTime())) return isoStr;
      return d.toLocaleString(undefined, {
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
      });
    } catch {
      return isoStr;
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-4xl w-[95vw] max-h-[88vh] flex flex-col p-6 overflow-hidden bg-card text-card-foreground border-border shadow-2xl">
        <DialogHeader className="flex flex-row items-center justify-between border-b border-border pb-4 pr-6">
          <div>
            <DialogTitle className="text-xl font-bold flex items-center gap-2">
              <Receipt className="w-5 h-5 text-emerald-400" />
              Member Credit Journal &amp; Official Receipts
            </DialogTitle>
            <DialogDescription className="text-xs text-muted-foreground mt-1 flex items-center gap-2">
              <span>Account: <strong>{user.email}</strong></span>
              <span>•</span>
              <span>Auditable Double-Entry Ledger</span>
            </DialogDescription>
          </div>

          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30">
              <span className="text-xs text-muted-foreground">Available:</span>
              <span className="text-sm font-bold text-emerald-400">
                {data !== null ? `${data.balance} Credits` : "..."}
              </span>
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={fetchHistory}
              disabled={loading}
              className="h-8 w-8 p-0"
              title="Refresh journal"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
            </Button>
          </div>
        </DialogHeader>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto py-4 pr-1 space-y-4">
          {error && (
            <div className="p-3 rounded-lg bg-destructive/15 border border-destructive/30 text-destructive text-sm flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {loading && !data && (
            <div className="py-16 flex flex-col items-center justify-center gap-2 text-muted-foreground">
              <Loader2 className="w-6 h-6 animate-spin text-emerald-400" />
              <p className="text-sm">Loading auditable credit ledger...</p>
            </div>
          )}

          {/* Inline Receipt Claim Dialog Overlay/Card */}
          {activeClaimOrder && (
            <div className="rounded-xl border border-emerald-500/40 bg-emerald-950/20 dark:bg-emerald-950/40 p-5 shadow-lg space-y-4 animate-in fade-in-50 zoom-in-95">
              <div className="flex items-start justify-between">
                <div>
                  <h3 className="font-semibold text-foreground flex items-center gap-2">
                    <Building className="w-4 h-4 text-emerald-400" />
                    Issue Official Reimbursement Receipt
                  </h3>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Order Reference: <strong className="text-foreground">{activeClaimOrder.orderNo}</strong> •{" "}
                    Amount: <strong className="text-foreground">NT$ {activeClaimOrder.amt}</strong>
                  </p>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    setActiveClaimOrder(null);
                    setClaimError(null);
                  }}
                  className="h-7 text-xs"
                >
                  Cancel
                </Button>
              </div>

              <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-xs text-amber-300 flex items-start gap-2">
                <AlertCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <p className="font-semibold">Irrevocable Legal &amp; Fiscal Compliance Guard:</p>
                  <p className="text-amber-300/90 leading-relaxed">
                    Once generated, the company/institution name is permanently locked to this receipt and cannot be edited or reissued. Please ensure legal entity accuracy for corporate accounting and tax reimbursement.
                  </p>
                </div>
              </div>

              <form onSubmit={handleClaimSubmit} className="space-y-3">
                <div className="space-y-1">
                  <label className="text-xs font-medium text-foreground flex justify-between">
                    <span>Company / Institution Name (公司抬頭 / 組織名稱):</span>
                    <span className="text-[11px] text-muted-foreground">{companyName.trim().length} / 120</span>
                  </label>
                  <Input
                    type="text"
                    required
                    placeholder="e.g. Acme Corporation Taiwan Ltd. or National Taiwan University"
                    value={companyName}
                    onChange={(e) => setCompanyName(e.target.value)}
                    maxLength={120}
                    className="h-9 text-sm bg-background"
                    autoFocus
                  />
                </div>

                {claimError && (
                  <p className="text-xs text-destructive font-medium flex items-center gap-1.5">
                    <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                    {claimError}
                  </p>
                )}

                <div className="flex justify-end gap-2 pt-1">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      setActiveClaimOrder(null);
                      setClaimError(null);
                    }}
                    disabled={claimLoading}
                  >
                    Cancel
                  </Button>
                  <Button
                    type="submit"
                    size="sm"
                    disabled={claimLoading || companyName.trim().length < 2 || companyName.trim().length > 120}
                    className="bg-emerald-600 hover:bg-emerald-500 text-white font-medium"
                  >
                    {claimLoading ? (
                      <>
                        <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />
                        Generating Receipt...
                      </>
                    ) : (
                      <>
                        <ShieldCheck className="w-3.5 h-3.5 mr-1.5" />
                        Generate Official Receipt
                      </>
                    )}
                  </Button>
                </div>
              </form>
            </div>
          )}

          {data && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              {/* ── Left Column: Credits Added ───────────────────────────────── */}
              <div className="flex flex-col rounded-xl border border-border bg-card/60 p-4 space-y-3">
                <div className="flex items-center justify-between border-b border-border pb-2.5">
                  <div className="flex items-center gap-2">
                    <div className="p-1 rounded-md bg-emerald-500/10 text-emerald-400">
                      <ArrowDownLeft className="w-4 h-4" />
                    </div>
                    <h3 className="text-sm font-semibold text-foreground">
                      Credits Added (Purchases &amp; Grants)
                    </h3>
                  </div>
                  <Badge variant="outline" className="text-[11px] font-normal border-emerald-500/30 text-emerald-400">
                    {data.additions.length} records
                  </Badge>
                </div>

                <div className="space-y-2.5 max-h-[50vh] overflow-y-auto pr-1">
                  {data.additions.length === 0 ? (
                    <p className="text-xs text-muted-foreground py-8 text-center italic">
                      No credit additions recorded yet.
                    </p>
                  ) : (
                    data.additions.map((item) => {
                      const isPurchase = item.reason === "purchase";
                      const isClaimed = Boolean(item.receiptIssuedAt && item.receiptUrl);

                      return (
                        <div
                          key={`addition-${item.id}`}
                          className="rounded-lg border border-border/70 bg-background/50 p-3 space-y-2 text-xs transition-colors hover:border-border"
                        >
                          <div className="flex items-start justify-between gap-2">
                            <div>
                              <div className="flex items-center gap-1.5 flex-wrap">
                                <span className="font-semibold text-foreground">
                                  {isPurchase
                                    ? `Credit Purchase`
                                    : item.reason === "signup"
                                    ? "Registration Bonus"
                                    : item.reason === "refund"
                                    ? "Analysis Failure Refund"
                                    : item.reason === "admin_adjust"
                                    ? "Administrative Grant"
                                    : item.reason}
                                </span>
                                {isPurchase && item.amt && (
                                  <span className="text-[11px] text-muted-foreground">
                                    (NT$ {item.amt}
                                    {item.usdAmt ? ` / $${item.usdAmt} USD` : ""})
                                  </span>
                                )}
                              </div>
                              <p className="text-[11px] text-muted-foreground mt-0.5">
                                {formatTimestamp(item.createdAt)}
                              </p>
                            </div>

                            <span className="font-bold text-emerald-400 text-xs px-2 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 shrink-0">
                              +{item.delta}
                            </span>
                          </div>

                          {/* Order & Note specifics */}
                          {item.orderNo && (
                            <p className="text-[11px] text-muted-foreground font-mono">
                              Order: {item.orderNo}
                            </p>
                          )}
                          {item.note && !isPurchase && (
                            <p className="text-[11px] text-muted-foreground italic">
                              {item.note}
                            </p>
                          )}

                          {/* Official Receipt Action Area for Purchases */}
                          {isPurchase && (
                            <div className="pt-2 border-t border-border/50 flex flex-col gap-1.5">
                              {isClaimed ? (
                                <div className="space-y-1.5 bg-card/80 p-2 rounded-md border border-border/60">
                                  <div className="flex items-center justify-between flex-wrap gap-1">
                                    <span className="text-[11px] text-emerald-400 font-medium flex items-center gap-1">
                                      <ShieldCheck className="w-3 h-3" />
                                      Official Receipt Issued
                                    </span>
                                    {item.receiptIssuedAt && (
                                      <span className="text-[10px] text-muted-foreground">
                                        {formatTimestamp(item.receiptIssuedAt)}
                                      </span>
                                    )}
                                  </div>

                                  {item.buyerName && (
                                    <p className="text-[11px] text-foreground font-medium truncate">
                                      Issued to: <span className="font-semibold">{item.buyerName}</span>
                                    </p>
                                  )}

                                  <div className="flex items-center gap-1.5 pt-0.5">
                                    <a
                                      href={item.receiptUrl!}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded bg-primary/10 text-primary hover:bg-primary/20 transition-colors font-medium"
                                    >
                                      <span>View Official Receipt</span>
                                      <ExternalLink className="w-3 h-3" />
                                    </a>

                                    <Button
                                      variant="ghost"
                                      size="sm"
                                      onClick={() => handleCopyLink(item.orderNo!, item.receiptUrl!)}
                                      className="h-6 px-2 text-[11px] text-muted-foreground hover:text-foreground"
                                      title="Copy receipt link"
                                    >
                                      {copiedOrderNo === item.orderNo ? (
                                        <>
                                          <Check className="w-3 h-3 text-emerald-400 mr-1" />
                                          <span className="text-emerald-400">Copied</span>
                                        </>
                                      ) : (
                                        <>
                                          <Copy className="w-3 h-3 mr-1" />
                                          <span>Copy Link</span>
                                        </>
                                      )}
                                    </Button>
                                  </div>
                                </div>
                              ) : (
                                <div className="flex items-center justify-between pt-1">
                                  <span className="text-[11px] text-muted-foreground">
                                    Official tax receipt available
                                  </span>
                                  <Button
                                    size="sm"
                                    variant="outline"
                                    onClick={() => {
                                      setActiveClaimOrder(item);
                                      setCompanyName("");
                                      setClaimError(null);
                                    }}
                                    className="h-7 text-xs border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/10 hover:border-emerald-500/60"
                                  >
                                    <Building className="w-3 h-3 mr-1" />
                                    Request Official Receipt
                                  </Button>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })
                  )}
                </div>
              </div>

              {/* ── Right Column: Credits Deducted ──────────────────────────────── */}
              <div className="flex flex-col rounded-xl border border-border bg-card/60 p-4 space-y-3">
                <div className="flex items-center justify-between border-b border-border pb-2.5">
                  <div className="flex items-center gap-2">
                    <div className="p-1 rounded-md bg-rose-500/10 text-rose-400">
                      <ArrowUpRight className="w-4 h-4" />
                    </div>
                    <h3 className="text-sm font-semibold text-foreground">
                      Credits Deducted (Analysis Usage)
                    </h3>
                  </div>
                  <Badge variant="outline" className="text-[11px] font-normal border-rose-500/30 text-rose-400">
                    {data.deductions.length} records
                  </Badge>
                </div>

                <div className="space-y-2.5 max-h-[50vh] overflow-y-auto pr-1">
                  {data.deductions.length === 0 ? (
                    <p className="text-xs text-muted-foreground py-8 text-center italic">
                      No credit deductions recorded yet.
                    </p>
                  ) : (
                    data.deductions.map((item) => (
                      <div
                        key={`deduction-${item.id}`}
                        className="rounded-lg border border-border/70 bg-background/50 p-3 space-y-1.5 text-xs transition-colors hover:border-border"
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="space-y-0.5">
                            <div className="flex items-center gap-1.5 flex-wrap">
                              <span className="font-semibold text-foreground">
                                {item.reason === "consume"
                                  ? "App Security Analysis"
                                  : item.reason === "admin_adjust"
                                  ? "Administrative Deduction"
                                  : item.reason}
                              </span>
                              {item.analysisType && (
                                <Badge
                                  variant="secondary"
                                  className="text-[10px] uppercase tracking-wider px-1.5 py-0 font-medium"
                                >
                                  {item.analysisType}
                                </Badge>
                              )}
                            </div>
                            <p className="text-[11px] text-muted-foreground">
                              {formatTimestamp(item.createdAt)}
                            </p>
                          </div>

                          <span className="font-bold text-rose-400 text-xs px-2 py-0.5 rounded-full bg-rose-500/10 border border-rose-500/30 shrink-0">
                            {item.delta}
                          </span>
                        </div>

                        {/* File Details */}
                        {item.filename ? (
                          <div className="flex items-center gap-1.5 text-[11px] text-foreground/90 font-mono bg-card/60 px-2 py-1 rounded border border-border/40 truncate">
                            <FileCode className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                            <span className="truncate">{item.filename}</span>
                          </div>
                        ) : item.note ? (
                          <p className="text-[11px] text-muted-foreground italic">
                            {item.note}
                          </p>
                        ) : (
                          <p className="text-[11px] text-muted-foreground font-mono">
                            Ref: {item.ref}
                          </p>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="pt-3 border-t border-border flex justify-between items-center text-xs text-muted-foreground">
          <span>Official receipts comply with corporate financial reimbursement standards.</span>
          <Button variant="outline" size="sm" onClick={onClose} className="h-8">
            Close
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default CreditHistoryModal;
