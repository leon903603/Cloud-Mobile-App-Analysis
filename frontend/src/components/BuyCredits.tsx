// src/components/BuyCredits.tsx
import * as React from "react";
import { auth } from "../firebase/config";
import { Button } from "./ui/button";

interface CreditPackage {
  id: string;
  credits: number;
  usd: number; // list price — fixed, and the same everywhere on the site
  twd?: number; // what NewebPay actually charges, at today's rate
  label?: string;
  popular?: boolean;
}

// 1 credit = 1 analysis run = US$40, matching the /product page. Static and
// dynamic analysis of the same file are two runs, and so two credits.
// Package ids must stay in sync with VALID_PACKAGES in server/newebpay.ts.
//
// Prices are denominated in USD; NewebPay can only charge TWD, so the NT$ figure
// is derived from a live rate and comes from GET /api/newebpay/pricing. These
// are the USD fallbacks used until that request lands (or if it fails) — the
// server is authoritative for the TWD actually charged.
const USD_PER_CREDIT = 40;
const CREDIT_PACKAGES: CreditPackage[] = [
  { id: "starter", credits: 1, usd: 1 * USD_PER_CREDIT, label: "Starter" },
  { id: "pro", credits: 5, usd: 5 * USD_PER_CREDIT, label: "Pro", popular: true },
  { id: "power", credits: 10, usd: 10 * USD_PER_CREDIT, label: "Power" },
  { id: "enterprise", credits: 25, usd: 25 * USD_PER_CREDIT, label: "Enterprise" },
];

interface BuyCreditsProps {
  currentCredits?: number;
  onBack?: () => void;
}

const BuyCredits: React.FC<BuyCreditsProps> = ({ currentCredits = 0, onBack }) => {
  const [selected, setSelected] = React.useState<string>("pro");
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const [success, setSuccess] = React.useState("");
  const [packages, setPackages] = React.useState<CreditPackage[]>(CREDIT_PACKAGES);
  const [rate, setRate] = React.useState<number | null>(null);

  // Pull the TWD figures the server will actually charge. Purely additive: if
  // this fails the USD prices above still render, and the server recomputes the
  // amount at checkout regardless of what was displayed here.
  React.useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch(
          `${import.meta.env.VITE_BACKEND_URL}/api/newebpay/pricing`
        );
        if (!res.ok) return;
        const data = await res.json();
        if (cancelled || !Array.isArray(data.packages)) return;
        setRate(data.rate ?? null);
        setPackages((prev) =>
          prev.map((p) => {
            const live = data.packages.find((q: CreditPackage) => q.id === p.id);
            return live ? { ...p, usd: live.usd, twd: live.twd } : p;
          })
        );
      } catch {
        /* keep the USD-only view */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const formatUsd = (usd: number) => `US$${usd.toLocaleString()}`;
  const formatTwd = (twd?: number) =>
    twd == null ? null : `NT$${twd.toLocaleString()}`;

  const handlePurchase = async () => {
    const pkg = CREDIT_PACKAGES.find((p) => p.id === selected);
    if (!pkg) return;

    setLoading(true);
    setError("");
    setSuccess("");

    try {
      const token = await auth.currentUser?.getIdToken();
      if (!token) throw new Error("You must be logged in to purchase credits.");

      // Get signed MPG form fields from the backend
      const response = await fetch(
        `${import.meta.env.VITE_BACKEND_URL}/api/newebpay/checkout`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ packageId: pkg.id }),
        }
      );

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.error ?? "Failed to create checkout session.");
      }

      const data = await response.json();

      if (data.simulated) {
        setSuccess(`Payment simulated successfully! Added ${pkg.credits} credit${pkg.credits > 1 ? "s" : ""} to your account.`);
        setLoading(false);
        setTimeout(() => {
          onBack?.();
          window.location.reload();
        }, 1200);
        return;
      }

      const { gateway, merchantID, tradeInfo, tradeSha, version } = data;

      // NewebPay requires a foreground HTML form post to the MPG payment page
      // (iframe/background posts are rejected with MPG02005).
      const form = document.createElement("form");
      form.method = "POST";
      form.action = gateway;
      const fields: Record<string, string> = {
        MerchantID: merchantID,
        TradeInfo: tradeInfo,
        TradeSha: tradeSha,
        Version: version,
      };
      for (const [name, value] of Object.entries(fields)) {
        const input = document.createElement("input");
        input.type = "hidden";
        input.name = name;
        input.value = value;
        form.appendChild(input);
      }
      document.body.appendChild(form);
      form.submit();
    } catch (err: any) {
      setError(err.message ?? "Something went wrong. Please try again.");
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col w-full space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        {onBack && (
          <button
            onClick={onBack}
            className="text-gray-400 hover:text-white text-sm flex items-center gap-1 transition-colors"
          >
            ← Back
          </button>
        )}
        <h2 className="text-white text-xl font-semibold flex-1 text-center">
          Buy Credits
        </h2>
        {onBack && <div className="w-12" />}
      </div>

      {/* Current balance */}
      <div className="bg-white/5 border border-white/10 rounded-lg px-4 py-3 flex justify-between items-center">
        <span className="text-gray-400 text-sm">Current balance</span>
        <span className="text-white font-semibold">
          {currentCredits.toLocaleString()} credits
        </span>
      </div>

      {/* Package grid */}
      <div className="grid grid-cols-2 gap-3">
        {packages.map((pkg) => {
          const isSelected = selected === pkg.id;
          return (
            <button
              key={pkg.id}
              onClick={() => setSelected(pkg.id)}
              className={`relative flex flex-col items-start p-4 rounded-lg border text-left transition-all duration-150 focus:outline-none ${
                isSelected
                  ? "border-blue-500 bg-blue-500/10"
                  : "border-white/10 bg-white/5 hover:border-white/20 hover:bg-white/10"
              }`}
            >
              {pkg.popular && (
                <span className="absolute -top-2.5 right-3 text-[11px] font-medium bg-blue-500 text-white px-2 py-0.5 rounded-full">
                  Most popular
                </span>
              )}
              <span
                className={`text-xs font-medium mb-2 ${
                  isSelected ? "text-blue-400" : "text-gray-400"
                }`}
              >
                {pkg.label}
              </span>
              <span className="text-white text-lg font-bold">
                {pkg.credits.toLocaleString()}
                <span className="text-gray-400 text-sm font-normal ml-1">
                  credits
                </span>
              </span>
              <span className="text-white font-semibold mt-1">
                {formatUsd(pkg.usd)}
              </span>
              <span className="text-gray-500 text-xs mt-1">
                {formatTwd(pkg.twd)
                  ? `charged as ${formatTwd(pkg.twd)}`
                  : `US$${USD_PER_CREDIT} per credit`}
              </span>
            </button>
          );
        })}
      </div>

      {/* Summary */}
      {(() => {
        const pkg = packages.find((p) => p.id === selected);
        if (!pkg) return null;
        return (
          <div className="border border-white/10 rounded-lg px-4 py-3 space-y-2">
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">
                {pkg.credits.toLocaleString()} credits
              </span>
              <span className="text-white">{formatUsd(pkg.usd)}</span>
            </div>
            {formatTwd(pkg.twd) && (
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">
                  Amount charged
                  {rate && (
                    <span className="text-gray-500">
                      {" "}
                      (1 USD = {rate.toFixed(2)} TWD)
                    </span>
                  )}
                </span>
                <span className="text-white">{formatTwd(pkg.twd)}</span>
              </div>
            )}
            <div className="flex justify-between text-sm border-t border-white/10 pt-2">
              <span className="text-gray-400">New balance after purchase</span>
              <span className="text-green-400 font-medium">
                {(currentCredits + pkg.credits).toLocaleString()} credits
              </span>
            </div>
          </div>
        );
      })()}

      {/* Error / success */}
      {error && <p className="text-red-400 text-sm text-center">{error}</p>}
      {success && <p className="text-green-400 text-sm text-center">{success}</p>}

      {/* CTA */}
      <Button
        onClick={handlePurchase}
        disabled={loading}
        className="w-full"
      >
        {loading ? "Redirecting to checkout…" : "Continue to Payment"}
      </Button>

      <p className="text-gray-500 text-xs text-center">
        Prices are listed in US dollars. Payments are processed securely by
        NewebPay (藍新金流) and billed in New Taiwan Dollars at the exchange rate
        shown above; cards issued outside Taiwan may be offered the option to pay
        in their own currency at checkout. Credits are added to your account once
        payment is confirmed. Credits are prepaid analysis fees — not stored
        value — and cannot be transferred or redeemed for cash.
      </p>
    </div>
  );
};

export default BuyCredits;