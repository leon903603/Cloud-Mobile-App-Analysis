import React from "react";
import type { User } from "firebase/auth";
import { ReceiptText } from "lucide-react";

interface Props {
  user: User;
  refreshSignal?: number;
  onCreditsLoaded?: (credits: number) => void;
  onClick?: () => void;
}

const UserCredits: React.FC<Props> = ({
  user,
  refreshSignal,
  onCreditsLoaded,
  onClick,
}) => {
  const [credits, setCredits] = React.useState<number | null>(null);

  const fetchCredits = async () => {
    try {
      const token = await user.getIdToken();
      const res = await fetch(
        `${import.meta.env.VITE_BACKEND_URL}/api/getCredits`,
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      if (!res.ok) return;

      const data = await res.json();
      setCredits(data.credits);
      onCreditsLoaded?.(data.credits);
    } catch (err) {
      console.error("Error fetching credits:", err);
    }
  };

  React.useEffect(() => {
    fetchCredits();
  }, [user]);

  React.useEffect(() => {
    fetchCredits();
  }, [refreshSignal]);

  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20 hover:border-emerald-500/50 transition-all cursor-pointer focus:outline-none focus:ring-2 focus:ring-emerald-400/50 shadow-sm"
      title="Click to view Credit Journal & Official Receipts"
      aria-label={`Credit balance: ${credits !== null ? credits : "loading"}. Click to view history and receipts.`}
    >
      <ReceiptText className="w-3.5 h-3.5 text-emerald-400" />
      <span>
        {credits !== null ? `Credits: ${credits}` : "Loading..."}
      </span>
      <span className="text-[10px] text-emerald-400/70 border-l border-emerald-500/30 pl-1.5 ml-0.5">
        Journal ↗
      </span>
    </button>
  );
};

export default UserCredits;
