// src/App.tsx
import * as React from "react";
import AuthForms from "./components/AuthForms";
import BuyCredits from "./components/BuyCredits";
import FileUploader from "./components/FileUploader";
import GuestUploader from "./components/GuestUploader";
import VerifyEmail from "./components/VerifyEmail";
import UploadHistory from "./components/UploadHistory";
import UserCredits from "./components/UserCredits";
import { Link } from "react-router-dom";
import { onUserStateChanged } from "./firebase/auth";
import { auth } from "./firebase/config";
import type { User } from "firebase/auth";
import { Button } from "./components/ui/button";
import ThemeToggle from "./components/ThemeToggle";

type View = "main" | "buy-credits";
type AuthMode = "auth" | "guest";

function App() {
  const [refresh, setRefresh] = React.useState(0);
  const [user, setUser] = React.useState<User | null>(null);
  const [view, setView] = React.useState<View>("main");
  const [currentCredits, setCurrentCredits] = React.useState<number>(0);
  const [authMode, setAuthMode] = React.useState<AuthMode>(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      const historyRaw = localStorage.getItem("cmaa_guest_jobs_history");
      const hasHistory = historyRaw && historyRaw !== "[]";
      if (
        params.get("guest_job") ||
        hasHistory ||
        localStorage.getItem("cmaa_guest_job")
      ) {
        return "guest";
      }
    }
    return "auth";
  });

  React.useEffect(() => {
    const unsubscribe = onUserStateChanged(setUser);
    return () => unsubscribe();
  }, []);

  // Handle NewebPay return callback status (?credits=success | ?credits=failed)
  React.useEffect(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      const credits = params.get("credits");
      if (credits === "success") {
        alert("Payment successful! Your credit balance has been updated.");
        params.delete("credits");
        const newSearch = params.toString() ? `?${params.toString()}` : "";
        window.history.replaceState({}, document.title, window.location.pathname + newSearch);
        setRefresh((prev) => prev + 1);
      } else if (credits === "failed") {
        alert("Payment was not completed or encountered an error. Please try again.");
        params.delete("credits");
        const newSearch = params.toString() ? `?${params.toString()}` : "";
        window.history.replaceState({}, document.title, window.location.pathname + newSearch);
      }
    }
  }, []);

  // Email-verified users only: ensure their backend/Firestore record exists.
  // getIdToken(true) forces a fresh token so the backend sees email_verified.
  React.useEffect(() => {
    if (!user || !user.emailVerified) return;
    (async () => {
      try {
        const token = await user.getIdToken(true);
        await fetch(`${import.meta.env.VITE_BACKEND_URL}/api/initUser`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        });
      } catch (err) {
        console.error("initUser error:", err);
      }
    })();
  }, [user]);

  const verified = !!user?.emailVerified;

  // Bumped whenever an upload or an analysis changes what the page should show —
  // the history list and the credit balance both key off it.
  const refreshAccount = () => setRefresh((prev) => prev + 1);

  const handleLogout = async () => {
    try {
      await auth.signOut();
    } finally {
      setAuthMode("auth");
      setView("main");
    }
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-gradient-to-br from-slate-100 via-background to-indigo-50 dark:from-[#070b16] dark:via-background dark:to-[#0c1226] p-4">
      <div className="w-full max-w-[760px] flex flex-col items-center gap-6 rounded-2xl border border-border bg-card p-7 shadow-2xl shadow-black/50">

        {/* ── Unauthenticated / unverified ─────────────────────────────── */}
        {(!user || !verified) && (
          <div className="flex justify-end w-full">
            <ThemeToggle />
          </div>
        )}

        {!user && authMode === "auth" && (
          <AuthForms onContinueAsGuest={() => setAuthMode("guest")} />
        )}

        {!user && authMode === "guest" && (
          <GuestUploader onSwitchToAuth={() => setAuthMode("auth")} />
        )}

        {/* Signed in but email not yet verified */}
        {user && !verified && <VerifyEmail email={user.email} />}

        {/* ── Authenticated & verified ─────────────────────────────────── */}
        {user && verified && view === "buy-credits" && (
          <BuyCredits
            currentCredits={currentCredits}
            onBack={() => setView("main")}
          />
        )}

        {user && verified && view === "main" && (
          <>
            <div className="flex justify-between w-full items-center">
              <div className="text-foreground font-medium flex items-center gap-2">
                Logged in as {user.email}
                <UserCredits
                  user={user}
                  refreshSignal={refresh}
                  onCreditsLoaded={setCurrentCredits}
                />
              </div>

              <div className="flex items-center gap-2">
                <ThemeToggle />
                <Button variant="outline" onClick={() => setView("buy-credits")}>
                  Buy Credits
                </Button>
                <Button onClick={handleLogout}>
                  Logout
                </Button>
              </div>
            </div>

            <FileUploader onUpload={refreshAccount} />
            {/* Analyses spend credits, so a run has to refresh the balance too */}
            <UploadHistory refreshSignal={refresh} onCreditsChanged={refreshAccount} />
          </>
        )}

        {/* ── Company / contact footer (required merchant disclosure) ──── */}
        <footer className="w-full border-t border-border pt-4 text-center text-sm text-muted-foreground">
          <Link to="/" className="text-primary hover:underline">
            Product Introduction &amp; Pricing
          </Link>
          <p className="mt-1">
            SUPREMA TECHNOLOGIES LTD ·{" "}
            <a
              href="mailto:suprematechnologiesltd@solitesterror.com"
              className="hover:underline"
            >
              suprematechnologiesltd@solitesterror.com
            </a>
          </p>
        </footer>

      </div>
    </div>
  );
}

export default App;