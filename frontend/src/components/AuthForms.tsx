// src/components/AuthForms.tsx
import * as React from "react";
import { login, register } from "../firebase/auth";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Shield, Mail, Lock, UserCircle, Loader2, AlertCircle, ArrowRight } from "lucide-react";

interface AuthFormsProps {
  /** Called when the user chooses to proceed without an account */
  onContinueAsGuest?: () => void;
}

/** Maps Firebase auth error codes to messages safe to show the user. */
const friendlyAuthError = (err: any, mode: "login" | "register"): string => {
  switch (err?.code) {
    case "auth/invalid-email":
    case "auth/user-not-found":
    case "auth/wrong-password":
    case "auth/invalid-credential":
      return "Invalid email or password.";
    case "auth/email-already-in-use":
      return "An account with this email already exists.";
    case "auth/weak-password":
      return "Password should be at least 6 characters.";
    case "auth/too-many-requests":
      return "Too many attempts. Please try again later.";
    case "auth/network-request-failed":
      return "Network error. Please check your connection.";
    default:
      return mode === "login"
        ? "Could not sign in. Please try again."
        : "Could not create your account. Please try again.";
  }
};

import TurnstileWidget from "./TurnstileWidget";

const AuthForms: React.FC<AuthFormsProps> = ({ onContinueAsGuest }) => {
  const [mode, setMode] = React.useState<"login" | "register">("login");
  const [email, setEmail] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [turnstileToken, setTurnstileToken] = React.useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    const hasTurnstileKey = !!import.meta.env.VITE_TURNSTILE_SITE_KEY;
    if (hasTurnstileKey && !turnstileToken) {
      setError("Please complete the human verification challenge.");
      return;
    }

    setLoading(true);

    try {
      if (turnstileToken) {
        // Q4-A: Verify Turnstile Token with backend before proceeding
        const verifyRes = await fetch(`${import.meta.env.VITE_BACKEND_URL}/api/auth/verify-turnstile`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token: turnstileToken }),
        });
        const verifyData = await verifyRes.json().catch(() => null);
        if (!verifyRes.ok || !verifyData?.ok) {
          throw new Error(verifyData?.error || "Human verification failed. Please try again.");
        }
      }

      if (mode === "login") {
        // App gates on emailVerified and runs initUser once verified.
        await login(email, password);
      } else {
        // register() also sends the verification email; the App then shows
        // the "verify your email" screen until the user confirms.
        await register(email, password);
      }
    } catch (err: any) {
      setError(friendlyAuthError(err, mode));
    } finally {
      setLoading(false);
    }
  };

  const switchMode = (m: "login" | "register") => {
    setMode(m);
    setError("");
  };

  return (
    <div className="w-full space-y-6">

      {/* ── Brand header ────────────────────────────────────────────────── */}
      <div className="flex flex-col items-center gap-3 text-center">
        <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-primary/15 ring-1 ring-primary/25">
          <Shield className="h-6 w-6 text-primary" />
        </div>
        <div>
          <h1 className="text-xl font-semibold">App Security Analysis</h1>
          <p className="mt-0.5 text-sm text-muted-foreground">
            {mode === "login"
              ? "Welcome back — sign in to continue."
              : "Create an account to get started."}
          </p>
        </div>
      </div>

      {/* ── Login / Register toggle ─────────────────────────────────────── */}
      <div className="grid grid-cols-2 gap-1 rounded-xl border border-border bg-muted/30 p-1">
        {(["login", "register"] as const).map((m) => (
          <button
            key={m}
            type="button"
            onClick={() => switchMode(m)}
            className={`rounded-lg py-2 text-sm font-medium transition-colors
              ${mode === m
                ? "bg-primary text-primary-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground"
              }`}
          >
            {m === "login" ? "Login" : "Register"}
          </button>
        ))}
      </div>

      {/* ── Form ────────────────────────────────────────────────────────── */}
      <form onSubmit={handleSubmit} className="space-y-4">
        {error && (
          <div className="flex items-start gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2.5">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
            <p className="text-sm text-destructive">{error}</p>
          </div>
        )}

        <div className="space-y-1.5">
          <label className="text-xs font-medium text-muted-foreground">Email</label>
          <div className="relative">
            <Mail className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              type="email"
              placeholder="you@example.com"
              className="pl-9"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>
        </div>

        <div className="space-y-1.5">
          <label className="text-xs font-medium text-muted-foreground">Password</label>
          <div className="relative">
            <Lock className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              type="password"
              placeholder="••••••••"
              className="pl-9"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
        </div>

        {/* Turnstile Human Verification Challenge */}
        <TurnstileWidget
          onVerify={(tok) => {
            setTurnstileToken(tok);
            setError("");
          }}
          onExpire={() => setTurnstileToken("")}
        />

        <Button type="submit" disabled={loading} className="w-full">
          {loading ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Please wait…
            </>
          ) : (
            <>
              {mode === "login" ? "Sign in" : "Create account"}
              <ArrowRight className="h-4 w-4" />
            </>
          )}
        </Button>
      </form>

      {/* ── Guest option ────────────────────────────────────────────────── */}
      {onContinueAsGuest && (
        <>
          <div className="flex items-center gap-3">
            <div className="h-px flex-1 bg-border" />
            <span className="text-[11px] uppercase tracking-wider text-muted-foreground">
              or
            </span>
            <div className="h-px flex-1 bg-border" />
          </div>

          <button
            type="button"
            onClick={onContinueAsGuest}
            className="group flex w-full items-center gap-3 rounded-xl border border-border bg-muted/20 p-3.5 text-left transition-all hover:border-primary/40 hover:bg-muted/40"
          >
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/15 text-primary">
              <UserCircle className="h-5 w-5" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium">Continue as guest</p>
              <p className="text-xs text-muted-foreground">
                Upload once, pay per report. Files auto-delete after 7 days.
              </p>
            </div>
            <ArrowRight className="h-4 w-4 shrink-0 text-muted-foreground transition-transform group-hover:translate-x-0.5" />
          </button>
        </>
      )}
    </div>
  );
};

export default AuthForms;
