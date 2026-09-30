import React, { useState, useCallback, useEffect, useRef } from "react";
import { sha256 } from "js-sha256";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  UploadCloud,
  FileText,
  AlertTriangle,
  CheckCircle,
  Loader2,
  Clock,
  AlertCircle,
  Download,
  Shield,
  RotateCcw,
  CreditCard,
  FileSearch,
  Zap,
  Mail,
  Lock,
  User,
  ShieldAlert,
  Hourglass,
  PlusCircle,
} from "lucide-react";
import PackedApkNotice from "./PackedApkNotice";

// ─── Types ────────────────────────────────────────────────────────────────────

type AnalysisType = "static" | "dynamic";

type UploadStep =
  | "idle"       // Waiting for file selection
  | "uploading"  // Hashing + sending to server
  | "tracking";  // Job created — polling for status

type JobStatus = "pending" | "uploaded" | "analyzing" | "done" | "error";

interface SummaryPreview {
  high?: number;
  medium?: number;
  low?: number;
  score?: number;
}

interface StoredGuestJob {
  jobId: string;
  secretKey: string;
  filename: string;
  analysisType: AnalysisType;
  status: JobStatus;
  createdAt: string;
  uploadTime?: string;
  isPaid?: boolean;
  priceUsd?: number;
  priceTwd?: number;
  summaryPreview?: SummaryPreview | null;
  downloadToken?: string;
}

// ─── Storage Helpers ──────────────────────────────────────────────────────────

const JOBS_STORAGE_KEY = "cmaa_guest_jobs_history";
const LEGACY_JOB_KEY = "cmaa_guest_job";
const COOLDOWN_KEY = "cmaa_guest_cooldown_until";

function loadStoredJobs(): StoredGuestJob[] {
  try {
    const raw = localStorage.getItem(JOBS_STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        return parsed.slice(0, 3).map((item: any) => ({
          jobId: item.jobId || "",
          secretKey: item.secretKey || "",
          filename: item.filename || "Previous Analysis",
          analysisType: item.analysisType || "static",
          status: item.status || "pending",
          createdAt: item.createdAt || item.uploadTime || new Date().toISOString(),
          uploadTime: item.uploadTime || item.createdAt || new Date().toISOString(),
          isPaid: Boolean(item.isPaid),
          downloadToken: item.downloadToken,
          priceUsd: item.priceUsd,
          priceTwd: item.priceTwd,
          summaryPreview: item.summaryPreview,
        }));
      }
    }
    const legacy = localStorage.getItem(LEGACY_JOB_KEY);
    if (legacy) {
      const now = new Date().toISOString();
      return [
        {
          jobId: legacy,
          secretKey: "",
          filename: "Previous Analysis",
          analysisType: "static",
          status: "pending",
          createdAt: now,
          uploadTime: now,
        },
      ];
    }
  } catch {}
  return [];
}

function saveStoredJobs(jobs: StoredGuestJob[]) {
  try {
    const trimmed = jobs.slice(0, 3).map((j) => ({
      jobId: j.jobId,
      secretKey: j.secretKey,
      filename: j.filename,
      analysisType: j.analysisType,
      status: j.status,
      isPaid: j.isPaid ?? false,
      downloadToken: j.downloadToken,
      createdAt: j.createdAt || j.uploadTime || new Date().toISOString(),
      uploadTime: j.uploadTime || j.createdAt || new Date().toISOString(),
      priceUsd: j.priceUsd,
      priceTwd: j.priceTwd,
      summaryPreview: j.summaryPreview,
    }));
    localStorage.setItem(JOBS_STORAGE_KEY, JSON.stringify(trimmed));
    if (trimmed.length > 0) {
      localStorage.setItem(LEGACY_JOB_KEY, trimmed[0].jobId);
    } else {
      localStorage.removeItem(LEGACY_JOB_KEY);
    }
  } catch {}
}

// ─── Static config ────────────────────────────────────────────────────────────

const ANALYSIS_OPTIONS: {
  value: AnalysisType;
  label: string;
  desc: string;
  icon: React.ComponentType<{ className?: string }>;
}[] = [
  {
    value: "static",
    label: "Static Analysis",
    desc: "Inspect code, permissions, and configuration without running the app (instant analysis).",
    icon: FileSearch,
  },
  {
    value: "dynamic",
    label: "Dynamic Analysis (~3 mins)",
    desc: "Run the app inside a dedicated ARM64 Android sandbox to inspect live runtime behavior and Frida hooks.",
    icon: Zap,
  },
];

const StatusIcon: React.FC<{ status: JobStatus; isPaid?: boolean }> = ({ status, isPaid }) => {
  const cls = "h-3.5 w-3.5";
  switch (status) {
    case "pending":
    case "uploaded":
      return <Clock className={cls} />;
    case "analyzing":
      return <Loader2 className={`${cls} animate-spin`} />;
    case "done":
      return isPaid ? <CheckCircle className={cls} /> : <CreditCard className={cls} />;
    case "error":
      return <AlertCircle className={cls} />;
  }
};

const statusLabel = (status: JobStatus, isPaid?: boolean): string => {
  switch (status) {
    case "pending":
    case "uploaded":
      return "Queued";
    case "analyzing":
      return "Analyzing…";
    case "done":
      return isPaid ? "Report Unlocked" : "Report Ready (Payment Required)";
    case "error":
      return "Analysis Failed";
  }
};

const statusPill = (status: JobStatus, isPaid?: boolean): string => {
  switch (status) {
    case "pending":
    case "uploaded":
      return "bg-yellow-500/15 text-yellow-400";
    case "analyzing":
      return "bg-blue-500/15 text-blue-400";
    case "done":
      return isPaid ? "bg-green-500/15 text-green-400" : "bg-amber-500/15 text-amber-400";
    case "error":
      return "bg-red-500/15 text-red-400";
  }
};

// ─── Main component ───────────────────────────────────────────────────────────

interface GuestUploaderProps {
  onSwitchToAuth?: () => void;
}

const GuestUploader: React.FC<GuestUploaderProps> = ({ onSwitchToAuth }) => {
  const [jobsList, setJobsList] = useState<StoredGuestJob[]>(() => loadStoredJobs());
  const [activeJobId, setActiveJobId] = useState<string | null>(() => {
    const list = loadStoredJobs();
    return list[0]?.jobId ?? null;
  });

  const [step, setStep] = useState<UploadStep>(() => {
    const list = loadStoredJobs();
    return list.length > 0 ? "tracking" : "idle";
  });

  const [analysisType, setAnalysisType] = useState<AnalysisType>("static");
  const [file, setFile] = useState<File | null>(null);
  const [progress, setProgress] = useState(0);
  const [isDragOver, setIsDragOver] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [paying, setPaying] = useState(false);
  const [paymentNotice, setPaymentNotice] = useState<{ type: "success" | "failed"; text: string } | null>(null);
  const [cooldownRemaining, setCooldownRemaining] = useState<number>(0);

  // Dynamic analysis optional test credentials
  const [appUsername, setAppUsername] = useState("");
  const [appPassword, setAppPassword] = useState("");

  // ── Cloudflare Turnstile Human Verification ─────────────────────────────────
  const [turnstileSiteKey, setTurnstileSiteKey] = useState<string>(
    import.meta.env.VITE_TURNSTILE_SITE_KEY || ""
  );
  const [turnstileToken, setTurnstileToken] = useState<string>("");
  const turnstileContainerRef = useRef<HTMLDivElement>(null);
  const turnstileWidgetId = useRef<string | null>(null);

  // Discover Turnstile site key dynamically if not baked into Vite env
  useEffect(() => {
    fetch(`${import.meta.env.VITE_BACKEND_URL}/guest/config`)
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data?.turnstileSiteKey) {
          setTurnstileSiteKey(data.turnstileSiteKey);
        }
      })
      .catch(() => {});
  }, []);

  // Dynamically load Cloudflare Turnstile script when key is available
  useEffect(() => {
    if (!turnstileSiteKey) return;
    if (document.getElementById("cf-turnstile-script")) return;

    const script = document.createElement("script");
    script.id = "cf-turnstile-script";
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    script.async = true;
    script.defer = true;
    document.head.appendChild(script);
  }, [turnstileSiteKey]);

  // Render Turnstile widget when container is ready
  useEffect(() => {
    if (!turnstileSiteKey || step !== "idle") return;

    let timer: NodeJS.Timeout;
    const tryRender = () => {
      const turnstile = (window as any).turnstile;
      if (turnstile && turnstileContainerRef.current) {
        if (turnstileWidgetId.current !== null) {
          try {
            turnstile.remove(turnstileWidgetId.current);
          } catch {}
          turnstileWidgetId.current = null;
        }
        try {
          turnstileWidgetId.current = turnstile.render(turnstileContainerRef.current, {
            sitekey: turnstileSiteKey,
            callback: (token: string) => {
              setTurnstileToken(token);
            },
            "expired-callback": () => {
              setTurnstileToken("");
            },
            "error-callback": () => {
              console.warn("Turnstile challenge encountered an error");
            },
            theme: "auto",
          });
        } catch (e) {
          console.warn("Turnstile render error:", e);
        }
      } else {
        timer = setTimeout(tryRender, 300);
      }
    };

    tryRender();

    return () => {
      clearTimeout(timer);
    };
  }, [turnstileSiteKey, step]);

  const pollTimersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  const activeJob: StoredGuestJob | null =
    jobsList.find((j) => j.jobId === activeJobId) || jobsList[0] || null;

  // Clean up all polling timers on unmount
  useEffect(() => () => {
    pollTimersRef.current.forEach((timer) => clearTimeout(timer));
    pollTimersRef.current.clear();
  }, []);

  // ── Cooldown timer countdown ───────────────────────────────────────────────
  useEffect(() => {
    const cooldownUntil = localStorage.getItem(COOLDOWN_KEY);
    if (cooldownUntil) {
      const remaining = Math.max(0, Math.ceil((Number(cooldownUntil) - Date.now()) / 1000));
      setCooldownRemaining(remaining);
    }
  }, []);

  useEffect(() => {
    if (cooldownRemaining <= 0) return;
    const timer = setInterval(() => {
      setCooldownRemaining((prev) => {
        if (prev <= 1) {
          localStorage.removeItem(COOLDOWN_KEY);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [cooldownRemaining]);

  const formatCooldown = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${String(mins).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;
  };

  // ── Polling status with x-guest-secret ──────────────────────────────────────
  const pollStatus = useCallback((jobId: string, secretKey?: string, attempts = 0) => {
    const MAX_ATTEMPTS = 120; // 120 × 3s = 6 mins
    const INTERVAL_MS = 3000;

    if (pollTimersRef.current.has(jobId)) {
      clearTimeout(pollTimersRef.current.get(jobId)!);
      pollTimersRef.current.delete(jobId);
    }

    const timer = setTimeout(async () => {
      try {
        const headers: Record<string, string> = {};
        if (secretKey) {
          headers["x-guest-secret"] = secretKey;
        }
        const res = await fetch(
          `${import.meta.env.VITE_BACKEND_URL}/guest/job-status/${jobId}`,
          { headers }
        );
        if (!res.ok) throw new Error("Status check failed");

        const data = await res.json();

        setJobsList((prev) => {
          const next = prev.map((j) => {
            if (j.jobId === jobId) {
              return {
                ...j,
                status: data.status,
                isPaid: data.isPaid,
                priceUsd: data.priceUsd,
                priceTwd: data.priceTwd,
                summaryPreview: data.summaryPreview ?? j.summaryPreview,
                downloadToken: data.downloadToken || j.downloadToken,
              };
            }
            return j;
          });
          saveStoredJobs(next);
          return next;
        });

        if (data.status === "analyzing" || data.status === "pending" || data.status === "uploaded") {
          pollStatus(jobId, secretKey, attempts + 1);
        } else {
          pollTimersRef.current.delete(jobId);
        }
      } catch {
        if (attempts < MAX_ATTEMPTS) {
          pollStatus(jobId, secretKey, attempts + 1);
        } else {
          pollTimersRef.current.delete(jobId);
        }
      }
    }, INTERVAL_MS);

    pollTimersRef.current.set(jobId, timer);
  }, []);

  // ── Restore active jobs on mount ───────────────────────────────────────────
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const guestJobParam = params.get("guest_job");
    const paymentParam = params.get("payment");
    const tokenParam = params.get("token");

    if (paymentParam === "success") {
      setPaymentNotice({
        type: "success",
        text: "Payment successful! Your security assessment report is unlocked. Click below to download your PDF report.",
      });
    } else if (paymentParam === "failed") {
      setPaymentNotice({
        type: "failed",
        text: "Payment was not completed or was cancelled. Please checkout again to unlock your report.",
      });
    }

    const currentList = loadStoredJobs();

    if (guestJobParam) {
      setActiveJobId(guestJobParam);
      setStep("tracking");
    }

    currentList.forEach((j) => {
      const headers: Record<string, string> = {};
      if (j.secretKey) headers["x-guest-secret"] = j.secretKey;

      fetch(`${import.meta.env.VITE_BACKEND_URL}/guest/job-status/${j.jobId}`, { headers })
        .then((res) => (res.ok ? res.json() : null))
        .then((data) => {
          if (data) {
            setJobsList((prev) => {
              const next = prev.map((item) => {
                if (item.jobId === j.jobId) {
                  return {
                    ...item,
                    filename: data.filename || item.filename,
                    analysisType: data.analysisType || item.analysisType,
                    status: data.status,
                    isPaid: data.isPaid || (guestJobParam === j.jobId && paymentParam === "success"),
                    priceUsd: data.priceUsd,
                    priceTwd: data.priceTwd,
                    summaryPreview: data.summaryPreview ?? item.summaryPreview,
                    downloadToken:
                      data.downloadToken ||
                      (guestJobParam === j.jobId && tokenParam ? tokenParam : undefined) ||
                      item.downloadToken,
                  };
                }
                return item;
              });
              saveStoredJobs(next);
              return next;
            });

            if (["analyzing", "pending", "uploaded"].includes(data.status)) {
              pollStatus(j.jobId, j.secretKey);
            }
          }
        })
        .catch(() => {});
    });
  }, [pollStatus]);

  // ── Helpers ────────────────────────────────────────────────────────────────

  const reset = () => {
    setStep("idle");
    setFile(null);
    setProgress(0);
    setErrorMsg(null);
    setPaymentNotice(null);
  };

  const handleDiscard = async () => {
    if (!activeJob?.jobId) {
      reset();
      return;
    }

    const isUnpaidCompleted = activeJob.status === "done" && !activeJob.isPaid;
    const confirmText = isUnpaidCompleted
      ? "Are you sure you want to discard this report? A 10-minute cooldown will be enforced before you can upload another application."
      : "Are you sure you want to discard this job?";

    const confirmed = window.confirm(confirmText);
    if (!confirmed) return;

    if (pollTimersRef.current.has(activeJob.jobId)) {
      clearTimeout(pollTimersRef.current.get(activeJob.jobId)!);
      pollTimersRef.current.delete(activeJob.jobId);
    }

    try {
      await fetch(`${import.meta.env.VITE_BACKEND_URL}/guest/discard-job`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(activeJob.secretKey ? { "x-guest-secret": activeJob.secretKey } : {}),
        },
        body: JSON.stringify({ jobId: activeJob.jobId, secretKey: activeJob.secretKey }),
      });
    } catch (e) {
      console.warn("Discard API call failed:", e);
    }

    if (isUnpaidCompleted) {
      const cooldownSeconds = 10 * 60; // 10 minutes
      const until = Date.now() + cooldownSeconds * 1000;
      localStorage.setItem(COOLDOWN_KEY, String(until));
      setCooldownRemaining(cooldownSeconds);
    }

    const remaining = jobsList.filter((j) => j.jobId !== activeJob.jobId);
    setJobsList(remaining);
    saveStoredJobs(remaining);
    setActiveJobId(remaining[0]?.jobId || null);

    if (remaining.length === 0) {
      setStep("idle");
    }
  };

  const calculateHash = async (f: File): Promise<string> => {
    const buf = await f.arrayBuffer();
    return sha256(new Uint8Array(buf));
  };

  // ── File handling ──────────────────────────────────────────────────────────

  const handleFile = useCallback(
    async (selectedFile: File) => {
      // Rule 1: Cooldown check
      if (cooldownRemaining > 0) {
        setErrorMsg(`Cooldown active: Please wait ${formatCooldown(cooldownRemaining)} before uploading another application.`);
        setStep("tracking");
        return;
      }

      // Rule 2: Unpaid job lock across recent session jobs
      const hasUnpaid = jobsList.some((j) => j.status === "done" && !j.isPaid);
      if (hasUnpaid) {
        setErrorMsg("Uploading is paused because you have a completed report awaiting payment. Please unlock or discard the existing report first.");
        setStep("tracking");
        return;
      }

      const name = selectedFile.name.toLowerCase();
      if (!name.endsWith(".apk") && !name.endsWith(".ipa")) {
        setErrorMsg("Invalid file extension: Only genuine .apk and .ipa files are accepted.");
        return;
      }
      if (selectedFile.size > 500 * 1024 * 1024) {
        setErrorMsg("File size must be under 500 MB.");
        return;
      }

      // Human verification check
      if (turnstileSiteKey && !turnstileToken) {
        setErrorMsg("Please complete the human verification challenge before uploading.");
        return;
      }

      // Client-side Magic Bytes check (ZIP header PK\x03\x04: 0x50 0x4B 0x03 0x04)
      try {
        const slice = selectedFile.slice(0, 4);
        const headerBuf = await slice.arrayBuffer();
        const bytes = new Uint8Array(headerBuf);
        if (
          bytes.length < 4 ||
          bytes[0] !== 0x50 ||
          bytes[1] !== 0x4b ||
          bytes[2] !== 0x03 ||
          bytes[3] !== 0x04
        ) {
          setErrorMsg("Invalid file format: The selected file is not a valid APK or IPA package (ZIP header PK\\x03\\x04 required).");
          return;
        }
      } catch (err) {
        console.warn("Client magic bytes check error:", err);
      }

      setFile(selectedFile);
      setStep("uploading");
      setProgress(0);
      setErrorMsg(null);

      // Hash calculation (0 → 20%)
      let sim = 0;
      const hashInterval = setInterval(() => {
        sim = Math.min(sim + Math.random() * 5, 20);
        setProgress(Math.round(sim));
      }, 100);

      let hash: string;
      try {
        hash = await calculateHash(selectedFile);
      } catch {
        clearInterval(hashInterval);
        setErrorMsg("Failed to read the file.");
        setStep("tracking");
        return;
      }
      clearInterval(hashInterval);
      setProgress(20);

      // Create guest job on backend
      let jobId: string;
      let secretKey: string;
      try {
        const res = await fetch(`${import.meta.env.VITE_BACKEND_URL}/guest/create-job`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            analysisType,
            hash,
            fileName: selectedFile.name,
            currentJobId: activeJobId || undefined,
            appUsername: appUsername.trim() || undefined,
            appPassword: appPassword.trim() || undefined,
            turnstileToken: turnstileToken || undefined,
          }),
        });

        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          if (errData.error === "turnstile_failed") {
            throw new Error(errData.message || "Human verification challenge failed. Please try again.");
          }
          if (errData.error === "unpaid_job_pending") {
            throw new Error("You have a completed report awaiting payment. Please unlock or discard it before analyzing another application.");
          }
          if (errData.error === "cooldown_active") {
            const sec = errData.remainingSeconds || 600;
            setCooldownRemaining(sec);
            throw new Error(`Cooldown active: Please wait ${formatCooldown(sec)} before uploading another application.`);
          }
          throw new Error(errData.message || "Failed to create job.");
        }
        const created = await res.json();
        jobId = created.jobId;
        secretKey = created.secretKey;

        // Reset Turnstile challenge for subsequent uploads
        if (turnstileSiteKey && (window as any).turnstile && turnstileWidgetId.current) {
          try {
            (window as any).turnstile.reset(turnstileWidgetId.current);
          } catch {}
          setTurnstileToken("");
        }
      } catch (e: any) {
        setErrorMsg(e.message ?? "Could not reach the server.");
        setStep("tracking");
        return;
      }

      // Evict oldest job if session array already has 3 jobs (physical S3 deletion triggered)
      if (jobsList.length >= 3) {
        const evictedJobs = jobsList.slice(2);
        for (const ej of evictedJobs) {
          fetch(`${import.meta.env.VITE_BACKEND_URL}/guest/cleanup-job`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              ...(ej.secretKey ? { "x-guest-secret": ej.secretKey } : {}),
            },
            body: JSON.stringify({ jobId: ej.jobId, secretKey: ej.secretKey }),
          }).catch((e) => console.warn("Failed to cleanup evicted job S3 files:", e));
        }
      }

      const nowIso = new Date().toISOString();
      const newJobEntry: StoredGuestJob = {
        jobId,
        secretKey,
        filename: selectedFile.name,
        analysisType,
        status: "analyzing",
        createdAt: nowIso,
        uploadTime: nowIso,
        isPaid: false,
      };

      const updatedJobsList = [newJobEntry, ...jobsList.slice(0, 2)];
      setJobsList(updatedJobsList);
      saveStoredJobs(updatedJobsList);
      setActiveJobId(jobId);

      // Upload file to S3 (20 → 100%)
      const fileType = name.endsWith(".ipa") ? "ipa" : "apk";
      const formData = new FormData();
      formData.append("file", selectedFile);
      formData.append("jobId", jobId);
      formData.append("analysisType", analysisType);
      formData.append("fileType", fileType);
      formData.append("hash", hash);

      try {
        await new Promise<void>((resolve, reject) => {
          const xhr = new XMLHttpRequest();
          xhr.upload.onprogress = (ev) => {
            if (ev.lengthComputable) {
              setProgress(Math.round(20 + (ev.loaded / ev.total) * 80));
            }
          };
          xhr.onload = () => (xhr.status >= 200 && xhr.status < 300 ? resolve() : reject(new Error(xhr.statusText)));
          xhr.onerror = () => reject(new Error("Network error during upload."));
          xhr.open("POST", `${import.meta.env.VITE_BACKEND_URL}/guest/upload`);
          if (secretKey) {
            xhr.setRequestHeader("x-guest-secret", secretKey);
          }
          xhr.send(formData);
        });
      } catch (e: any) {
        setErrorMsg(e.message ?? "Upload failed.");
        setStep("tracking");
        return;
      }

      setProgress(100);
      setStep("tracking");

      // Automatically poll analysis progress until done
      pollStatus(jobId, secretKey);
    },
    [analysisType, pollStatus, appUsername, appPassword, jobsList, activeJobId, cooldownRemaining]
  );

  // ── NewebPay Checkout for Guest Report ─────────────────────────────────────

  const handleGuestCheckout = async () => {
    if (!activeJob?.jobId) return;
    setPaying(true);
    try {
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (activeJob.secretKey) {
        headers["x-guest-secret"] = activeJob.secretKey;
      }

      const res = await fetch(`${import.meta.env.VITE_BACKEND_URL}/api/newebpay/guest-checkout`, {
        method: "POST",
        headers,
        body: JSON.stringify({ jobId: activeJob.jobId }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error ?? "Failed to initialize checkout order.");
      }

      const data = await res.json();
      if (data.simulated) {
        setJobsList((prev) => {
          const updated = prev.map((j) =>
            j.jobId === activeJob.jobId
              ? { ...j, isPaid: true, downloadToken: data.downloadToken }
              : j
          );
          saveStoredJobs(updated);
          return updated;
        });
        setPaymentNotice({
          type: "success",
          text: "Payment successful! Your security assessment report is unlocked. Click below to download your PDF report.",
        });
        setPaying(false);
        return;
      }

      const { gateway, merchantID, tradeInfo, tradeSha, version } = data;

      // Submit foreground HTML POST form to NewebPay gateway
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
      alert(err.message ?? "Payment gateway error. Please try again later.");
      setPaying(false);
    }
  };

  // ── PDF download with x-guest-secret ───────────────────────────────────────

  const handleDownload = async (lang: "zh-TW" | "en" = "zh-TW") => {
    if (!activeJob?.downloadToken) return;
    try {
      const headers: Record<string, string> = {};
      if (activeJob.secretKey) {
        headers["x-guest-secret"] = activeJob.secretKey;
      }
      const res = await fetch(
        `${import.meta.env.VITE_BACKEND_URL}/guest/report/${activeJob.downloadToken}?lang=${lang}`,
        { headers }
      );
      if (!res.ok) throw new Error("Download failed.");

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute(
        "download",
        `${(activeJob.filename || "security-report").replace(/\.[^/.]+$/, "")}-${activeJob.analysisType}-${lang === "en" ? "en" : "zh"}-report.pdf`
      );
      document.body.appendChild(link);
      link.click();
      link.parentNode?.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Download error:", err);
      alert("Download failed. Please check that the report has not expired or exceeded its download limit.");
    }
  };

  // ── Drag & drop state ──────────────────────────────────────────────────────

  const isAnalyzing = Boolean(
    activeJob && (activeJob.status === "analyzing" || activeJob.status === "pending" || activeJob.status === "uploaded")
  );
  const hasUnpaidJob = jobsList.some((j) => j.status === "done" && !j.isPaid);
  const isUploadDisabled = hasUnpaidJob || cooldownRemaining > 0 || isAnalyzing;

  const onDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    if (!isUploadDisabled) setIsDragOver(true);
  };
  const onDragLeave = () => setIsDragOver(false);
  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    if (!isUploadDisabled && e.dataTransfer.files.length > 0) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="w-full space-y-6">

      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-primary/15 ring-1 ring-primary/25">
            <Shield className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h2 className="text-lg font-semibold leading-tight">App Security Analysis</h2>
            <p className="text-xs text-muted-foreground">Guest session — up to 3 recent jobs preserved</p>
          </div>
        </div>
        {onSwitchToAuth && (
          <Button
            variant="ghost"
            size="sm"
            className="text-xs text-muted-foreground"
            onClick={onSwitchToAuth}
          >
            Sign in / Register
          </Button>
        )}
      </div>

      <div className="h-px bg-border" />

      {/* ── Multi-job History Selector (Retains latest 3 jobs) ─────────────── */}
      {jobsList.length > 0 && (
        <div className="space-y-2 rounded-xl border border-border bg-muted/20 p-3.5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Clock className="h-3.5 w-3.5 text-primary" />
              <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Recent Tasks ({jobsList.length}/3)
              </span>
            </div>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
            {jobsList.map((item) => {
              const isSelected = step === "tracking" && activeJob?.jobId === item.jobId;
              return (
                <button
                  key={item.jobId}
                  type="button"
                  onClick={() => {
                    setActiveJobId(item.jobId);
                    setStep("tracking");
                  }}
                  className={`flex items-center justify-between gap-2 rounded-lg border p-2.5 text-left transition-all ${
                    isSelected
                      ? "border-primary bg-primary/10 ring-1 ring-primary/40 shadow-sm"
                      : "border-border bg-background/70 hover:border-primary/40 hover:bg-muted/30"
                  }`}
                >
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-xs font-medium text-foreground">{item.filename || "App Analysis"}</p>
                    <div className="flex items-center gap-1.5 mt-0.5">
                      <span className="text-[10px] text-muted-foreground capitalize">{item.analysisType}</span>
                      <span className="text-[10px] text-muted-foreground">·</span>
                      <span className="text-[10px] text-muted-foreground">
                        {item.isPaid ? "Paid" : item.status === "done" ? "Ready" : item.status}
                      </span>
                    </div>
                  </div>
                  <StatusIcon status={item.status} isPaid={item.isPaid} />
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Payment notice banner if returning from NewebPay */}
      {paymentNotice && (
        <div
          className={`flex items-start gap-2.5 rounded-xl border p-3.5 text-xs ${
            paymentNotice.type === "success"
              ? "border-green-500/30 bg-green-500/10 text-green-300"
              : "border-destructive/30 bg-destructive/10 text-destructive"
          }`}
        >
          {paymentNotice.type === "success" ? (
            <CheckCircle className="h-4 w-4 shrink-0 text-green-400 mt-0.5" />
          ) : (
            <AlertCircle className="h-4 w-4 shrink-0 text-destructive mt-0.5" />
          )}
          <p className="flex-1 leading-relaxed">{paymentNotice.text}</p>
        </div>
      )}

      {/* ── Idle: file selector ─────────────────────────────────────────── */}
      {step === "idle" && (
        <div className="space-y-5">
          <div className="space-y-3">
            <p className="text-sm font-medium">Choose analysis type</p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {ANALYSIS_OPTIONS.map((opt) => {
                const Icon = opt.icon;
                const active = analysisType === opt.value;
                return (
                  <button
                    type="button"
                    key={opt.value}
                    onClick={() => setAnalysisType(opt.value)}
                    className={`relative flex flex-col gap-2 rounded-xl border p-4 text-left transition-all ${
                      active
                        ? "border-primary bg-primary/10 ring-1 ring-primary/40"
                        : "border-border bg-muted/20 hover:border-primary/40 hover:bg-muted/40"
                    }`}
                  >
                    <div
                      className={`flex h-9 w-9 items-center justify-center rounded-lg ${
                        active ? "bg-primary/20 text-primary" : "bg-muted text-muted-foreground"
                      }`}
                    >
                      <Icon className="h-5 w-5" />
                    </div>
                    <span className="text-sm font-semibold">{opt.label}</span>
                    <span className="text-xs leading-snug text-muted-foreground">{opt.desc}</span>
                    {active && <CheckCircle className="absolute right-3 top-3 h-4 w-4 text-primary" />}
                  </button>
                );
              })}
            </div>

            {analysisType === "static" && <PackedApkNotice />}

            {/* Dynamic Analysis: Penetration test notice & optional test account inputs */}
            {analysisType === "dynamic" && (
              <div className="space-y-3 rounded-xl border border-border bg-muted/20 p-4 text-xs">
                <div className="flex items-start gap-2.5 text-muted-foreground">
                  <ShieldAlert className="h-4 w-4 shrink-0 text-amber-400 mt-0.5" />
                  <div className="space-y-1">
                    <p className="font-medium text-foreground">Automated Dynamic Sandbox Notes & Limitations (~3 mins)</p>
                    <p className="leading-relaxed">
                      The sandbox executes inside a dedicated ARM64 Android environment for up to 3 minutes with Frida runtime monitoring. If your app enforces SMS OTP, 2FA, biometric authentication, or root detection, the automated sandbox will inspect pre-login behaviors only.
                    </p>
                    <div className="pt-1">
                      <a
                        href="mailto:nthu.islab.appsec@gmail.com?subject=[CMAA]%20Custom%20Penetration%20Testing%20Inquiry"
                        className="inline-flex items-center gap-1.5 font-medium text-primary hover:underline"
                      >
                        <Mail className="h-3.5 w-3.5" />
                        For in-depth manual penetration testing, contact our team: nthu.islab.appsec@gmail.com
                      </a>
                    </div>
                  </div>
                </div>

                <div className="h-px bg-border my-2" />

                <div className="space-y-2">
                  <p className="font-medium text-foreground">Test Credentials (Optional, for simulated login)</p>
                  <div className="grid grid-cols-2 gap-2">
                    <div className="relative">
                      <User className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
                      <Input
                        placeholder="Username (optional)"
                        className="h-8 pl-8 text-xs bg-background"
                        value={appUsername}
                        onChange={(e) => setAppUsername(e.target.value)}
                      />
                    </div>
                    <div className="relative">
                      <Lock className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
                      <Input
                        type="password"
                        placeholder="Password (optional)"
                        className="h-8 pl-8 text-xs bg-background"
                        value={appPassword}
                        onChange={(e) => setAppPassword(e.target.value)}
                      />
                    </div>
                  </div>
                  <p className="text-[10px] text-muted-foreground">Credentials are encrypted with AES-256 and purged immediately after analysis.</p>
                </div>
              </div>
            )}
          </div>

          {/* Locked Upload Notice if an unpaid completed report exists */}
          {hasUnpaidJob && (
            <div className="rounded-xl border border-amber-500/40 bg-amber-500/10 p-4 space-y-3">
              <div className="flex items-start gap-2.5">
                <ShieldAlert className="h-5 w-5 text-amber-500 shrink-0 mt-0.5" />
                <div className="space-y-1 text-xs">
                  <p className="font-semibold text-foreground">Notice: Completed Report Awaiting Unlock</p>
                  <p className="text-muted-foreground leading-relaxed">
                    You have an existing completed security report for <span className="font-semibold text-foreground">{activeJob?.filename}</span> awaiting payment. Uploading a new app is paused until you unlock or discard the existing report.
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2 pt-1 border-t border-border/60">
                <Button size="sm" onClick={() => setStep("tracking")}>
                  <CreditCard className="h-3.5 w-3.5 mr-1.5" />
                  View & Unlock Report
                </Button>
                <Button size="sm" variant="ghost" className="text-muted-foreground hover:text-destructive text-xs" onClick={handleDiscard}>
                  <RotateCcw className="h-3.5 w-3.5 mr-1.5" />
                  Discard Report & Enter 10-Min Cooldown
                </Button>
              </div>
            </div>
          )}

          {/* Active Cooldown Banner if user discarded a report */}
          {cooldownRemaining > 0 && (
            <div className="rounded-xl border border-amber-500/40 bg-amber-500/10 p-4 space-y-2 text-xs">
              <div className="flex items-center gap-2 text-amber-500 font-semibold">
                <Hourglass className="h-4 w-4 animate-spin" />
                Cooldown Active: Next Upload Unlocks in {formatCooldown(cooldownRemaining)}
              </div>
              <p className="text-muted-foreground leading-relaxed">
                A 10-minute cooldown is active after discarding a completed report to prevent automated quota abuse. New uploads will unlock automatically when the countdown ends.
              </p>
            </div>
          )}

          {/* Cloudflare Turnstile Human Verification (rendered when site key is configured) */}
          {turnstileSiteKey && (
            <div className="flex flex-col items-center justify-center p-3 rounded-xl border border-border/80 bg-muted/20">
              <p className="text-xs text-muted-foreground mb-2 flex items-center gap-1.5 font-medium">
                <Shield className="h-3.5 w-3.5 text-primary" />
                Human Verification
              </p>
              <div ref={turnstileContainerRef} />
            </div>
          )}

          {/* Upload Dropzone */}
          <div
            onDragOver={onDragOver}
            onDragLeave={onDragLeave}
            onDrop={onDrop}
            onClick={() => {
              if (!isUploadDisabled) document.getElementById("guest-file-upload")?.click();
            }}
            className={`group flex flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed p-10 transition-all ${
              isUploadDisabled
                ? "cursor-not-allowed opacity-50 border-muted bg-muted/10"
                : isDragOver
                ? "cursor-pointer border-primary bg-primary/10"
                : "cursor-pointer border-border hover:border-primary/50 hover:bg-muted/30"
            }`}
          >
            <div className="flex h-14 w-14 items-center justify-center rounded-full bg-primary/15 ring-1 ring-primary/20 transition-transform group-hover:scale-105">
              {isUploadDisabled ? (
                <Lock className="h-7 w-7 text-muted-foreground" />
              ) : (
                <UploadCloud className="h-7 w-7 text-primary" />
              )}
            </div>
            <div className="text-center">
              {cooldownRemaining > 0 ? (
                <>
                  <p className="text-sm font-medium text-amber-500">Cooldown In Progress ({formatCooldown(cooldownRemaining)})</p>
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    Uploading will unlock automatically when the timer reaches 00:00.
                  </p>
                </>
              ) : isAnalyzing ? (
                <>
                  <p className="text-sm font-medium text-blue-400">Analysis In Progress</p>
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    Please wait while your application is being analyzed.
                  </p>
                </>
              ) : hasUnpaidJob ? (
                <>
                  <p className="text-sm font-medium text-muted-foreground">Upload Paused</p>
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    Please unlock or discard your previous completed report above.
                  </p>
                </>
              ) : (
                <>
                  <p className="text-sm font-medium">Drag & drop your APK or IPA file</p>
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    or <span className="font-medium text-primary">browse</span> to choose a file
                  </p>
                </>
              )}
            </div>
            <p className="text-[11px] text-muted-foreground">Max 500 MB · .apk or .ipa · Free preview, pay to unlock PDF</p>
            <input
              id="guest-file-upload"
              type="file"
              disabled={isUploadDisabled}
              className="hidden"
              accept=".apk,.ipa"
              onChange={(e) => e.target.files && handleFile(e.target.files[0])}
            />
          </div>
        </div>
      )}

      {/* ── Uploading: progress ─────────────────────────────────────────── */}
      {step === "uploading" && (
        <div className="flex flex-col items-center gap-5 rounded-xl border border-border bg-muted/20 p-10">
          <div className="flex h-14 w-14 items-center justify-center rounded-full bg-primary/15 ring-1 ring-primary/20">
            <UploadCloud className="h-7 w-7 text-primary animate-pulse" />
          </div>
          <div className="text-center">
            <p className="font-medium">
              {progress < 20 ? "Validating & hashing package…" : "Uploading to analysis server…"}
            </p>
            <p className="mt-1 text-xs text-muted-foreground">{file?.name}</p>
          </div>
          <div className="w-full space-y-1.5">
            <Progress value={progress} className="h-2" />
            <div className="flex justify-between text-[11px] text-muted-foreground">
              <span className="capitalize">{analysisType} analysis</span>
              <span>{progress}%</span>
            </div>
          </div>
        </div>
      )}

      {/* ── Tracking: single job card ───────────────────────────────────── */}
      {step === "tracking" && (
        <div className="space-y-4">

          {/* Error notice */}
          {errorMsg && (
            <div className="flex flex-col items-center gap-3 rounded-xl border border-destructive/30 bg-destructive/10 p-6 text-center">
              <div className="flex h-10 w-10 items-center justify-center rounded-full bg-destructive/15">
                <AlertTriangle className="h-5 w-5 text-destructive" />
              </div>
              <p className="text-xs text-destructive max-w-md">{errorMsg}</p>
              <Button variant="outline" size="sm" onClick={reset}>
                Try again
              </Button>
            </div>
          )}

          {/* Job card */}
          {activeJob && (
            <div className="overflow-hidden rounded-xl border border-border">
              {/* Header */}
              <div className="flex items-center justify-between gap-3 border-b border-border bg-muted/30 px-4 py-3">
                <div className="flex min-w-0 items-center gap-2.5">
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-background">
                    <FileText className="h-4 w-4 text-muted-foreground" />
                  </div>
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium">{activeJob.filename}</p>
                    <p className="text-[11px] text-muted-foreground">
                      {new Date(activeJob.uploadTime).toLocaleString()}
                    </p>
                  </div>
                </div>
                <Badge variant="outline" className="shrink-0 capitalize">
                  {activeJob.analysisType}
                </Badge>
              </div>

              {/* Body */}
              <div className="space-y-4 px-4 py-4">
                <div className="flex items-center justify-between gap-3">
                  <span
                    className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${statusPill(
                      activeJob.status,
                      activeJob.isPaid
                    )}`}
                  >
                    <StatusIcon status={activeJob.status} isPaid={activeJob.isPaid} />
                    {statusLabel(activeJob.status, activeJob.isPaid)}
                  </span>

                  {/* Analyzing status indicator */}
                  {(activeJob.status === "pending" || activeJob.status === "uploaded" || activeJob.status === "analyzing") && (
                    <Button size="sm" disabled variant="outline" className="text-xs">
                      <Loader2 className="h-3.5 w-3.5 animate-spin mr-1.5" />
                      Analyzing (~{activeJob.analysisType === "dynamic" ? "3 mins" : "30s"})…
                    </Button>
                  )}

                  {/* Ready for Payment Unlock - Exact requested format */}
                  {activeJob.status === "done" && !activeJob.isPaid && (
                    <Button size="sm" onClick={handleGuestCheckout} disabled={paying}>
                      {paying ? <Loader2 className="h-3.5 w-3.5 animate-spin mr-1.5" /> : <CreditCard className="h-3.5 w-3.5 mr-1.5" />}
                      Pay ${activeJob.priceUsd || 40}(one credit) to Unlock PDF
                    </Button>
                  )}

                  {/* Already Paid & Unlocked - Bilingual download options */}
                  {activeJob.status === "done" && activeJob.isPaid && (
                    <div className="flex flex-wrap items-center gap-2">
                      <Button size="sm" onClick={() => handleDownload("zh-TW")} className="bg-green-600 hover:bg-green-700 text-white">
                        <Download className="h-3.5 w-3.5 mr-1.5" />
                        下載中文報告 (PDF)
                      </Button>
                      <Button size="sm" variant="outline" onClick={() => handleDownload("en")} className="border-green-600/40 text-green-400 hover:bg-green-600/10">
                        <Download className="h-3.5 w-3.5 mr-1.5" />
                        Download English (PDF)
                      </Button>
                    </div>
                  )}

                  {/* Error state retry */}
                  {activeJob.status === "error" && (
                    <Button size="sm" variant="destructive" onClick={reset}>
                      <RotateCcw className="h-3.5 w-3.5 mr-1.5" />
                      Try Again
                    </Button>
                  )}
                </div>

                {/* Analysis in progress explanation */}
                {(activeJob.status === "analyzing" || activeJob.status === "pending" || activeJob.status === "uploaded") && (
                  <p className="rounded-lg bg-muted/40 px-3 py-2 text-xs text-muted-foreground leading-relaxed">
                    The system is analyzing your application in the background (evaluating 80+ security rules and runtime patterns). Once complete, you will receive a free score preview before choosing to pay and unlock the full PDF report.
                  </p>
                )}

                {/* Report Ready: Teaser & Pricing Box */}
                {activeJob.status === "done" && !activeJob.isPaid && (
                  <div className="space-y-3 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3.5 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-amber-400">🎉 Analysis Complete! Security Assessment Preview Ready</span>
                      <span className="font-bold text-foreground">US${activeJob.priceUsd || 40} (One Credit · Approx. NT${activeJob.priceTwd || 1200})</span>
                    </div>

                    {activeJob.summaryPreview && (
                      <div className="grid grid-cols-4 gap-2 text-center pt-1">
                        <div className="rounded-md bg-background/60 p-2 border border-border">
                          <p className="text-[10px] text-muted-foreground">Security Score</p>
                          <p className="text-base font-bold text-primary">{activeJob.summaryPreview.score ?? 75}/100</p>
                        </div>
                        <div className="rounded-md bg-background/60 p-2 border border-border">
                          <p className="text-[10px] text-muted-foreground">High Risk</p>
                          <p className="text-base font-bold text-destructive">{activeJob.summaryPreview.high ?? 0}</p>
                        </div>
                        <div className="rounded-md bg-background/60 p-2 border border-border">
                          <p className="text-[10px] text-muted-foreground">Medium Risk</p>
                          <p className="text-base font-bold text-amber-400">{activeJob.summaryPreview.medium ?? 0}</p>
                        </div>
                        <div className="rounded-md bg-background/60 p-2 border border-border">
                          <p className="text-[10px] text-muted-foreground">Low Risk</p>
                          <p className="text-base font-bold text-green-400">{activeJob.summaryPreview.low ?? 0}</p>
                        </div>
                      </div>
                    )}

                    <p className="text-muted-foreground leading-relaxed">
                      The full report includes alignment with OWASP MASVS and Taiwan Mobile App Security Standards, decompiled vulnerabilities, and remediation advice. Click above to unlock via NewebPay.
                    </p>
                  </div>
                )}

                {/* Paid Success Notice */}
                {activeJob.status === "done" && activeJob.isPaid && (
                  <div className="rounded-lg bg-green-500/10 border border-green-500/30 p-3 text-xs text-green-300">
                    <p className="font-medium">Report Unlocked!</p>
                    <p className="text-muted-foreground mt-0.5">
                      You can now download the complete PDF report above. Under our data minimization policy, this report is retained for 7 days with up to 3 downloads.
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* If paid or error, allow analyzing next file */}
          {activeJob && (activeJob.isPaid || activeJob.status === "error") && (
            <div className="flex justify-center pt-1">
              <Button variant="outline" size="sm" onClick={() => setStep("idle")}>
                <PlusCircle className="h-3.5 w-3.5 mr-1.5" />
                Analyze Another App
              </Button>
            </div>
          )}

          {/* If unpaid done, give option to discard with 10-minute cooldown */}
          {activeJob && activeJob.status === "done" && !activeJob.isPaid && (
            <div className="flex flex-col items-center gap-1.5 pt-1">
              <Button variant="ghost" size="sm" className="text-xs text-muted-foreground hover:text-destructive" onClick={handleDiscard}>
                <RotateCcw className="h-3.5 w-3.5 mr-1.5" />
                Discard This Report & Enter 10-Min Cooldown
              </Button>
              <p className="text-[10px] text-muted-foreground text-center">
                Notice: Discarding a completed report initiates a 10-minute cooldown before you can upload another application.
              </p>
            </div>
          )}

        </div>
      )}

    </div>
  );
};

export default GuestUploader;
