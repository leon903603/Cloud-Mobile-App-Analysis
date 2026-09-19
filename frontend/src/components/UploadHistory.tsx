import React, { useEffect, useState } from "react";
import { Card, CardHeader, CardContent, CardTitle } from "@/components/ui/card";
import { Calendar, FileText, CheckCircle, Loader2, AlertCircle, Clock, KeyRound } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Input } from "./ui/input";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Button } from "@/components/ui/button";
import { getIdToken } from "../firebase/auth";
import { auth } from "../firebase/config";
import PackedApkNotice from "./PackedApkNotice";
import { DynamicConfirmModal } from "./DynamicConfirmModal";

// Structure of an upload entry, might need to adjust based on actual backend response
interface UploadEntry {
  id: string;
  filename: string;
  analysisType: string;
  status: string;
  filePath?: string;
  hash?: string;
  uploadTime?: string;
  /** True once a credit has paid for this analysis — retrying it is then free. */
  creditSpent?: boolean;
  /** Dynamic runs only: whether a test account is stored for this row. */
  hasCredentials?: boolean;
  /** The stored account's username. Null if none, or if it can't be decrypted. */
  credentialUsername?: string | null;
}

// ─── Test account for a dynamic run ───────────────────────────────────────────
// A dynamic analysis sees only what a signed-out user sees, so it can be handed
// an account to explore the rest. Editable here and not just at upload time: the
// row may have come from the "reuse" path, which has no upload of its own, and an
// account can turn out to be wrong long before anyone presses Analyze. The
// exchange is one-way — the username comes back so its owner can see which
// account is stored, the password never does.
const CredentialsPanel: React.FC<{ upload: UploadEntry; onChanged: () => void }> = ({
  upload,
  onChanged,
}) => {
  const [editing, setEditing] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (method: "POST" | "DELETE") => {
    setBusy(true);
    setError(null);
    try {
      const token = await getIdToken();
      if (!token) throw new Error("User not logged in");

      const base = `${import.meta.env.VITE_BACKEND_URL}/dynamic-credentials`;
      const res = await fetch(
        method === "POST" ? base : `${base}/${upload.hash}`,
        {
          method,
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
          ...(method === "POST"
            ? { body: JSON.stringify({ hash: upload.hash, username, password }) }
            : {}),
        }
      );

      if (!res.ok) {
        const body = await res.json().catch(() => ({} as { error?: string }));
        throw new Error(
          res.status === 503
            ? "Credential storage isn't configured on this server."
            : body.error ?? `Could not save the test account (HTTP ${res.status})`
        );
      }

      setUsername("");
      setPassword("");
      setEditing(false);
      onChanged(); // refetch so the stored username shows
    } catch (err: any) {
      setError(err.message ?? "Something went wrong");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-3 rounded-lg border border-border bg-muted/20 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-sm">
          <KeyRound className="h-4 w-4 shrink-0 text-muted-foreground" />
          {upload.hasCredentials ? (
            <span>
              Test account:{" "}
              <span className="font-medium">{upload.credentialUsername ?? "(stored)"}</span>
            </span>
          ) : (
            <span className="text-muted-foreground">
              No test account — the run won't get past the login screen
            </span>
          )}
        </div>
        <div className="flex gap-2">
          <Button
            size="sm"
            variant="outline"
            disabled={busy}
            onClick={() => {
              setError(null);
              setEditing((e) => !e);
            }}
          >
            {editing ? "Cancel" : upload.hasCredentials ? "Change" : "Add test account"}
          </Button>
          {upload.hasCredentials && (
            <Button size="sm" variant="ghost" disabled={busy} onClick={() => submit("DELETE")}>
              Remove
            </Button>
          )}
        </div>
      </div>

      {editing && (
        <div className="space-y-2">
          <div className="grid gap-2 sm:grid-cols-2">
            <Input
              type="text"
              autoComplete="off"
              placeholder="Username or email"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
            <Input
              type="password"
              autoComplete="new-password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          <div className="flex items-center justify-between gap-2">
            <p className="text-xs leading-snug text-muted-foreground">
              <span className="font-medium text-foreground">
                We delete the account as soon as the analysis finishes.
              </span>{" "}
              Encrypted until then. Use a throwaway test account, never a real user's.
            </p>
            <Button
              size="sm"
              disabled={busy || !username.trim() || !password}
              onClick={() => submit("POST")}
            >
              {busy ? "Saving…" : "Save"}
            </Button>
          </div>
        </div>
      )}

      {error && <p className="text-sm text-amber-500">{error}</p>}
    </div>
  );
};


// Optional prop to trigger refresh from parent component
interface UploadHistoryProps {
  refreshSignal?: number;
  /** Called after an analysis spends a credit, so the header balance re-reads. */
  onCreditsChanged?: () => void;
}

const UploadHistory: React.FC<UploadHistoryProps> = ({ refreshSignal, onCreditsChanged }) => {
  const [uploads, setUploads] = useState<UploadEntry[]>([]);
  // Per-row failure message, keyed by upload id (e.g. "not enough credits").
  const [notices, setNotices] = useState<Record<string, string>>({});
  const [confirmModalOpen, setConfirmModalOpen] = useState(false);
  const [pendingDynamicUpload, setPendingDynamicUpload] = useState<UploadEntry | null>(null);
  const [isStartingDynamic, setIsStartingDynamic] = useState(false);

  // Fetch upload history from backend
  const fetchUploads = async () => {
    try {
      // Ensure token is fresh
      const token = await auth.currentUser?.getIdToken(true);  // Force token refresh
    
      if (!token) {
        console.error("No valid token found.");
        return;
      }
    
      // Send the request with the fresh token
      const res = await fetch(`${import.meta.env.VITE_BACKEND_URL}/uploads`, {
        headers: {
          "Authorization": `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });
    
      if (!res.ok) {
        console.error("Fetch uploads failed with status", res.status);
        return;
      }
    
      const data = await res.json();
      setUploads(data);
    } catch (error) {
      console.error("Error fetching uploads:", error);
    }
  };

  const requestAnalyze = (upload: UploadEntry) => {
    if (upload.analysisType === "dynamic") {
      setPendingDynamicUpload(upload);
      setConfirmModalOpen(true);
    } else {
      handleAnalyze(upload);
    }
  };

  const handleConfirmDynamic = async () => {
    if (!pendingDynamicUpload) return;
    setIsStartingDynamic(true);
    try {
      await handleAnalyze(pendingDynamicUpload);
      setConfirmModalOpen(false);
    } finally {
      setIsStartingDynamic(false);
      setPendingDynamicUpload(null);
    }
  };

  // Trigger analysis for a specific upload
  const handleAnalyze = async (upload: UploadEntry) => {
    try {
      let endpoint = "";

      if (upload.filename.endsWith(".ipa") && upload.analysisType === "static") {
        endpoint = `${import.meta.env.VITE_BACKEND_URL}/ios-static-analyze`;
      } else if (upload.filename.endsWith(".apk") && upload.analysisType === "static") {
        endpoint = `${import.meta.env.VITE_BACKEND_URL}/android-static-analyze`;
      } else if (upload.filename.endsWith(".apk") && upload.analysisType === "dynamic") {
        endpoint = `${import.meta.env.VITE_BACKEND_URL}/android-dynamic-analyze`;
      } else {
        throw new Error("File not eligible for analysis");
        return;
      }

      // Call backend analyze API
      const token = await getIdToken();
      if (!token) throw new Error("User not logged in");

      // Optimistically update status in UI immediately
      setUploads((prev) =>
        prev.map((u) =>
          u.id === upload.id
            ? { ...u, status: upload.analysisType === "dynamic" ? "starting_sandbox" : "analyzing" }
            : u
        )
      );

      const res = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ hash: upload.hash }),
      });

      // A credit is charged here, server-side, so this is where a user finds out
      // they have run out — 402 rather than a generic failure.
      if (!res.ok) {
        const body = await res.json().catch(() => ({} as { error?: string }));
        setNotices((prev) => ({
          ...prev,
          [upload.id]:
            res.status === 402
              ? "Not enough credits to run this analysis. Buy more to continue."
              : body.error ?? "Failed to trigger analysis",
        }));
        // Revert status on failure
        fetchUploads();
        return;
      }

      setNotices(({ [upload.id]: _removed, ...rest }) => rest);
      // The balance just moved; ask the header to re-read it.
      onCreditsChanged?.();
      fetchUploads();

    } catch (err) {
      console.error("Analyze error:", err);
      fetchUploads();
    }
  };

  // Trigger PDF report generation and download
  const handleReportGeneration = async (upload: UploadEntry) => {
    const token = await getIdToken();
    if (!token) throw new Error("User not logged in");

    try {
      // Call backend generate-report API
      const res = await fetch(`${import.meta.env.VITE_BACKEND_URL}/generate-report`, {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`
         },
        body: JSON.stringify({
          hash: upload.hash,
          type: upload.analysisType,
        })
      });
      if (!res.ok) throw new Error("Failed to trigger report generation");

      // The backend returns a short-lived presigned S3 URL; the PDF is downloaded
      // straight from S3 rather than streamed through the backend.
      const { url } = (await res.json()) as { url?: string };
      if (!url) throw new Error("No download URL returned");

      const link = document.createElement("a");
      link.href = url;
      // The object's Content-Disposition already carries the filename; this is the
      // hint for browsers that honour the attribute on same-navigation downloads.
      link.setAttribute("download", `${upload.filename}-${upload.analysisType}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.parentNode?.removeChild(link);
    } catch (err) {
      console.error("Report generation error:", err);
    }
  }

  // Retry analysis for errored uploads
  const handleRetry = async (upload: UploadEntry) => {
    try {
      const token = await getIdToken();
      if (!token) throw new Error("User not logged in");
      const res = await fetch(`${import.meta.env.VITE_BACKEND_URL}/retry`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
        body: JSON.stringify({ hash: upload.hash, type: upload.analysisType }),
      });
      if (!res.ok) throw new Error("Retry failed");
      fetchUploads(); // Refetch uploads to update status to pending
    } catch (err) {
      console.error("Retry error:", err);
    }
  };

  // Ensure refresh when new file is uploaded
  useEffect(() => {
    fetchUploads();
  }, [refreshSignal]);

  useEffect(() => {
    const intervalId = setInterval(fetchUploads, 10000); // Refresh every 10 seconds
    return () => clearInterval(intervalId); // Cleanup on unmount
  }, []);

  // Helper function to format status with descriptive text
  const formatStatus = (status: string) => {
    switch (status) {
      case "starting_sandbox":
        return "Starting Sandbox (Waking cloud sandbox...)";
      case "analyzing":
        return "Analyzing (Runtime detection & sampling...)";
      case "generating_report":
        return "Generating Report (Compiling dynamic report...)";
      case "done":
        return "Done";
      case "pending":
        return "Pending";
      case "error":
        return "Error";
      default:
        return status.charAt(0).toUpperCase() + status.slice(1);
    }
  };

  // Specific icon for each status
  const StatusIcon: React.FC<{ status: string }> = ({ status }) => {
    switch (status) {
      case "pending":
        return <Clock className="h-5 w-5 text-yellow-500 animate-pulse" />;
      case "starting_sandbox":
        return <Loader2 className="h-5 w-5 text-amber-500 animate-spin" />;
      case "analyzing":
        return <Loader2 className="h-5 w-5 text-blue-500 animate-spin" />;
      case "generating_report":
        return <Loader2 className="h-5 w-5 text-purple-500 animate-spin" />;
      case "done":
        return <CheckCircle className="h-5 w-5 text-green-500" />;
      case "error":
        return <AlertCircle className="h-5 w-5 text-red-500" />;
      default:
        return null;
    }
  };

  return (
    <Card className="w-full mt-4">
      <CardHeader>
        <CardTitle>Analysis History</CardTitle>
      </CardHeader>

      <CardContent>
        {/* Simple message if no uploads */}
        {uploads.length === 0 ? (
          <p>No uploads yet.</p>
        ) : (
          // Accordion for each upload entry
          <Accordion type="single" collapsible className="w-full" defaultValue="">
            {uploads.map((upload) => (
              <AccordionItem key={upload.id} value={upload.id}>
                {/* Trigger to expand/collapse each upload entry */}
                <AccordionTrigger>
                  <div className="flex justify-between items-center w-full pr-4">
                    <div className="flex items-center gap-3">
                      <FileText className="h-5 w-5 text-muted-foreground" />
                      <span className="font-medium truncate">{upload.filename}</span>
                      <Badge variant="outline" className="capitalize">{upload.analysisType}</Badge>
                    </div>
                    <div className="flex items-center gap-2 text-sm text-muted-foreground">
                      <Calendar className="h-4 w-4" />
                      {/* Format upload time, fallback to "N/A" if not available */}
                      <span>{upload.uploadTime ? new Date(upload.uploadTime).toLocaleDateString() : "N/A"}</span>
                    </div>
                  </div>
                </AccordionTrigger>

                {/* Content shown when an upload entry is expanded */}
                <AccordionContent>
                  <div className="pl-8 pr-4 py-4 space-y-2 relative">
                    <div className="flex items-center gap-2">
                      <StatusIcon status={upload.status} />
                      <span className="font-medium">{formatStatus(upload.status)}</span>
                    </div>
                    {/* Display file hash */}
                    <p>Hash: {upload.hash}</p>

                    {/* Why an APK's static report can come back thin */}
                    {upload.filename.toLowerCase().endsWith(".apk") &&
                      upload.analysisType === "static" && <PackedApkNotice />}

                    {/* Who the dynamic run signs in as, while it still can be changed */}
                    {upload.analysisType === "dynamic" &&
                      (upload.status === "pending" || upload.status === "error") && (
                        <CredentialsPanel upload={upload} onChanged={fetchUploads} />
                      )}

                    {/* Dynamic analysis running hint */}
                    {upload.analysisType === "dynamic" &&
                      ["starting_sandbox", "analyzing", "generating_report"].includes(upload.status) && (
                        <div className="rounded-lg border border-indigo-500/30 bg-indigo-500/10 p-3 text-xs text-indigo-300">
                          <div className="flex items-center gap-2 font-medium">
                            <Clock className="h-4 w-4 text-indigo-400 shrink-0" />
                            <span>Cloud sandbox is executing in background (Est. 8~10 minutes)</span>
                          </div>
                          <p className="mt-1 text-muted-foreground leading-relaxed">
                            Offline pickup supported: You can safely close or navigate away from this page. The cloud sandbox will automatically power off upon completion, and your report will be saved for download.
                          </p>
                        </div>
                      )}

                    {/* Why an analysis could not be started (e.g. no credits) */}
                    {notices[upload.id] && (
                      <p className="text-sm text-amber-500">{notices[upload.id]}</p>
                    )}

                    {/* Show analyze button */}
                    <div className="flex flex-wrap items-center justify-end gap-2">
                      {upload.status === "pending" && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => requestAnalyze(upload)}
                        >
                          {/* Already paid for — a retry of a failed run is free */}
                          {upload.creditSpent ? "Analyze" : "Analyze · 1 credit"}
                        </Button>
                      )}
                      {["starting_sandbox", "analyzing", "generating_report"].includes(upload.status) && (
                        <Button size="sm" disabled className="gap-2">
                          <Loader2 className="h-4 w-4 animate-spin" />
                          {upload.status === "starting_sandbox"
                            ? "Starting Sandbox..."
                            : upload.status === "generating_report"
                            ? "Generating Report..."
                            : "Analyzing..."}
                        </Button>
                      )}
                      {upload.status === "done" && (
                        <div className="flex flex-wrap items-center gap-2">
                          {upload.analysisType === "static" ? (
                            <>
                              <Button size="sm" onClick={() => handleReportGeneration(upload)}>
                                <FileText className="mr-1.5 h-4 w-4" />
                                Download Static Report (PDF, 36 Pages)
                              </Button>
                              {uploads.find(
                                (u) => u.hash === upload.hash && u.analysisType === "dynamic" && u.status === "done"
                              ) && (
                                <Button
                                  size="sm"
                                  variant="outline"
                                  className="border-indigo-500/40 text-indigo-400 hover:bg-indigo-500/10"
                                  onClick={() => {
                                    const dyn = uploads.find(
                                      (u) => u.hash === upload.hash && u.analysisType === "dynamic" && u.status === "done"
                                    );
                                    if (dyn) handleReportGeneration(dyn);
                                  }}
                                >
                                  <FileText className="mr-1.5 h-4 w-4 text-indigo-400" />
                                  Download Dynamic Report (PDF)
                                </Button>
                              )}
                            </>
                          ) : (
                            <>
                              <Button
                                size="sm"
                                className="bg-indigo-600 hover:bg-indigo-700 text-white"
                                onClick={() => handleReportGeneration(upload)}
                              >
                                <FileText className="mr-1.5 h-4 w-4" />
                                Download Dynamic Runtime Report (PDF)
                              </Button>
                              {uploads.find(
                                (u) => u.hash === upload.hash && u.analysisType === "static" && u.status === "done"
                              ) && (
                                <Button
                                  size="sm"
                                  variant="outline"
                                  onClick={() => {
                                    const stat = uploads.find(
                                      (u) => u.hash === upload.hash && u.analysisType === "static" && u.status === "done"
                                    );
                                    if (stat) handleReportGeneration(stat);
                                  }}
                                >
                                  <FileText className="mr-1.5 h-4 w-4" />
                                  Download Static Report (PDF, 36 Pages)
                                </Button>
                              )}
                            </>
                          )}
                        </div>
                      )}
                      {upload.status === "error" && (
                        <Button size="sm" onClick={() => handleRetry(upload)}>
                          Retry
                        </Button>
                      )}
                    </div>
                  </div>
                </AccordionContent>
              </AccordionItem>
            ))}
          </Accordion>
        )}

        <DynamicConfirmModal
          isOpen={confirmModalOpen}
          onClose={() => setConfirmModalOpen(false)}
          onConfirm={handleConfirmDynamic}
          filename={pendingDynamicUpload?.filename ?? ""}
          creditSpent={pendingDynamicUpload?.creditSpent}
          hasCredentials={pendingDynamicUpload?.hasCredentials}
          credentialUsername={pendingDynamicUpload?.credentialUsername}
          isStarting={isStartingDynamic}
        />
      </CardContent>
    </Card>
  );
};

export default UploadHistory;
