import fs from "fs";
import FormData from "form-data";
import fetch from "node-fetch";
import {
  EC2Client,
  StartInstancesCommand,
  StopInstancesCommand,
  waitUntilInstanceRunning,
} from "@aws-sdk/client-ec2";
import { downloadToTemp } from "../s3";

export type SandboxPhase =
  | "queued"
  | "starting_sandbox"
  | "analyzing"
  | "generating_pdf";

export type SandboxErrorKind =
  | "capacity"
  | "startup_failed"
  | "timeout"
  | "analysis_failed";

export class SandboxExecutionError extends Error {
  constructor(
    public readonly kind: SandboxErrorKind,
    message: string,
    public readonly cause?: unknown
  ) {
    super(message);
    this.name = "SandboxExecutionError";
  }
}

export interface DynamicJobRequest {
  s3UploadKey: string;
  filename: string;
  fileHash: string;
  credentials?: { username: string; password: string } | null;
  allowSimulationFallback?: boolean;
  onPhaseChange?: (phase: SandboxPhase) => void;
}

export interface DynamicJobOutput {
  reportData: Record<string, unknown>;
  pdfBase64: string | null;
  simulated: boolean;
}

export interface StaticJobRequest {
  platform: "android" | "ios";
  s3UploadKey: string;
  filename: string;
  fileHash: string;
  allowSimulationFallback?: boolean;
  onTaskQueued?: (taskId: string) => void;
}

export interface SandboxAdapterPort {
  runDynamicAnalysis(req: DynamicJobRequest): Promise<DynamicJobOutput>;
  runStaticAnalysis(req: StaticJobRequest): Promise<{
    reportData: Record<string, unknown>;
    simulated: boolean;
  }>;
  getQueueState(): { activeCount: number; pendingInQueue: number };
}

export interface SandboxAdapterDeps {
  ec2Client?: EC2Client;
  instanceId?: string;
  sandboxHost?: string;
  sandboxPort?: string;
  timeoutMs?: number;
  ec2Send?: (command: any) => Promise<any>;
  waitUntilRunning?: (opts: any, cmd: any) => Promise<any>;
  probeFn?: (url: string, timeoutSec: number) => Promise<boolean>;
  downloadToTempFn?: (key: string) => Promise<string>;
  fetchFn?: typeof fetch;
  staticApiAndroid?: string;
  staticApiIos?: string;
  startRetryDelayMs?: number;
  stopRetryDelayMs?: number;
  pollIntervalMs?: number;
  createReadStreamFn?: (p: string) => any;
}

export function createSandboxAdapter(deps?: SandboxAdapterDeps): SandboxAdapterPort {
  const instanceId = deps?.instanceId || process.env.DYNAMIC_SANDBOX_INSTANCE_ID || "i-019a9da9385f1e495";
  const sandboxHost = deps?.sandboxHost || process.env.DYNAMIC_SANDBOX_HOST || "172.31.22.42";
  // Default to 5002, matching docker-compose.yml
  const sandboxPort = deps?.sandboxPort || process.env.DYNAMIC_SANDBOX_PORT || "5002";
  const sandboxBaseUrl = `http://${sandboxHost}:${sandboxPort}`;
  const DYNAMIC_TIMEOUT_MS = deps?.timeoutMs ?? (3 * 60 * 1000);

  const ec2Client = deps?.ec2Client || new EC2Client({
    region: process.env.AWS_REGION || "ap-southeast-2",
  });
  const ec2Send = deps?.ec2Send || ((cmd: any) => ec2Client.send(cmd));
  const waitRunning = deps?.waitUntilRunning || ((opts: any, cmd: any) => waitUntilInstanceRunning(opts, cmd));
  const downloadFn = deps?.downloadToTempFn || downloadToTemp;
  const customFetch = deps?.fetchFn || fetch;
  const createReadStream = deps?.createReadStreamFn || ((p: string) => fs.createReadStream(p));

  const ANDROID_STATIC_API = (deps?.staticApiAndroid ?? process.env.ANDROID_STATIC_API ?? "").replace(/\/+$/, "");
  const IOS_STATIC_API = (deps?.staticApiIos ?? process.env.IOS_STATIC_API ?? "").replace(/\/+$/, "");

  // Mutex state
  let queueTail: Promise<void> = Promise.resolve();
  let pendingCount = 0;
  let activeCount = 0;

  async function probeSandbox(url: string, timeoutSec: number = 60): Promise<boolean> {
    if (deps?.probeFn) return deps.probeFn(url, timeoutSec);
    const start = Date.now();
    while (Date.now() - start < timeoutSec * 1000) {
      try {
        const res = await customFetch(url, { method: "GET", timeout: 2000 } as any);
        if (res.ok || res.status === 404 || res.status === 401) {
          return true;
        }
      } catch {
        // Retry
      }
      await new Promise((r) => setTimeout(r, 2000));
    }
    return false;
  }

  // ADR-0004: Stop instance with exponential backoff retries
  async function stopSandboxWithRetry(targetId: string): Promise<void> {
    const maxRetries = 3;
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        console.log(`[Dynamic Sandbox] Dispatching StopInstancesCommand for ${targetId} (attempt ${attempt}/${maxRetries})...`);
        await ec2Send(new StopInstancesCommand({ InstanceIds: [targetId] }));
        console.log(`[Dynamic Sandbox] StopInstancesCommand successfully acknowledged for ${targetId}.`);
        return;
      } catch (err: any) {
        console.warn(`[Dynamic Sandbox] StopInstances attempt ${attempt} failed:`, err?.message ?? err);
        if (attempt < maxRetries) {
          await new Promise((r) => setTimeout(r, attempt * (deps?.stopRetryDelayMs ?? 2000)));
        } else {
          console.error(`[CRITICAL-SANDBOX-LEAK] Failed to stop sandbox ${targetId} after ${maxRetries} attempts.`);
        }
      }
    }
  }

  async function acquireLock(onPhaseChange?: (phase: SandboxPhase) => void): Promise<() => void> {
    pendingCount++;
    const isQueued = activeCount > 0;
    if (isQueued) {
      onPhaseChange?.("queued");
      console.log(`[Dynamic Sandbox] Job queued. Current queue depth: ${pendingCount}`);
    }

    let releaseLock: () => void = () => {};
    const lockPromise = new Promise<void>((resolve) => {
      releaseLock = resolve;
    });

    const previousTail = queueTail;
    queueTail = queueTail.then(() => lockPromise);

    await previousTail;
    activeCount = 1;

    return () => {
      activeCount = 0;
      pendingCount--;
      releaseLock();
    };
  }

  return {
    getQueueState() {
      return { activeCount, pendingInQueue: Math.max(0, pendingCount - activeCount) };
    },

    async runDynamicAnalysis(req: DynamicJobRequest): Promise<DynamicJobOutput> {
      const unlock = await acquireLock(req.onPhaseChange);

      const abortController = new AbortController();
      let timeoutTimer: NodeJS.Timeout | null = null;
      let tmpPath: string | null = null;

      const timeoutPromise = new Promise<never>((_, reject) => {
        timeoutTimer = setTimeout(() => {
          abortController.abort(new Error("Dynamic analysis exceeded hard timeout"));
          reject(new SandboxExecutionError("timeout", "Dynamic analysis exceeded hard timeout"));
        }, DYNAMIC_TIMEOUT_MS);
      });

      const executeCore = async (signal: AbortSignal): Promise<DynamicJobOutput> => {
        // ── Phase 1: Startup & verification ─────────────────────────
        req.onPhaseChange?.("starting_sandbox");
        console.log(`[Dynamic Sandbox] Ensuring sandbox instance ${instanceId} is running...`);

        let startRetries = 3;
        while (startRetries > 0) {
          try {
            await ec2Send(new StartInstancesCommand({ InstanceIds: [instanceId] }));
            break;
          } catch (startErr: any) {
            const isCapacity = startErr?.name === "InsufficientInstanceCapacity";
            const isStopping = startErr?.name === "IncorrectInstanceState" || startErr?.message?.includes("stopping");

            if ((isCapacity || isStopping) && startRetries > 1) {
              console.warn(`[Dynamic Sandbox] Retrying start (${startErr?.name ?? startErr?.message}), attempts left: ${startRetries - 1}...`);
              await new Promise((r) => setTimeout(r, deps?.startRetryDelayMs ?? 10000));
              startRetries--;
            } else {
              throw new SandboxExecutionError("capacity", `Failed to start sandbox: ${startErr?.message ?? startErr}`, startErr);
            }
          }
        }

        console.log(`[Dynamic Sandbox] Waiting for instance ${instanceId} to enter 'running' state...`);
        try {
          await waitRunning({ client: ec2Client, maxWaitTime: 120 }, { InstanceIds: [instanceId] });
        } catch (waitErr: any) {
          throw new SandboxExecutionError("startup_failed", `Sandbox failed to reach running state: ${waitErr?.message ?? waitErr}`, waitErr);
        }

        console.log(`[Dynamic Sandbox] Probing sandbox API at ${sandboxBaseUrl}/...`);
        const isReady = await probeSandbox(`${sandboxBaseUrl}/`, 90);
        if (!isReady) {
          throw new SandboxExecutionError("startup_failed", `Sandbox at ${sandboxBaseUrl} not responsive within timeout`);
        }

        // ── Phase 2: Analyzing ──────────────────────────────────────
        req.onPhaseChange?.("analyzing");
        tmpPath = await downloadFn(req.s3UploadKey);

        const form = new FormData();
        const fileStream = createReadStream(tmpPath);
        form.append("file", fileStream, req.filename);
        form.append("hash", req.fileHash);

        if (req.credentials) {
          form.append("username", req.credentials.username);
          form.append("password", req.credentials.password);
        }

        console.log(`[Dynamic Sandbox] Dispatching ${req.filename} to ${sandboxBaseUrl}/analyze_dynamic`);
        const res = await customFetch(`${sandboxBaseUrl}/analyze_dynamic`, {
          method: "POST",
          body: form,
          headers: form.getHeaders(),
          signal,
        } as any);

        if (!res.ok) {
          const errBody = await res.text().catch(() => "");
          throw new SandboxExecutionError("analysis_failed", `Sandbox API request failed (${res.status}): ${errBody}`);
        }

        const responseData = (await res.json()) as any;
        const reportData = (responseData && typeof responseData === "object" && "report" in responseData)
          ? responseData.report
          : responseData;
        const pdfBase64 = (responseData && typeof responseData === "object" && "pdf_base64" in responseData)
          ? responseData.pdf_base64
          : null;

        req.onPhaseChange?.("generating_pdf");
        return { reportData, pdfBase64, simulated: false };
      };

      try {
        let result: DynamicJobOutput;
        try {
          result = await Promise.race([executeCore(abortController.signal), timeoutPromise]);
        } catch (err: any) {
          if (req.allowSimulationFallback && !(err instanceof SandboxExecutionError && err.kind === "timeout")) {
            console.warn(`[Dynamic Sandbox] Cloud sandbox unavailable (${err?.message}), using synthetic simulation.`);
            result = {
              reportData: {
                status: "success",
                filename: req.filename,
                hash: req.fileHash,
                security_score: 68,
                summary: { high: 3, medium: 2, low: 4, score: 68 },
                vulnerabilities: [
                  {
                    title: "Dynamic Crypto Misuse & Weak IV Observed",
                    severity: "high",
                    description: "Frida runtime monitoring captured AES cipher initialized with a predictable IV.",
                    cwe: "CWE-329",
                    owasp: "M5: Insufficient Cryptography",
                  },
                ],
              },
              pdfBase64: null,
              simulated: true,
            };
          } else {
            throw err;
          }
        }
        return result;
      } finally {
        if (timeoutTimer) clearTimeout(timeoutTimer);
        if (tmpPath) await fs.promises.unlink(tmpPath).catch(() => {});

        // Release the mutex lock for next queued job
        unlock();

        // Last-One-Out Stops EC2: Only shut down if no other job is queued
        if (pendingCount === 0) {
          console.log(`[Dynamic Sandbox] Queue is empty. Initiating zero-idle shutdown for ${instanceId}...`);
          await stopSandboxWithRetry(instanceId);
        } else {
          console.log(`[Dynamic Sandbox] Handing over warm instance to next queued job (${pendingCount} waiting).`);
        }
      }
    },

    async runStaticAnalysis(req: StaticJobRequest): Promise<{
      reportData: Record<string, unknown>;
      simulated: boolean;
    }> {
      const apiBase = (req.platform === "ios"
        ? (deps?.staticApiIos ?? process.env.IOS_STATIC_API ?? "")
        : (deps?.staticApiAndroid ?? process.env.ANDROID_STATIC_API ?? "")
      ).replace(/\/+$/, "");
      const submitPath = req.platform === "ios" ? "/analyze_ipa" : "/analyze_apk";

      if (!apiBase) {
        if (req.allowSimulationFallback || process.env.NODE_ENV === "test") {
          return {
            reportData: {
              status: "success",
              filename: req.filename,
              hash: req.fileHash,
              security_score: 72,
              summary: { high: 2, medium: 3, low: 5, score: 72 },
              vulnerabilities: [
                {
                  title: "Insecure Data Storage in SharedPreferences",
                  severity: "high",
                  description: "Application stores authentication tokens without encryption.",
                  cwe: "CWE-312",
                  owasp: "M2: Insecure Data Storage",
                },
              ],
            },
            simulated: true,
          };
        }
        throw new Error(`${req.platform.toUpperCase()} static API is not configured`);
      }

      const submitUrl = `${apiBase}${submitPath}`;
      console.log(`[Static Analysis] Submitting ${req.filename} to ${submitUrl}`);

      const staticTimeout = deps?.timeoutMs ?? 15000;
      let report: any = null;
      try {
        const submitRes = await customFetch(submitUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            key: req.s3UploadKey,
            hash: req.fileHash,
            filename: req.filename,
          }),
          timeout: staticTimeout,
        } as any);

        if (!submitRes.ok) {
          const errText = await submitRes.text().catch(() => "");
          throw new Error(`Wrapper submission failed (${submitRes.status}): ${errText}`);
        }

        const { job_id } = (await submitRes.json()) as { job_id: string };
        req.onTaskQueued?.(job_id);

        for (let attempt = 0; attempt < 180; attempt++) {
          await new Promise((r) => setTimeout(r, deps?.pollIntervalMs ?? 5000));
          const pollRes = await customFetch(`${apiBase}/status/${job_id}`, {
            timeout: 10000,
          } as any);
          if (!pollRes.ok) continue;

          const data = (await pollRes.json()) as any;
          if (data.status === "pending" || data.status === "running") continue;
          if (data.status === "success") {
            report = data.result;
            break;
          }
          throw new Error(`Static analysis failed: ${data.error}`);
        }
      } catch (err: any) {
        if (req.allowSimulationFallback) {
          console.warn(`[Static Analysis] Static API unreachable (${err?.message}), using synthetic result.`);
          return {
            reportData: {
              status: "success",
              filename: req.filename,
              hash: req.fileHash,
              security_score: 72,
              summary: { high: 2, medium: 3, low: 5, score: 72 },
              vulnerabilities: [
                {
                  title: "Application Debuggable Flag Enabled",
                  severity: "low",
                  description: "android:debuggable is true in AndroidManifest.xml.",
                  cwe: "CWE-215",
                  owasp: "M9: Reverse Engineering",
                },
              ],
            },
            simulated: true,
          };
        }
        throw err;
      }

      if (!report) throw new Error("Static analysis timed out after 180 attempts");
      const parsedReport = typeof report === "string" ? JSON.parse(report) : report;
      return { reportData: parsedReport, simulated: false };
    },
  };
}

export const SandboxAdapter = createSandboxAdapter();
