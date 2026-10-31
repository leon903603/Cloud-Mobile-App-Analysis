import fs from "fs";
import os from "os";
import path from "path";
import crypto from "crypto";

import express, { Request, Response, Router } from "express";
import multer, { FileFilterCallback, StorageEngine } from "multer";
import rateLimit from "express-rate-limit";
import { v4 as uuidv4 } from "uuid";
import { GuestJob, GuestJobRow, AnalysisType, FileType, JobStatus } from "./models/GuestJob";
import { dispatchGuestJob } from "./dispatch";
import { ArtifactVault } from "./services/artifactVault";
import { getTwdPerUsd } from "./fx";
import { seal, sealingAvailable } from "./secretbox";
import { verifyTurnstileToken } from "./turnstile";

export { GuestJob, GuestJobRow };

// Constant-time safe string comparison helper
function safeEqual(a?: string | null, b?: string | null): boolean {
  if (!a || !b) return false;
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
}

// ─── Multer — buffer uploads to a temp dir, then stream to S3 ──────────────────

const storage: StorageEngine = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, os.tmpdir()),
  filename: (_req, _file, cb) => cb(null, uuidv4()),
});

// S3 key schemes for the guest flow.
const guestUploadKey = (jobId: string, ext: string) => `guest/uploads/${jobId}${ext}`;

const upload = multer({
  storage,
  limits: { fileSize: 500 * 1024 * 1024 }, // 500 MB limit
  defParamCharset: "utf8",
  fileFilter: (_req: Request, file: Express.Multer.File, cb: FileFilterCallback) => {
    const allowed = [".apk", ".ipa"];
    cb(null, allowed.includes(path.extname(file.originalname).toLowerCase()));
  },
} as any);

// ─── Request body types ───────────────────────────────────────────────────────

interface CreateJobBody {
  analysisType: AnalysisType;
  hash: string;
  fileName: string;
  currentJobId?: string;
  appUsername?: string;
  appPassword?: string;
  turnstileToken?: string;
}

interface UploadBody {
  jobId: string;
  analysisType: AnalysisType;
  fileType: FileType;
  hash: string;
}

// ─── Rate Limiter (Max 10 create-job per hour per real IP) ─────────────────────

const createJobLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 requests per hour
  standardHeaders: true,
  legacyHeaders: false,
  validate: { keyGeneratorIpFallback: false, xForwardedForHeader: false },
  keyGenerator: (req: Request) => {
    const cfIp = req.headers["cf-connecting-ip"];
    if (typeof cfIp === "string" && cfIp.trim()) {
      return cfIp.trim();
    }
    return req.ip || req.socket.remoteAddress || "unknown";
  },
  handler: (_req, res) => {
    res.status(429).json({
      error: "rate_limit_exceeded",
      message: "Too many guest jobs created from this IP. The limit is 10 jobs per hour.",
    });
  },
});

// ─── Router ───────────────────────────────────────────────────────────────────

const router: Router = express.Router();

const GUEST_DISCARD_COOLDOWN_MS = 10 * 60 * 1000; // 10 minutes cooldown

// ─── GET /guest/config ────────────────────────────────────────────────────────
// Returns client-relevant public config (e.g., Turnstile site key)
router.get("/config", (_req: Request, res: Response): void => {
  res.json({
    turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || process.env.VITE_TURNSTILE_SITE_KEY || "",
  });
});

// ─── POST /guest/create-job ───────────────────────────────────────────────────
// Creates a new guest job.
// Rule 0: Human verification check (Cloudflare Turnstile, bypassed if unconfigured).
// Rule 1: If the visitor has an unpaid completed job, reject with unpaid_job_pending.
// Rule 2: If the visitor recently discarded an unpaid completed job, enforce a 10-minute cooldown.
// Rule 3: Enforces rate limit (10/hr per IP).
router.post(
  "/create-job",
  createJobLimiter,
  async (req: Request<{}, {}, CreateJobBody>, res: Response): Promise<void> => {
    try {
      const { analysisType, hash, fileName, currentJobId, appUsername, appPassword, turnstileToken } = req.body;

      if (!["static", "dynamic"].includes(analysisType)) {
        res.status(400).json({ message: "Invalid analysisType." });
        return;
      }

      // Human verification check
      const clientIp = (req.headers["cf-connecting-ip"] as string) || req.ip;
      const turnstileCheck = await verifyTurnstileToken(turnstileToken, clientIp);
      if (!turnstileCheck.ok) {
        const status = turnstileCheck.code === "missing_token" ? 400 : 403;
        res.status(status).json({ error: "turnstile_failed", message: turnstileCheck.reason });
        return;
      }

      // Check if visitor has a pending unpaid completed job or active discard cooldown
      if (currentJobId) {
        const existing = GuestJob.findByJobId(currentJobId);
        if (existing) {
          if (["analyzing", "pending", "uploaded"].includes(existing.status)) {
            res.status(409).json({
              error: "analysis_in_progress",
              message: "An analysis is already in progress for your session. Please wait until it completes.",
              jobId: existing.jobId,
            });
            return;
          }

          if (existing.status === "done" && !existing.isPaid) {
            res.status(403).json({
              error: "unpaid_job_pending",
              message: "You have a completed report awaiting payment. Please unlock or discard it before analyzing another application.",
              jobId: existing.jobId,
            });
            return;
          }

          if (existing.discardedAt) {
            const elapsed = Date.now() - new Date(existing.discardedAt).getTime();
            if (elapsed < GUEST_DISCARD_COOLDOWN_MS) {
              const remainingSec = Math.ceil((GUEST_DISCARD_COOLDOWN_MS - elapsed) / 1000);
              res.status(429).json({
                error: "cooldown_active",
                message: `Cooldown active: You recently discarded a completed report. Please wait ${remainingSec} seconds before uploading another application.`,
                remainingSeconds: remainingSec,
              });
              return;
            }
          }
        }
      }

      const jobId = uuidv4();
      const secretKey = crypto.randomBytes(24).toString("hex");

      let encryptedPassword = appPassword ? appPassword.trim() : null;
      if (encryptedPassword && sealingAvailable()) {
        try {
          encryptedPassword = seal(encryptedPassword);
        } catch (e) {
          console.warn("[create-job] Could not seal guest dynamic password, storing raw");
        }
      }

      GuestJob.create({
        jobId,
        analysisType,
        fileHash: hash,
        filename: fileName,
        status: "pending",
        secretKey,
        appUsername: appUsername ? appUsername.trim() : null,
        appPassword: encryptedPassword,
      });

      res.json({ jobId, secretKey });
    } catch (err) {
      console.error("create-job error:", err);
      res.status(500).json({ message: "Internal server error." });
    }
  }
);

// ─── POST /guest/upload ───────────────────────────────────────────────────────
// Uploads file to S3 and automatically triggers background analysis!
router.post(
  "/upload",
  upload.single("file"),
  async (req: Request<{}, {}, UploadBody>, res: Response): Promise<void> => {
    try {
      const { jobId, fileType } = req.body;
      const file = req.file;

      if (!file || !jobId) {
        res.status(400).json({ message: "Missing file or jobId." });
        return;
      }

      const job = GuestJob.findByJobId(jobId);
      if (!job || job.status !== "pending") {
        if (file && file.path) await fs.promises.unlink(file.path).catch(() => {});
        res.status(404).json({ message: "Job not found or already processed." });
        return;
      }

      // Verify authorization secret
      const clientSecret = (req.headers["x-guest-secret"] as string) || (req.body as any)?.secretKey;
      if (job.secretKey && (!clientSecret || job.secretKey !== clientSecret)) {
        if (file && file.path) await fs.promises.unlink(file.path).catch(() => {});
        res.status(403).json({ error: "forbidden", message: "Invalid or missing authorization secret." });
        return;
      }

      let key: string;
      try {
        const ingested = await ArtifactVault.ingestUploadedBinary(
          {
            role: "guest",
            jobId: job.jobId,
            analysisType: job.analysisType,
            filename: file.originalname,
          },
          file.path
        );
        key = ingested.uploadKey;
      } catch (ingestErr: any) {
        if (ingestErr.code === "invalid_file_format" || ingestErr.message?.includes("Invalid file format")) {
          res.status(400).json({
            error: "invalid_file_format",
            message: ingestErr.message,
          });
          return;
        }
        throw ingestErr;
      }

      GuestJob.update(job.jobId, {
        uploadPath: key,
        fileType,
        status: "analyzing",
      });

      // Fire and forget analysis in background
      dispatchGuestJob(job.jobId).catch((err) => {
        console.error(`[guest] Background analysis failed for ${job.jobId}:`, err);
        GuestJob.update(job.jobId, { status: "error" });
      });

      res.json({ success: true, jobId: job.jobId, status: "analyzing" });
    } catch (err) {
      console.error("upload error:", err);
      res.status(500).json({ message: "Internal server error." });
    }
  }
);

// ─── GET /guest/job-status/:jobId ─────────────────────────────────────────────
// Returns job progress, payment status, and pricing info.
// IDOR Protected: Only reveals downloadToken if paid and secretKey matches!
router.get(
  "/job-status/:jobId",
  async (req: Request<{ jobId: string }>, res: Response): Promise<void> => {
    try {
      const job = GuestJob.findByJobId(req.params.jobId);

      if (!job) {
        res.status(404).json({ message: "Job not found." });
        return;
      }

      const clientSecret = (req.headers["x-guest-secret"] as string) || (req.query.secret as string);
      const clientToken = (req.headers["x-download-token"] as string) || (req.query.token as string);

      // If client explicitly provided a secret, it must match job.secretKey
      if (clientSecret && !safeEqual(job.secretKey, clientSecret)) {
        res.status(403).json({ error: "forbidden", message: "Invalid or missing authorization secret." });
        return;
      }

      const validSecret = job.secretKey ? safeEqual(job.secretKey, clientSecret) : true;
      const validPaidToken = !!(job.isPaid && job.downloadToken && safeEqual(job.downloadToken, clientToken));

      if (!validSecret && !validPaidToken) {
        res.status(403).json({ error: "forbidden", message: "Invalid or missing authorization secret." });
        return;
      }

      const { rate } = getTwdPerUsd();
      const parsedUsd = Number(process.env.USD_PER_CREDIT);
      const priceUsd = Number.isFinite(parsedUsd) && parsedUsd > 0 ? parsedUsd : 40;
      const priceTwd = Math.round(priceUsd * rate);

      // Self-healing: if job is marked as paid but lacks downloadToken (e.g. manual DB update), generate one
      if (job.isPaid && !job.downloadToken) {
        const downloadToken = crypto.randomBytes(32).toString("hex");
        const downloadsRemaining = job.downloadsRemaining && job.downloadsRemaining > 0 ? job.downloadsRemaining : 5;
        GuestJob.update(job.jobId, {
          downloadToken,
          downloadsRemaining,
        });
        job.downloadToken = downloadToken;
        job.downloadsRemaining = downloadsRemaining;
      }

      res.json({
        jobId: job.jobId,
        filename: job.filename,
        analysisType: job.analysisType,
        status: job.status,
        isPaid: !!job.isPaid,
        priceUsd,
        priceTwd,
        summaryPreview: job.summaryPreview ? JSON.parse(job.summaryPreview) : null,
        downloadToken: job.isPaid ? job.downloadToken : undefined,
        // If returning via NewebPay ReturnURL with valid downloadToken across browsers, return secretKey to restore credentials
        secretKey: validPaidToken ? job.secretKey : undefined,
      });
    } catch (err) {
      console.error("job-status error:", err);
      res.status(500).json({ message: "Internal server error." });
    }
  }
);

// ─── POST /guest/discard-job ──────────────────────────────────────────────────
// Marks a completed unpaid job as discarded, physically deletes S3 artifacts,
// and starts the 10-minute cooldown
router.post(
  "/discard-job",
  async (req: Request<{}, {}, { jobId: string; secretKey?: string }>, res: Response): Promise<void> => {
    try {
      const { jobId, secretKey } = req.body;
      if (!jobId) {
        res.status(400).json({ message: "Missing jobId." });
        return;
      }

      const job = GuestJob.findByJobId(jobId);
      if (!job) {
        res.status(404).json({ message: "Job not found." });
        return;
      }

      // Verify secretKey if present on job
      const clientSecret = (req.headers["x-guest-secret"] as string) || secretKey;
      if (job.secretKey && !safeEqual(job.secretKey, clientSecret)) {
        res.status(403).json({ error: "forbidden", message: "Invalid authorization secret." });
        return;
      }

      // Physical S3 file version-aware purge via ArtifactVault
      await ArtifactVault.purgeAllJobArtifacts({
        role: "guest",
        jobId,
        analysisType: job.analysisType,
        existingUploadPath: job.uploadPath,
        existingReportPath: job.reportPath,
      });

      const nowIso = new Date().toISOString();
      GuestJob.update(jobId, {
        discardedAt: nowIso,
        status: "expired",
        uploadPath: null,
        reportPath: null,
      });

      res.json({
        success: true,
        cooldownSeconds: Math.round(GUEST_DISCARD_COOLDOWN_MS / 1000),
        discardedAt: nowIso,
      });
    } catch (err) {
      console.error("discard-job error:", err);
      res.status(500).json({ message: "Internal server error." });
    }
  }
);

// ─── POST /guest/cleanup-job ──────────────────────────────────────────────────
// Cleans up expired / evicted jobs when exceeding the 3-job retention limit.
// Deletes S3 files without enforcing a 10-minute user cooldown.
router.post(
  "/cleanup-job",
  async (req: Request<{}, {}, { jobId: string; secretKey?: string }>, res: Response): Promise<void> => {
    try {
      const { jobId, secretKey } = req.body;
      if (!jobId) {
        res.status(400).json({ message: "Missing jobId." });
        return;
      }

      const job = GuestJob.findByJobId(jobId);
      if (!job) {
        // Already deleted or absent
        res.json({ success: true, message: "Job already absent." });
        return;
      }

      // Verify secretKey
      const clientSecret = (req.headers["x-guest-secret"] as string) || secretKey;
      if (job.secretKey && !safeEqual(job.secretKey, clientSecret)) {
        res.status(403).json({ error: "forbidden", message: "Invalid authorization secret." });
        return;
      }

      // Physical S3 file version-aware purge via ArtifactVault
      await ArtifactVault.purgeAllJobArtifacts({
        role: "guest",
        jobId,
        analysisType: job.analysisType,
        existingUploadPath: job.uploadPath,
        existingReportPath: job.reportPath,
      });

      GuestJob.update(jobId, {
        status: "expired",
        uploadPath: null,
        reportPath: null,
      });

      res.json({ success: true, cleanedJobId: jobId });
    } catch (err) {
      console.error("cleanup-job error:", err);
      res.status(500).json({ message: "Internal server error." });
    }
  }
);

// ─── POST /guest/cleanup-old-jobs ─────────────────────────────────────────────
// Supports batch or single cleanup when exceeding the 3-job retention limit.
router.post(
  "/cleanup-old-jobs",
  async (req: Request<{}, {}, { jobId?: string; jobIds?: string[]; secretKey?: string }>, res: Response): Promise<void> => {
    try {
      const ids = Array.isArray(req.body.jobIds)
        ? req.body.jobIds
        : req.body.jobId
        ? [req.body.jobId]
        : [];

      if (ids.length === 0) {
        res.status(400).json({ message: "Missing jobId or jobIds." });
        return;
      }

      const clientSecret = (req.headers["x-guest-secret"] as string) || req.body.secretKey;
      const cleaned: string[] = [];

      for (const id of ids) {
        const job = GuestJob.findByJobId(id);
        if (!job) continue;

        if (job.secretKey && !safeEqual(job.secretKey, clientSecret)) {
          continue;
        }

        await ArtifactVault.purgeAllJobArtifacts({
          role: "guest",
          jobId: id,
          analysisType: job.analysisType,
          existingUploadPath: job.uploadPath,
          existingReportPath: job.reportPath,
        });

        GuestJob.update(id, {
          status: "expired",
          uploadPath: null,
          reportPath: null,
        });
        cleaned.push(id);
      }

      res.json({ success: true, cleanedJobIds: cleaned });
    } catch (err) {
      console.error("cleanup-old-jobs error:", err);
      res.status(500).json({ message: "Internal server error." });
    }
  }
);

// ─── GET /guest/report/:token ─────────────────────────────────────────────────
// Downloads the generated PDF report with a valid downloadToken.
router.get(
  "/report/:token",
  async (req: Request<{ token: string }>, res: Response): Promise<void> => {
    try {
      const job = GuestJob.findByToken(req.params.token);

      if (!job) {
        res.status(404).json({ message: "Report not found." });
        return;
      }

      // Verify authorization:
      const clientSecret = (req.headers["x-guest-secret"] as string) || (req.query.secret as string);

      // If client explicitly provided a secret, it must match job.secretKey
      if (clientSecret && !safeEqual(job.secretKey, clientSecret)) {
        res.status(403).json({ error: "forbidden", message: "Invalid or missing authorization secret." });
        return;
      }

      const hasValidSecret = safeEqual(job.secretKey, clientSecret);
      const hasValidDownloadToken = !!(job.isPaid && safeEqual(job.downloadToken, req.params.token));

      if (!hasValidSecret && !hasValidDownloadToken) {
        res.status(403).json({ error: "forbidden", message: "Invalid or missing authorization secret." });
        return;
      }

      if (new Date(job.expiresAt) < new Date()) {
        res.status(410).json({ message: "This report link has expired." });
        return;
      }

      if (job.status !== "done") {
        res.status(202).json({ message: "Report is not ready yet. Check back soon." });
        return;
      }

      // Strict Payment Gate: Unconditionally reject unpaid download attempts
      if (!job.isPaid) {
        res.status(402).json({ error: "payment_required", message: "Payment required to download this report." });
        return;
      }

      if (job.downloadsRemaining <= 0) {
        res.status(403).json({ message: "Download limit reached." });
        return;
      }

      if (!job.reportPath) {
        res.status(500).json({ message: "Report file missing." });
        return;
      }

      const reqLang = (req.query.lang as string) === "en" ? "en" : "zh-TW";

      const downloadResult = await ArtifactVault.acquireReportDownloadUrl({
        scope: {
          role: "guest",
          jobId: job.jobId,
          analysisType: job.analysisType as any,
          filename: job.filename || "security-report",
          fileType: job.fileType,
          existingUploadPath: job.uploadPath,
          existingReportPath: job.reportPath,
        },
        lang: reqLang as any,
        consumeDownloadQuota: () => GuestJob.decrementDownloadsRemaining(job.jobId),
      });

      if (!downloadResult.ok) {
        if (downloadResult.code === "quota_exceeded") {
          res.status(403).json({ message: "Download limit reached." });
          return;
        }
        res.status(downloadResult.code === "pdf_not_available" ? 404 : 500).json({ message: downloadResult.message || "Report file missing." });
        return;
      }

      const presignedUrl = downloadResult.url;

      const acceptHeader = req.headers.accept || "";
      if (req.query.json === "true" || acceptHeader.includes("application/json")) {
        res.json({ url: presignedUrl, expiresIn: 60 });
      } else {
        res.redirect(302, presignedUrl);
      }
    } catch (err) {
      console.error("report download error:", err);
      res.status(500).json({ message: "Internal server error." });
    }
  }
);

export default router;
