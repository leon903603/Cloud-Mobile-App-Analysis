import fs from "fs";
import os from "os";
import path from "path";
import crypto from "crypto";

import express, { Request, Response, Router } from "express";
import multer, { FileFilterCallback, StorageEngine } from "multer";
import rateLimit from "express-rate-limit";
import { v4 as uuidv4 } from "uuid";
import { putFile, getStream, deleteObject, objectExists, getPresignedDownloadUrl, purgeObjectAllVersions } from "./s3";
import { GuestJob, GuestJobRow, AnalysisType, FileType, JobStatus } from "./models/GuestJob";
import { getAssociatedStorageKeys } from "./services/storageHygiene";
import { dispatchGuestJob } from "./dispatch";
import { renderReportPdf } from "./pdf";
import { getTwdPerUsd } from "./fx";
import { seal, sealingAvailable } from "./secretbox";
import { verifyTurnstileToken } from "./turnstile";

export { GuestJob, GuestJobRow };

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

      // Security Check: Magic Bytes for ZIP/APK/IPA (0x50 0x4B 0x03 0x04)
      try {
        const fd = await fs.promises.open(file.path, "r");
        const header = Buffer.alloc(4);
        await fd.read(header, 0, 4, 0);
        await fd.close();
        if (
          header[0] !== 0x50 ||
          header[1] !== 0x4b ||
          header[2] !== 0x03 ||
          header[3] !== 0x04
        ) {
          await fs.promises.unlink(file.path).catch(() => {});
          res.status(400).json({
            message: "Invalid file format: must be a valid APK or IPA package (ZIP header PK\\x03\\x04 required).",
          });
          return;
        }
      } catch (checkErr) {
        console.warn("Magic bytes check warning:", checkErr);
      }

      // Include original extension in the key so analysis tools can identify it
      const ext = fileType === "ipa" ? ".ipa" : ".apk";
      const key = guestUploadKey(job.jobId, ext);
      await putFile(key, file.path);
      await fs.promises.unlink(file.path).catch(() => {});

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
      if (job.secretKey && (!clientSecret || job.secretKey !== clientSecret)) {
        res.status(403).json({ error: "forbidden", message: "Invalid or missing authorization secret." });
        return;
      }

      const { rate } = getTwdPerUsd();
      const priceUsd = Number(process.env.USD_PER_CREDIT ?? 40);
      const priceTwd = Math.round(priceUsd * rate);

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
      if (job.secretKey && job.secretKey !== clientSecret) {
        res.status(403).json({ error: "forbidden", message: "Invalid authorization secret." });
        return;
      }

      // Physical S3 file version-aware purge
      const keysToDelete = getAssociatedStorageKeys(job);
      for (const key of keysToDelete) {
        await purgeObjectAllVersions(key).catch((e) => {
          console.warn(`[discard-job] Warning purging S3 key ${key}:`, e);
        });
      }

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
      if (job.secretKey && job.secretKey !== clientSecret) {
        res.status(403).json({ error: "forbidden", message: "Invalid authorization secret." });
        return;
      }

      // Physical S3 file version-aware purge
      const keysToDelete = getAssociatedStorageKeys(job);
      for (const key of keysToDelete) {
        await purgeObjectAllVersions(key).catch((e) => {
          console.warn(`[cleanup-job] Warning purging S3 key ${key}:`, e);
        });
      }

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

        if (job.secretKey && (!clientSecret || job.secretKey !== clientSecret)) {
          continue;
        }

        const keysToDelete = getAssociatedStorageKeys(job);
        for (const key of keysToDelete) {
          await purgeObjectAllVersions(key).catch((e) => {
            console.warn(`[cleanup-old-jobs] Warning purging S3 key ${key}:`, e);
          });
        }

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

      // Verify authorization secret if job has one
      const clientSecret = (req.headers["x-guest-secret"] as string) || (req.query.secret as string);
      if (job.secretKey && (!clientSecret || job.secretKey !== clientSecret)) {
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

      if (!job.isPaid && job.downloadToken !== req.params.token) {
        res.status(403).json({ message: "Payment required to download this report." });
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
      const langSuffix = reqLang === "en" ? "_en" : "_zh";
      const langPdfKey = `guest/reports/${job.jobId}${langSuffix}.pdf`;
      const legacyPdfKey = job.reportPath || `guest/reports/${job.jobId}.pdf`;
      const jsonKey = `guest/reports/${job.jobId}.json`;

      let targetKey = "";
      if (await objectExists(langPdfKey)) {
        targetKey = langPdfKey;
      } else if (reqLang === "zh-TW" && (await objectExists(legacyPdfKey))) {
        targetKey = legacyPdfKey;
      } else if (await objectExists(jsonKey)) {
        // Render on demand for requested language
        const pdfRes = await renderReportPdf({
          reportKey: jsonKey,
          filename: `${job.filename || "security-report"}.pdf`,
          type: job.analysisType,
          lang: reqLang,
          outputKey: langPdfKey,
        });
        if (pdfRes.ok) {
          targetKey = langPdfKey;
        }
      }

      if (!targetKey) {
        targetKey = legacyPdfKey;
      }

      // Check if client expects JSON or direct redirect
      const downloadFilename = `${(job.filename || "security-report").replace(/\.[^/.]+$/, "")}-${job.analysisType}-${reqLang === "en" ? "en" : "zh"}-report.pdf`;

      // Check S3 object existence first so a missing object doesn't consume quota
      const exists = await objectExists(targetKey);
      if (!exists) {
        res.status(500).json({ message: "Report file missing." });
        return;
      }

      const decremented = GuestJob.decrementDownloadsRemaining(job.jobId);
      if (!decremented) {
        res.status(403).json({ message: "Download limit reached." });
        return;
      }

      const presignedUrl = await getPresignedDownloadUrl(targetKey, downloadFilename, 60);

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
