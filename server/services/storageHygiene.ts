import { GuestJob, GuestJobRow } from "../models/GuestJob";
import { purgeObjectAllVersions } from "../s3";

export const ONE_HOUR_MS = 60 * 60 * 1000;
export const UNPAID_TTL_MS = 24 * 60 * 60 * 1000;
export const PAID_TTL_MS = 48 * 60 * 60 * 1000;

/**
 * Deterministically evaluates whether a guest job has exceeded its TTL threshold.
 * - Unpaid jobs expire after 24 hours.
 * - Paid jobs expire after 48 hours.
 */
export function isJobExpired(
  job: Pick<GuestJobRow, "createdAt" | "isPaid">,
  nowMs: number = Date.now()
): boolean {
  if (!job.createdAt) return false;
  const createdAtMs = new Date(job.createdAt).getTime();
  if (isNaN(createdAtMs) || createdAtMs <= 0) return false;

  const ttl = Boolean(job.isPaid) ? PAID_TTL_MS : UNPAID_TTL_MS;
  return nowMs - createdAtMs > ttl;
}

/**
 * Computes all related S3 storage keys associated with a guest job.
 */
export function getAssociatedStorageKeys(job: Pick<GuestJobRow, "jobId" | "uploadPath" | "reportPath">): string[] {
  const keys = new Set<string>();
  if (job.uploadPath) keys.add(job.uploadPath);
  keys.add(`guest/uploads/${job.jobId}.apk`);
  keys.add(`guest/uploads/${job.jobId}.ipa`);
  if (job.reportPath) keys.add(job.reportPath);
  keys.add(`guest/reports/${job.jobId}.pdf`);
  keys.add(`guest/reports/${job.jobId}_zh.pdf`);
  keys.add(`guest/reports/${job.jobId}_en.pdf`);
  keys.add(`guest/reports/${job.jobId}.json`);
  return Array.from(keys);
}

/**
 * Sweeps active guest jobs, purges S3 artifacts for expired jobs across all versions,
 * and atomically updates database job records to 'expired'.
 */
export async function purgeExpiredGuestJobs(
  nowMs: number = Date.now()
): Promise<{ scanned: number; purged: number }> {
  const activeJobs = GuestJob.findActiveJobs();
  let purgedCount = 0;

  for (const job of activeJobs) {
    if (isJobExpired(job, nowMs)) {
      const keysToDelete = getAssociatedStorageKeys(job);
      for (const key of keysToDelete) {
        await purgeObjectAllVersions(key).catch((err) => {
          console.warn(`[Storage Hygiene] Warning deleting key ${key}:`, err?.message ?? err);
        });
      }

      GuestJob.update(job.jobId, {
        status: "expired",
        uploadPath: null,
        reportPath: null,
      });
      purgedCount++;
    }
  }

  return { scanned: activeJobs.length, purged: purgedCount };
}

/**
 * Starts the hourly recurring storage hygiene background worker.
 */
export function startStorageHygieneSchedule(): { initialTimer: NodeJS.Timeout; intervalTimer: NodeJS.Timeout } {
  const runCleanup = async () => {
    try {
      console.log("[Storage Hygiene] Scanning for expired guest jobs...");
      const result = await purgeExpiredGuestJobs();
      if (result.purged > 0) {
        console.log(`[Storage Hygiene] Successfully purged ${result.purged} expired guest job(s) from S3 & DB.`);
      }
    } catch (err) {
      console.error("[Storage Hygiene] Scheduled cleanup error:", err);
    }
  };

  // Run initial pass after 15 seconds, then repeat every hour
  const initialTimer = setTimeout(runCleanup, 15000);
  const intervalTimer = setInterval(runCleanup, ONE_HOUR_MS);

  return { initialTimer, intervalTimer };
}
