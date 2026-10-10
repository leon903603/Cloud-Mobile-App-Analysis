import { GuestJob, GuestJobRow } from "../models/GuestJob";
import { purgeObjectAllVersions } from "../s3";
import { db } from "../db";

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

      db.transaction(() => {
        GuestJob.update(job.jobId, {
          status: "expired",
          uploadPath: null,
          reportPath: null,
        });
      })();
      purgedCount++;
    }
  }

  return { scanned: activeJobs.length, purged: purgedCount };
}

/**
 * ADR-0007: Sunday Epoch System Reset & Transient Storage Purge.
 * Purges all transient guest jobs and member files created prior to the Sunday reset cutoff,
 * deleting S3 objects across all versions and cleaning database records.
 */
export async function purgeSundayEpochReset(
  cutoffMs: number = Date.now()
): Promise<{ guestPurged: number; memberFilesPurged: number }> {
  let guestPurged = 0;
  let memberFilesPurged = 0;

  // 1. Purge all guest jobs created prior to cutoff
  const allGuestJobs = db.prepare("SELECT * FROM guest_jobs WHERE status != 'expired'").all() as GuestJobRow[];
  for (const job of allGuestJobs) {
    const jobTime = job.createdAt ? new Date(job.createdAt).getTime() : 0;
    if (jobTime <= cutoffMs) {
      const keys = getAssociatedStorageKeys(job);
      for (const key of keys) {
        await purgeObjectAllVersions(key).catch((err) => {
          console.warn(`[Sunday Reset] Warning deleting key ${key}:`, err?.message ?? err);
        });
      }
      db.transaction(() => {
        GuestJob.update(job.jobId, {
          status: "expired",
          uploadPath: null,
          reportPath: null,
        });
      })();
      guestPurged++;
    }
  }

  // 2. Purge member file_meta records created prior to cutoff
  const cutoffIso = new Date(cutoffMs).toISOString();
  const oldMemberFiles = db.prepare("SELECT * FROM file_meta WHERE uploadTime <= ?").all(cutoffIso) as { id: number; filePath: string; reportPath: string }[];
  for (const file of oldMemberFiles) {
    if (file.filePath) {
      await purgeObjectAllVersions(file.filePath).catch(() => {});
    }
    if (file.reportPath) {
      await purgeObjectAllVersions(file.reportPath).catch(() => {});
    }
    db.prepare("DELETE FROM file_meta WHERE id = ?").run(file.id);
    memberFilesPurged++;
  }

  return { guestPurged, memberFilesPurged };
}

/**
 * Starts the recurring storage hygiene and Sunday reset background worker.
 */
export function startStorageHygieneSchedule(): { initialTimer: NodeJS.Timeout; intervalTimer: NodeJS.Timeout } {
  let lastSundayResetDate = "";

  const runCleanup = async () => {
    try {
      console.log("[Storage Hygiene] Scanning for expired guest jobs...");
      const result = await purgeExpiredGuestJobs();
      if (result.purged > 0) {
        console.log(`[Storage Hygiene] Successfully purged ${result.purged} expired guest job(s) from S3 & DB.`);
      }

      // Check if current time is Sunday (UTC Day 0) and hasn't run today
      const now = new Date();
      const todayDateStr = now.toISOString().slice(0, 10);
      if (now.getUTCDay() === 0 && lastSundayResetDate !== todayDateStr) {
        console.log(`[Sunday Reset] Initiating scheduled Sunday Epoch System Reset for ${todayDateStr}...`);
        const resetResult = await purgeSundayEpochReset(Date.now());
        lastSundayResetDate = todayDateStr;
        console.log(`[Sunday Reset] Completed: ${resetResult.guestPurged} guest jobs and ${resetResult.memberFilesPurged} member files purged.`);
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
