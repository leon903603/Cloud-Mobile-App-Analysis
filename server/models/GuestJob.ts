import { db } from "../db";

export type AnalysisType = "static" | "dynamic";
export type FileType = "apk" | "ipa";
export type JobStatus = "pending" | "uploaded" | "analyzing" | "done" | "error" | "expired";

export interface GuestJobRow {
  jobId: string;
  analysisType: AnalysisType;
  fileHash: string;
  fileType: FileType | null;
  filename: string | null;
  uploadPath: string | null;
  reportPath: string | null;
  status: JobStatus;
  downloadToken: string | null;
  downloadsRemaining: number;
  createdAt: string; // ISO 8601
  expiresAt: string; // ISO 8601
  isPaid: number;    // 0 = unpaid, 1 = paid & unlocked
  paidAt: string | null;
  summaryPreview: string | null; // JSON string with { high, medium, low, score }
  secretKey: string | null;
  appUsername: string | null;
  appPassword: string | null;
  discardedAt?: string | null;
}

const GUEST_JOB_TTL_MS = 7 * 24 * 60 * 60 * 1000;

const insertStmt = db.prepare(`
  INSERT INTO guest_jobs (jobId, analysisType, fileHash, filename, status, expiresAt, secretKey, appUsername, appPassword, isPaid)
  VALUES (@jobId, @analysisType, @fileHash, @filename, @status, @expiresAt, @secretKey, @appUsername, @appPassword, 0)
`);
const findByJobIdStmt = db.prepare("SELECT * FROM guest_jobs WHERE jobId = ?");
const findByTokenStmt = db.prepare("SELECT * FROM guest_jobs WHERE downloadToken = ?");

export const GuestJob = {
  create(data: {
    jobId: string;
    analysisType: AnalysisType;
    fileHash: string;
    filename: string | null;
    status: JobStatus;
    secretKey?: string | null;
    appUsername?: string | null;
    appPassword?: string | null;
  }): void {
    insertStmt.run({
      ...data,
      secretKey: data.secretKey ?? null,
      appUsername: data.appUsername ?? null,
      appPassword: data.appPassword ?? null,
      expiresAt: new Date(Date.now() + GUEST_JOB_TTL_MS).toISOString(),
    });
  },

  findByJobId(jobId: string): GuestJobRow | undefined {
    return findByJobIdStmt.get(jobId) as GuestJobRow | undefined;
  },

  findByToken(token: string): GuestJobRow | undefined {
    return findByTokenStmt.get(token) as GuestJobRow | undefined;
  },

  findActiveJobs(): GuestJobRow[] {
    return db.prepare("SELECT * FROM guest_jobs WHERE status != 'expired'").all() as GuestJobRow[];
  },

  update(jobId: string, patch: Partial<GuestJobRow>): void {
    const keys = Object.keys(patch) as (keyof typeof patch)[];
    if (keys.length === 0) return;
    db.prepare(`UPDATE guest_jobs SET ${keys.map((k) => `${k} = ?`).join(", ")} WHERE jobId = ?`)
      .run(...keys.map((k) => patch[k]), jobId);
  },

  delete(jobId: string): void {
    db.prepare("DELETE FROM guest_jobs WHERE jobId = ?").run(jobId);
  },
};
