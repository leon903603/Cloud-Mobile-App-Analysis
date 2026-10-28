import { FileMeta, FileMetaRow } from "./models/FileMeta";
import { DynamicCredentials } from "./models/DynamicCredentials";
import { GuestJob, GuestJobRow } from "./models/GuestJob";
import { ArtifactVault } from "./services/artifactVault";
import { SandboxAdapter, SandboxExecutionError } from "./services/sandboxAdapter";

const isTestEnv = () => process.env.NODE_ENV === "test";

/**
 * Defensive unpacking: prevents single or double JSON serialized strings from crash in downstream PDF Lambda
 */
export function normalizeReportObject(raw: unknown): Record<string, any> {
  let current = raw;
  for (let i = 0; i < 3 && typeof current === "string"; i++) {
    try {
      current = JSON.parse(current);
    } catch {
      break;
    }
  }
  if (!current || typeof current !== "object" || Array.isArray(current)) {
    throw new Error("Invalid report data structure: expected a JSON object");
  }
  return current as Record<string, any>;
}

async function runStaticJob(fileDoc: FileMetaRow, platform: "android" | "ios") {
  FileMeta.update(fileDoc.id, { status: "analyzing" });

  const { reportData: rawReportData, pdfs } = await SandboxAdapter.runStaticAnalysis({
    platform,
    s3UploadKey: fileDoc.filePath,
    filename: fileDoc.filename,
    fileHash: fileDoc.hash,
    allowSimulationFallback: isTestEnv(),
    onTaskQueued: (taskId) => {
      FileMeta.update(fileDoc.id, { taskId });
    },
  });

  const reportData = normalizeReportObject(rawReportData);

  await ArtifactVault.storeCompletedReport(
    {
      role: "member",
      uid: fileDoc.user,
      hash: fileDoc.hash,
      analysisType: fileDoc.analysisType as any,
      filename: fileDoc.filename,
      existingFilePath: fileDoc.filePath,
      existingReportPath: fileDoc.reportPath,
    },
    reportData,
    {
      allowDummyPdfFallback: isTestEnv(),
      // iOS: zh-TW/en PDFs rendered on the Mac (the PDF Lambda only knows Android)
      pregeneratedZhPdfBase64: pdfs?.["zh-TW"],
      pregeneratedEnPdfBase64: pdfs?.en,
    }
  );

  FileMeta.update(fileDoc.id, { status: "done" });
  return reportData;
}

export async function analyzeIOSStatic(fileId: number) {
  try {
    const fileDoc = FileMeta.findById(fileId);
    if (!fileDoc) throw new Error(`No file found with id ${fileId}`);
    if (fileDoc.analysisType !== "static" || !fileDoc.filename.endsWith(".ipa"))
      throw new Error(`File ${fileDoc.filename} is not eligible for IPA static analysis`);

    return await runStaticJob(fileDoc, "ios");
  } catch (err) {
    console.error("Error in analyzeIOSStatic:", err);
    FileMeta.update(fileId, { status: "error" });
    throw err;
  }
}

export async function analyzeAndroidStatic(fileId: number) {
  try {
    const fileDoc = FileMeta.findById(fileId);
    if (!fileDoc) throw new Error(`No file found with id ${fileId}`);
    if (fileDoc.analysisType !== "static" || !fileDoc.filename.endsWith(".apk"))
      throw new Error(`File ${fileDoc.filename} is not eligible for APK static analysis`);

    return await runStaticJob(fileDoc, "android");
  } catch (err) {
    console.error("Error in analyzeAndroidStatic:", err);
    FileMeta.update(fileId, { status: "error" });
    throw err;
  }
}

export async function analyzeAndroidDynamic(fileId: number) {
  const fileDoc = FileMeta.findById(fileId);
  if (!fileDoc) throw new Error(`No file found with id ${fileId}`);
  if (fileDoc.analysisType !== "dynamic" || !fileDoc.filename.endsWith(".apk"))
    throw new Error(`File ${fileDoc.filename} is not eligible for APK dynamic analysis`);

  FileMeta.update(fileDoc.id, { status: "analyzing", taskId: "substatus:starting_sandbox" });

  try {
    const credentials = DynamicCredentials.reveal(fileDoc.id);

    const result = await SandboxAdapter.runDynamicAnalysis({
      s3UploadKey: fileDoc.filePath,
      filename: fileDoc.filename,
      fileHash: fileDoc.hash,
      credentials,
      allowSimulationFallback: isTestEnv(),
      onPhaseChange: (phase) => {
        const substatus = phase === "generating_pdf" ? "generating_report" : phase;
        FileMeta.update(fileDoc.id, { taskId: `substatus:${substatus}` });
      },
    });

    const reportData = normalizeReportObject(result.reportData);

    // Sandbox generated pdfBase64 is English, do not pass to zh path; generate dual language PDF via Lambda
    await ArtifactVault.storeCompletedReport(
      {
        role: "member",
        uid: fileDoc.user,
        hash: fileDoc.hash,
        analysisType: "dynamic",
        filename: fileDoc.filename,
        existingFilePath: fileDoc.filePath,
        existingReportPath: fileDoc.reportPath,
      },
      reportData,
      { allowDummyPdfFallback: isTestEnv() }
    );

    DynamicCredentials.remove(fileDoc.id);

    FileMeta.update(fileDoc.id, { status: "done", taskId: null });
    console.log(`[Dynamic Analysis] Analysis for file ${fileDoc.id} finished successfully.`);
    return reportData;
  } catch (err: any) {
    console.error("Error in analyzeAndroidDynamic:", err);
    let errorTag = "error:analysis_failed";
    if (err instanceof SandboxExecutionError) {
      errorTag = `error:${err.kind}`;
    }
    FileMeta.update(fileId, {
      status: "error",
      taskId: errorTag,
    });
    throw err;
  }
}

// ── Guest Analysis Helpers ─────────────────────────────────────────────────

export function extractSummaryPreview(report: any): string {
  if (!report || typeof report !== "object") {
    return JSON.stringify({ high: 1, medium: 2, low: 3, score: 78 });
  }
  let high = 0;
  let medium = 0;
  let low = 0;
  let score = 75;

  if (Array.isArray(report.vulnerabilities)) {
    high = report.vulnerabilities.filter((v: any) => v.severity === "high" || v.severity === "critical").length;
    medium = report.vulnerabilities.filter((v: any) => v.severity === "medium").length;
    low = report.vulnerabilities.filter((v: any) => v.severity === "low" || v.severity === "info").length;
    score = Math.max(20, Math.min(100, 100 - high * 15 - medium * 5));
  } else if (report.summary && typeof report.summary === "object") {
    high = report.summary.high || report.summary.critical || 0;
    medium = report.summary.medium || 0;
    low = report.summary.low || 0;
    score = report.summary.score || Math.max(20, Math.min(100, 100 - high * 15 - medium * 5));
  } else if (report.security_score !== undefined) {
    score = Number(report.security_score);
  } else if (report.findings && typeof report.findings === "object") {
    const vals = Object.values(report.findings);
    high = vals.filter((f: any) => f?.severity === "high" || f?.severity === "critical").length;
    medium = vals.filter((f: any) => f?.severity === "medium").length;
    low = vals.filter((f: any) => f?.severity === "low" || f?.severity === "info").length;
    score = Math.max(20, Math.min(100, 100 - high * 15 - medium * 5));
  }

  return JSON.stringify({ high, medium, low, score });
}

async function runGuestStaticJob(job: GuestJobRow, platform: "android" | "ios") {
  if (!job.uploadPath) throw new Error("Missing uploadPath for guest job");

  const pdfKey = `guest/reports/${job.jobId}.pdf`;

  // Restrict simulation strictly to NODE_ENV === "test"
  const { reportData: rawReportData, pdfs } = await SandboxAdapter.runStaticAnalysis({
    platform,
    s3UploadKey: job.uploadPath,
    filename: job.filename || "security-report.apk",
    fileHash: job.fileHash,
    allowSimulationFallback: isTestEnv(),
  });

  const reportData = normalizeReportObject(rawReportData);

  await ArtifactVault.storeCompletedReport(
    {
      role: "guest",
      jobId: job.jobId,
      analysisType: "static",
      filename: job.filename || "security-report.apk",
      existingUploadPath: job.uploadPath,
      existingReportPath: job.reportPath,
    },
    reportData,
    {
      allowDummyPdfFallback: isTestEnv(),
      pregeneratedZhPdfBase64: pdfs?.["zh-TW"],
      pregeneratedEnPdfBase64: pdfs?.en,
    }
  );

  GuestJob.update(job.jobId, {
    status: "done",
    reportPath: pdfKey,
    summaryPreview: extractSummaryPreview(reportData),
  });

  return reportData;
}

async function runGuestDynamicJob(job: GuestJobRow) {
  if (!job.uploadPath) throw new Error("Missing uploadPath for guest job");

  const pdfKey = `guest/reports/${job.jobId}.pdf`;
  const credentials = GuestJob.revealCredentials(job);

  // Restrict simulation strictly to NODE_ENV === "test"
  const result = await SandboxAdapter.runDynamicAnalysis({
    s3UploadKey: job.uploadPath,
    filename: job.filename || "security-report.apk",
    fileHash: job.fileHash,
    credentials,
    allowSimulationFallback: isTestEnv(),
  });

  const reportData = normalizeReportObject(result.reportData);

  await ArtifactVault.storeCompletedReport(
    {
      role: "guest",
      jobId: job.jobId,
      analysisType: "dynamic",
      filename: job.filename || "security-report.apk",
      existingUploadPath: job.uploadPath,
      existingReportPath: job.reportPath,
    },
    reportData,
    {
      allowDummyPdfFallback: isTestEnv(),
    }
  );

  GuestJob.update(job.jobId, {
    status: "done",
    reportPath: pdfKey,
    summaryPreview: extractSummaryPreview(reportData),
  });

  return reportData;
}

export async function dispatchGuestJob(jobId: string): Promise<void> {
  const job = GuestJob.findByJobId(jobId);
  if (!job) {
    console.error(`[dispatchGuestJob] Job not found: ${jobId}`);
    return;
  }

  console.log(`[dispatchGuestJob] Starting analysis for ${job.jobId} (${job.analysisType})`);
  GuestJob.update(jobId, { status: "analyzing" });

  try {
    if (job.analysisType === "static") {
      const isIpa = job.fileType === "ipa" || job.filename?.toLowerCase().endsWith(".ipa");
      await runGuestStaticJob(job, isIpa ? "ios" : "android");
    } else if (job.analysisType === "dynamic") {
      await runGuestDynamicJob(job);
    } else {
      throw new Error(`Unsupported analysisType: ${job.analysisType}`);
    }
    console.log(`[dispatchGuestJob] Analysis completed successfully for ${job.jobId}`);
  } catch (err: any) {
    console.error(`[dispatchGuestJob] Error analyzing ${job.jobId}:`, err);
    GuestJob.update(jobId, { status: "error" });
    throw err;
  }
}

// Optional CLI support
if (require.main === module) {
  const fileId = Number(process.argv[2]);
  const mode = process.argv[3];
  if (!fileId || !mode) {
    console.error("Usage: ts-node dispatch.ts <fileMetaId> <mode>");
    process.exit(1);
  }

  (async () => {
    try {
      if (mode === "ios-static") await analyzeIOSStatic(fileId);
      else if (mode === "android-static") await analyzeAndroidStatic(fileId);
      else if (mode === "android-dynamic") await analyzeAndroidDynamic(fileId);
      else throw new Error(`Unknown mode: ${mode}`);
    } catch (err) {
      console.error(err);
    }
  })();
}
