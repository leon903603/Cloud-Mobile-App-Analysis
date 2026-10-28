import fs from "fs";
import {
  putFile,
  putJson,
  putObject,
  objectExists,
  getPresignedDownloadUrl,
  purgeObjectAllVersions,
} from "../s3";
import { renderReportPdf } from "../pdf";

export type ReportLanguage = "zh-TW" | "en";
export type AnalysisKind = "static" | "dynamic";

export type ArtifactScope =
  | {
      role: "member";
      uid: string;
      hash: string;
      analysisType: AnalysisKind;
      filename: string;
      existingFilePath?: string | null;
      existingReportPath?: string | null;
    }
  | {
      role: "guest";
      jobId: string;
      analysisType: AnalysisKind;
      filename?: string;
      fileType?: "apk" | "ipa" | null;
      existingUploadPath?: string | null;
      existingReportPath?: string | null;
    };

export type DownloadReportError =
  | "report_json_missing"
  | "pdf_generation_failed"
  | "report_file_missing"
  | "quota_exceeded";

export type DownloadReportResult =
  | { ok: true; url: string; expiresIn: number; targetKey: string }
  | { ok: false; code: DownloadReportError; message: string };

export class InvalidBinaryError extends Error {
  code = "invalid_file_format";
  constructor(message: string = "Invalid file format: must be a valid APK or IPA package (ZIP header PK\\x03\\x04 required).") {
    super(message);
    this.name = "InvalidBinaryError";
  }
}

const DUMMY_PDF_BUFFER = Buffer.from(
  "%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>startxref\n0\n%%EOF"
);

const PREGENERATED_PDF_MAX_BYTES = 10 * 1024 * 1024;

/**
 * Decode a PDF handed over by an analysis host (base64). Anything that is not a
 * PDF, or is oversized, is dropped so the caller falls back to Lambda rendering.
 */
export function decodePregeneratedPdf(b64: string | null | undefined, label: string): Buffer | null {
  if (!b64 || typeof b64 !== "string") return null;
  const buf = Buffer.from(b64, "base64");
  if (buf.length > PREGENERATED_PDF_MAX_BYTES || buf.subarray(0, 5).toString("latin1") !== "%PDF-") {
    console.warn(`[ArtifactVault] Ignoring pre-generated ${label} PDF: not a PDF or too large (${buf.length} bytes)`);
    return null;
  }
  return buf;
}

export interface ArtifactVaultPort {
  resolveBasePaths(scope: ArtifactScope): {
    uploadKey: string;
    reportJsonKey: string;
    pdfKeyZh: string;
    pdfKeyEn: string;
    legacyPdfKey: string;
  };

  initializePendingReport(scope: ArtifactScope): Promise<string>;

  ingestUploadedBinary(
    scope: ArtifactScope,
    localTempFilePath: string
  ): Promise<{ uploadKey: string; reportJsonKey: string }>;

  storeCompletedReport(
    scope: ArtifactScope,
    reportData: unknown,
    opts?: {
      pregeneratedZhPdfBase64?: string | null;
      pregeneratedEnPdfBase64?: string | null;
      allowDummyPdfFallback?: boolean;
    }
  ): Promise<{ reportJsonKey: string; pdfKeyZh: string; pdfKeyEn: string }>;

  acquireReportDownloadUrl(params: {
    scope: ArtifactScope;
    lang: ReportLanguage;
    consumeDownloadQuota: () => boolean;
  }): Promise<DownloadReportResult>;

  purgeArtifacts(
    scope: ArtifactScope,
    opts?: { includeBinary?: boolean }
  ): Promise<{ purgedKeys: string[] }>;
}

class ArtifactVaultService implements ArtifactVaultPort {
  resolveBasePaths(scope: ArtifactScope) {
    if (scope.role === "member") {
      const uploadKey =
        scope.existingFilePath ||
        `uploads/${scope.uid}/${scope.hash}/${scope.filename}`;
      const reportJsonKey =
        scope.existingReportPath ||
        `reports/${scope.uid}/${scope.hash}/${scope.analysisType}.json`;
      const pdfKeyZh = reportJsonKey.replace(/\.json$/, "_zh.pdf");
      const pdfKeyEn = reportJsonKey.replace(/\.json$/, "_en.pdf");
      const legacyPdfKey = reportJsonKey.replace(/\.json$/, ".pdf");
      return { uploadKey, reportJsonKey, pdfKeyZh, pdfKeyEn, legacyPdfKey };
    } else {
      const ext = scope.fileType || (scope.filename?.endsWith(".ipa") ? "ipa" : "apk");
      const uploadKey =
        scope.existingUploadPath || `guest/uploads/${scope.jobId}.${ext}`;
      const reportJsonKey =
        scope.existingReportPath?.replace(/\.pdf$/, ".json") ||
        `guest/reports/${scope.jobId}.json`;
      const pdfKeyZh = `guest/reports/${scope.jobId}_zh.pdf`;
      const pdfKeyEn = `guest/reports/${scope.jobId}_en.pdf`;
      const legacyPdfKey = `guest/reports/${scope.jobId}.pdf`;
      return { uploadKey, reportJsonKey, pdfKeyZh, pdfKeyEn, legacyPdfKey };
    }
  }

  async ingestUploadedBinary(
    scope: ArtifactScope,
    localTempFilePath: string
  ): Promise<{ uploadKey: string; reportJsonKey: string }> {
    const paths = this.resolveBasePaths(scope);
    try {
      // Validate magic bytes for ZIP/APK/IPA (0x50 0x4B 0x03 0x04)
      const fd = await fs.promises.open(localTempFilePath, "r");
      const header = Buffer.alloc(4);
      await fd.read(header, 0, 4, 0);
      await fd.close();
      if (
        header[0] !== 0x50 ||
        header[1] !== 0x4b ||
        header[2] !== 0x03 ||
        header[3] !== 0x04
      ) {
        throw new InvalidBinaryError();
      }

      await putFile(paths.uploadKey, localTempFilePath);
      return { uploadKey: paths.uploadKey, reportJsonKey: paths.reportJsonKey };
    } finally {
      await fs.promises.unlink(localTempFilePath).catch(() => {});
    }
  }

  async initializePendingReport(scope: ArtifactScope): Promise<string> {
    const paths = this.resolveBasePaths(scope);
    await putJson(paths.reportJsonKey, { status: "pending" });
    return paths.reportJsonKey;
  }

  async storeCompletedReport(
    scope: ArtifactScope,
    reportData: unknown,
    opts?: {
      pregeneratedZhPdfBase64?: string | null;
      pregeneratedEnPdfBase64?: string | null;
      allowDummyPdfFallback?: boolean;
    }
  ): Promise<{ reportJsonKey: string; pdfKeyZh: string; pdfKeyEn: string }> {
    const paths = this.resolveBasePaths(scope);

    // 1. Save parsed JSON report
    await putJson(paths.reportJsonKey, reportData);

    const filenameBase = (scope.filename || "security-report").replace(/\.[^/.]+$/, "");
    const pdfType = scope.analysisType === "dynamic" ? "android-dynamic" : "static";

    // 2. Handle Traditional Chinese PDF (write both _zh.pdf and legacy .pdf for 100% cache hit)
    const zhPdf = decodePregeneratedPdf(opts?.pregeneratedZhPdfBase64, "zh-TW");
    if (zhPdf) {
      try {
        const pdfBuffer = zhPdf;
        await Promise.all([
          putObject(paths.pdfKeyZh, pdfBuffer, "application/pdf"),
          putObject(paths.legacyPdfKey, pdfBuffer, "application/pdf").catch(() => {}),
        ]);
        console.log(`[ArtifactVault] Fast Path: Saved pre-generated Chinese PDF to S3 (${pdfBuffer.length} bytes)`);
      } catch (err) {
        console.error(`[ArtifactVault] Error saving pregenerated PDF:`, err);
      }
    } else {
      try {
        const zhRes = await renderReportPdf({
          reportKey: paths.reportJsonKey,
          filename: `${filenameBase}.pdf`,
          type: pdfType,
          lang: "zh-TW",
          outputKey: paths.pdfKeyZh,
        });
        if (zhRes.ok) {
          // Keep legacy key populated concurrently for full backwards compatibility
          await renderReportPdf({
            reportKey: paths.reportJsonKey,
            filename: `${filenameBase}.pdf`,
            type: pdfType,
            lang: "zh-TW",
            outputKey: paths.legacyPdfKey,
          }).catch(() => {});
        } else if (opts?.allowDummyPdfFallback) {
          await putObject(paths.pdfKeyZh, DUMMY_PDF_BUFFER, "application/pdf").catch(() => {});
          await putObject(paths.legacyPdfKey, DUMMY_PDF_BUFFER, "application/pdf").catch(() => {});
        } else {
          throw new Error(`Failed to generate Chinese PDF report: ${zhRes.error}`);
        }
      } catch (err) {
        if (opts?.allowDummyPdfFallback) {
          console.warn(`[ArtifactVault] Warning generating Chinese PDF:`, err);
          await putObject(paths.pdfKeyZh, DUMMY_PDF_BUFFER, "application/pdf").catch(() => {});
          await putObject(paths.legacyPdfKey, DUMMY_PDF_BUFFER, "application/pdf").catch(() => {});
        } else {
          console.error(`[ArtifactVault] Error generating Chinese PDF:`, err);
          throw err;
        }
      }
    }

    // 3. English PDF: pre-generated by the analysis host (iOS), else pre-warm via Lambda
    const enPdf = decodePregeneratedPdf(opts?.pregeneratedEnPdfBase64, "en");
    if (enPdf) {
      await putObject(paths.pdfKeyEn, enPdf, "application/pdf");
      console.log(`[ArtifactVault] Fast Path: Saved pre-generated English PDF to S3 (${enPdf.length} bytes)`);
    } else {
      try {
        const enRes = await renderReportPdf({
          reportKey: paths.reportJsonKey,
          filename: `${filenameBase}-en.pdf`,
          type: pdfType,
          lang: "en",
          outputKey: paths.pdfKeyEn,
        });
        if (!enRes.ok && opts?.allowDummyPdfFallback) {
          await putObject(paths.pdfKeyEn, DUMMY_PDF_BUFFER, "application/pdf").catch(() => {});
        }
      } catch (err) {
        console.warn(`[ArtifactVault] Warning pre-warming English PDF:`, err);
        if (opts?.allowDummyPdfFallback) {
          await putObject(paths.pdfKeyEn, DUMMY_PDF_BUFFER, "application/pdf").catch(() => {});
        }
      }
    }

    return {
      reportJsonKey: paths.reportJsonKey,
      pdfKeyZh: paths.pdfKeyZh,
      pdfKeyEn: paths.pdfKeyEn,
    };
  }

  async acquireReportDownloadUrl(params: {
    scope: ArtifactScope;
    lang: ReportLanguage;
    consumeDownloadQuota: () => boolean;
  }): Promise<DownloadReportResult> {
    const { scope, lang, consumeDownloadQuota } = params;
    const paths = this.resolveBasePaths(scope);
    const targetLang = lang === "en" ? "en" : "zh-TW";
    const cleanFilename = (scope.filename || "security-report").replace(/\.[^/.]+$/, "");
    const downloadFilename = `${cleanFilename}-${scope.analysisType}-${targetLang === "en" ? "en" : "zh"}.pdf`;

    let effectiveKey = "";

    // 1. Check existing cached files on S3 (prioritize standard _zh.pdf / _en.pdf, fallback to legacy .pdf)
    if (targetLang === "en") {
      if (await objectExists(paths.pdfKeyEn)) {
        effectiveKey = paths.pdfKeyEn;
      }
    } else {
      if (await objectExists(paths.pdfKeyZh)) {
        effectiveKey = paths.pdfKeyZh;
      } else if (await objectExists(paths.legacyPdfKey)) {
        effectiveKey = paths.legacyPdfKey;
      }
    }

    // 2. On-demand rendering fallback if PDF is missing
    if (!effectiveKey) {
      const hasJson = await objectExists(paths.reportJsonKey);
      if (!hasJson) {
        return {
          ok: false,
          code: "report_json_missing",
          message: "Report JSON missing on storage",
        };
      }

      const targetKey = targetLang === "en" ? paths.pdfKeyEn : paths.pdfKeyZh;
      const pdfType = scope.analysisType === "dynamic" ? "android-dynamic" : "static";
      const renderRes = await renderReportPdf({
        reportKey: paths.reportJsonKey,
        filename: downloadFilename,
        type: pdfType,
        lang: targetLang,
        outputKey: targetKey,
      });

      if (!renderRes.ok) {
        return {
          ok: false,
          code: "pdf_generation_failed",
          message: `PDF rendering failed: ${renderRes.error}`,
        };
      }
      effectiveKey = targetKey;
    }

    // 3. Quota Safety Guard: Ensure S3 object truly exists before consuming quota
    const exists = await objectExists(effectiveKey);
    if (!exists) {
      return {
        ok: false,
        code: "report_file_missing",
        message: "Generated report file not found on storage",
      };
    }

    // 4. Atomic quota deduction
    const quotaGranted = consumeDownloadQuota();
    if (!quotaGranted) {
      return {
        ok: false,
        code: "quota_exceeded",
        message: "Download quota exhausted (max 5 downloads).",
      };
    }

    // 5. Generate ephemeral 60s Presigned URL
    const url = await getPresignedDownloadUrl(effectiveKey, downloadFilename, 60);
    return {
      ok: true,
      url,
      expiresIn: 60,
      targetKey: effectiveKey,
    };
  }

  async purgeArtifacts(
    scope: ArtifactScope,
    opts?: { includeBinary?: boolean }
  ): Promise<{ purgedKeys: string[] }> {
    const paths = this.resolveBasePaths(scope);
    const keys = new Set<string>();

    if (opts?.includeBinary !== false) {
      keys.add(paths.uploadKey);
      if (scope.role === "guest") {
        keys.add(`guest/uploads/${scope.jobId}.apk`);
        keys.add(`guest/uploads/${scope.jobId}.ipa`);
      }
    }

    keys.add(paths.reportJsonKey);
    keys.add(paths.pdfKeyZh);
    keys.add(paths.pdfKeyEn);
    keys.add(paths.legacyPdfKey);

    const purgedKeys = Array.from(keys);
    for (const key of purgedKeys) {
      await purgeObjectAllVersions(key).catch((err) => {
        console.warn(`[ArtifactVault] Warning purging S3 key ${key}:`, err?.message ?? err);
      });
    }

    return { purgedKeys };
  }

  purgeAllJobArtifacts = this.purgeArtifacts.bind(this);
}

export const ArtifactVault = new ArtifactVaultService();
