import fs from "fs";
import FormData from "form-data";
import fetch from "node-fetch";
import { FileMeta, FileMetaRow } from "./models/FileMeta";
import { DynamicCredentials } from "./models/DynamicCredentials";
import { downloadToTemp, putJson, putObject } from "./s3";
import {
  EC2Client,
  StartInstancesCommand,
  StopInstancesCommand,
  waitUntilInstanceRunning,
} from "@aws-sdk/client-ec2";
import { renderReportPdf } from "./pdf";

// Static analysis wrappers on islab53, reached over Tailscale, e.g.
//   ANDROID_STATIC_API=http://100.117.29.74:5001   (Celery queue_wrapper)
//   IOS_STATIC_API=http://100.117.29.74:8000       (ios-static-backend, RQ)
// Both speak the same contract: POST /analyze_{apk,ipa} with {key, hash, filename}
// → 202 {job_id}, then GET /status/<job_id>. The wrapper pulls the binary from S3
// itself and pre-generates reports/{uid}/{hash}/static.pdf, which /generate-report
// serves before falling back to the PDF Lambda. Trailing slashes are stripped so
// the paths join cleanly.
const ANDROID_STATIC_API = (process.env.ANDROID_STATIC_API ?? "").replace(/\/+$/, "");
const IOS_STATIC_API = (process.env.IOS_STATIC_API ?? "").replace(/\/+$/, "");

// Dynamic analysis ARM64 sandbox configuration (AWS Sydney VPC Private IP direct connect)
const DYNAMIC_SANDBOX_INSTANCE_ID = process.env.DYNAMIC_SANDBOX_INSTANCE_ID || "i-037917cfa6d87177f";
const DYNAMIC_SANDBOX_HOST = process.env.DYNAMIC_SANDBOX_HOST || "172.31.43.199";
const DYNAMIC_SANDBOX_PORT = process.env.DYNAMIC_SANDBOX_PORT || "5002";

const POLL_INTERVAL_MS = 5000;
// 180 × 5s = 15 min per static job, shared by Android and iOS. Large IPAs spend
// most of it in Ghidra; the iOS wrapper's own RQ job timeout is 3600s.
const MAX_POLL_ATTEMPTS = 180;

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

/**
 * Submit a static-analysis job to an islab53 wrapper and poll it to completion.
 * The report JSON is written to the row's reportPath; the wrapper has already
 * put static.pdf next to it.
 */
async function runStaticJob(fileDoc: FileMetaRow, api: string, submitPath: string) {
  if (!api) throw new Error(`Static analysis API for ${submitPath} is not configured`);

  FileMeta.update(fileDoc.id, { status: "analyzing" });

  // The wrapper pulls the binary from S3 itself, so we send the object key
  // (fileDoc.filePath) as JSON instead of uploading the bytes. Returns 202 + job_id.
  // The key must be uploads/{uid}/{hash}/<file>: the wrapper derives the
  // reports/{uid}/{hash}/static.pdf key from it.
  const postRes = await fetch(`${api}${submitPath}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      key: fileDoc.filePath,
      hash: fileDoc.hash,
      filename: fileDoc.filename,
    }),
  });
  if (postRes.status !== 202) throw new Error(`Enqueue failed with status ${postRes.status}`);
  const { job_id } = (await postRes.json()) as { job_id: string };
  if (!job_id) throw new Error("No job_id returned from wrapper");

  FileMeta.update(fileDoc.id, { taskId: job_id });

  // Poll /status/<job_id> until done
  let report: any = null;
  for (let attempt = 1; attempt <= MAX_POLL_ATTEMPTS; attempt++) {
    console.log(`Polling attempt ${attempt}/${MAX_POLL_ATTEMPTS} for job ${job_id}...`);
    await sleep(POLL_INTERVAL_MS);

    const statusRes = await fetch(`${api}/status/${job_id}`);
    // Failed jobs come back as HTTP 500 with {status:"failed", error} — surface
    // the real reason instead of a bare status code.
    const data = (await statusRes.json().catch(() => null)) as any;
    if (!statusRes.ok) {
      throw new Error(`Job ${job_id} failed: ${data?.error ?? `status poll returned ${statusRes.status}`}`);
    }
    if (!data) throw new Error(`Status poll for ${job_id} returned invalid JSON`);

    if (data.status === "pending" || data.status === "running") {
      console.log(`Job ${job_id} still running — step ${data.step ?? "?"}/${data.total ?? "?"}: ${data.message ?? ""}`);
      continue;
    }
    if (data.status === "success") {
      report = data.result;
      console.log(`Job ${job_id} completed successfully`);
      break;
    }
    throw new Error(`Job ${job_id} failed: ${data.error}`);
  }

  if (!report) throw new Error(`Job ${job_id} did not complete after ${MAX_POLL_ATTEMPTS} attempts`);

  // Wrapper may return the report as a JSON string or an object — store parsed JSON.
  const parsedReport = typeof report === "string" ? JSON.parse(report) : report;
  await putJson(fileDoc.reportPath, parsedReport);
  FileMeta.update(fileDoc.id, { status: "done" });

  return report;
}

// Every analyze function takes the `file_meta` row id, never the file hash. Two
// users can upload the same binary — the table is unique on (user, hash,
// analysisType), not on the hash — so a lookup by hash alone would resolve to
// whichever row was created first and analyse, and overwrite, the wrong user's
// report while the caller's own row sat in `analyzing` forever. The caller has
// already paid a credit for a specific row, so that row is what runs.
export async function analyzeIOSStatic(fileId: number) {
  try {
    const fileDoc = FileMeta.findById(fileId);
    if (!fileDoc) throw new Error(`No file found with id ${fileId}`);
    if (fileDoc.analysisType !== "static" || !fileDoc.filename.endsWith(".ipa"))
      throw new Error(`File ${fileDoc.filename} is not eligible for IPA static analysis`);

    return await runStaticJob(fileDoc, IOS_STATIC_API, "/analyze_ipa");
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

    return await runStaticJob(fileDoc, ANDROID_STATIC_API, "/analyze_apk");
  } catch (err) {
    console.error("Error in analyzeAndroidStatic:", err);
    FileMeta.update(fileId, { status: "error" });
    throw err;
  }
}

function getEC2Client(): EC2Client {
  return new EC2Client({
    region: process.env.AWS_REGION || "ap-southeast-2",
    credentials:
      process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY
        ? {
            accessKeyId: process.env.AWS_ACCESS_KEY_ID,
            secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
          }
        : undefined,
  });
}

async function probeSandbox(url: string, timeoutSec = 90): Promise<boolean> {
  const start = Date.now();
  while (Date.now() - start < timeoutSec * 1000) {
    try {
      const res = await fetch(url, { method: "GET" });
      if (res.status < 500) {
        return true;
      }
    } catch {
      // not yet responding
    }
    await sleep(3000);
  }
  return false;
}

export async function analyzeAndroidDynamic(fileId: number) {
  let tmpPath: string | null = null;
  const fileDoc = FileMeta.findById(fileId);
  if (!fileDoc) throw new Error(`No file found with id ${fileId}`);
  if (fileDoc.analysisType !== "dynamic" || !fileDoc.filename.endsWith(".apk"))
    throw new Error(`File ${fileDoc.filename} is not eligible for APK dynamic analysis`);

  const ec2 = getEC2Client();
  const instanceId = DYNAMIC_SANDBOX_INSTANCE_ID;
  const sandboxBaseUrl = `http://${DYNAMIC_SANDBOX_HOST}:${DYNAMIC_SANDBOX_PORT}`;

  try {
    // ── Phase 1: Waking up sandbox instance ───────────────────────────
    FileMeta.update(fileDoc.id, { status: "analyzing", taskId: "substatus:starting_sandbox" });
    console.log(`[Dynamic Analysis] Starting sandbox instance ${instanceId}...`);

    let startRetries = 3;
    while (startRetries > 0) {
      try {
        await ec2.send(new StartInstancesCommand({ InstanceIds: [instanceId] }));
        console.log(`[Dynamic Analysis] Waiting for instance ${instanceId} to reach running state...`);
        await waitUntilInstanceRunning(
          { client: ec2, maxWaitTime: 120 },
          { InstanceIds: [instanceId] }
        );
        console.log(`[Dynamic Analysis] Sandbox instance ${instanceId} is running. Probing ${sandboxBaseUrl}...`);
        break;
      } catch (startErr: any) {
        startRetries--;
        const isCapacityErr = String(startErr).includes("InsufficientInstanceCapacity") || startErr?.name === "InsufficientInstanceCapacity";
        if (isCapacityErr && startRetries > 0) {
          console.warn(`[Dynamic Analysis] EC2 capacity busy. Retrying start instance in 10s... (${startRetries} attempts left)`);
          await new Promise((r) => setTimeout(r, 10000));
        } else {
          console.error(`[Dynamic Analysis] Failed to start EC2 instance:`, startErr);
          FileMeta.update(fileDoc.id, {
            status: "error",
            taskId: isCapacityErr ? "error:capacity" : "error:startup_failed",
          });
          throw new Error(`Failed to start sandbox instance: ${startErr}`);
        }
      }
    }

    const isReady = await probeSandbox(`${sandboxBaseUrl}/`, 90);
    if (!isReady) {
      throw new Error(`Sandbox service at ${sandboxBaseUrl} did not become ready within 90s`);
    }
    console.log(`[Dynamic Analysis] Sandbox is responsive. Dispatching analysis...`);

    // ── Phase 2: Running dynamic analysis & Frida sampling ────────────
    FileMeta.update(fileDoc.id, { status: "analyzing", taskId: "substatus:analyzing" });

    const credentials = DynamicCredentials.reveal(fileDoc.id);
    tmpPath = await downloadToTemp(fileDoc.filePath);

    const form = new FormData();
    const fileStream = fs.createReadStream(tmpPath);
    form.append("file", fileStream, fileDoc.filename);
    form.append("hash", fileDoc.hash);
    if (credentials) {
      form.append("username", credentials.username);
      form.append("password", credentials.password);
    }
    console.log(
      `[Dynamic Analysis] Dispatching ${fileDoc.filename} to ${sandboxBaseUrl}/analyze_dynamic (test account: ${credentials ? "provided" : "none"})`
    );

    const res = await fetch(`${sandboxBaseUrl}/analyze_dynamic`, {
      method: "POST",
      body: form,
      headers: form.getHeaders(),
    });

    if (!res.ok) {
      const errBody = await res.text().catch(() => "");
      throw new Error(`Analysis API request failed with status ${res.status}: ${errBody}`);
    }

    // ── Phase 3: Generating report & saving to S3 ────────────────────
    FileMeta.update(fileDoc.id, { status: "analyzing", taskId: "substatus:generating_report" });
    const responseData = (await res.json()) as any;

    // Handle both wrapped response ({ report, pdf_base64 }) and raw report JSON
    let reportData = responseData;
    let pdfBase64: string | null = null;
    if (responseData && typeof responseData === "object" && "report" in responseData) {
      reportData = responseData.report;
      pdfBase64 = responseData.pdf_base64 ?? null;
    }

    console.log(
      `[Dynamic Analysis] Response parsed: has pdf_base64=${!!pdfBase64} (${pdfBase64 ? pdfBase64.length : 0} chars), response keys: ${Object.keys(responseData || {})}`
    );

    // 1. Save JSON Report
    await putJson(fileDoc.reportPath, reportData);

    // 2. Render dynamic PDF via Dedicated Dynamic Lambda (or save pre-generated if available)
    const pdfKey = fileDoc.reportPath.replace(/\.json$/, ".pdf");
    if (pdfBase64) {
      try {
        const pdfBuffer = Buffer.from(pdfBase64, "base64");
        await putObject(pdfKey, pdfBuffer, "application/pdf");
        console.log(`[Dynamic Analysis] Fast Path: Saved pre-generated PDF to S3 key ${pdfKey} (${pdfBuffer.length} bytes)`);
      } catch (pdfSaveErr) {
        console.error(`[Dynamic Analysis] Warning: Failed to save PDF to S3:`, pdfSaveErr);
      }
    } else {
      try {
        console.log(`[Dynamic Analysis] Invoking Dynamic PDF Lambda for ${fileDoc.filename}...`);
        const pdfRes = await renderReportPdf({
          reportKey: fileDoc.reportPath,
          filename: `${fileDoc.filename}.pdf`,
          type: "android-dynamic",
          outputKey: pdfKey,
        });
        if (pdfRes.ok) {
          console.log(`[Dynamic Analysis] Dynamic PDF Lambda generated PDF successfully (${pdfRes.bytes} bytes)`);
        } else {
          console.warn(`[Dynamic Analysis] Warning: Dynamic PDF Lambda failed: ${pdfRes.error}`);
        }
      } catch (lambdaErr) {
        console.warn(`[Dynamic Analysis] Warning invoking PDF Lambda:`, lambdaErr);
      }
    }

    DynamicCredentials.remove(fileDoc.id);

    // ── Phase 4: Done ────────────────────────────────────────────────
    FileMeta.update(fileDoc.id, { status: "done", taskId: null });
    console.log(`[Dynamic Analysis] Analysis for file ${fileDoc.id} finished successfully.`);

    return reportData;

  } catch (err) {
    console.error("Error in analyzeAndroidDynamic:", err);
    FileMeta.update(fileId, { status: "error" });
    throw err;
  } finally {
    if (tmpPath) await fs.promises.unlink(tmpPath).catch(() => {});

    // ── STRICT ZERO-IDLE-COST POLICY: Always shut down the sandbox instance ──
    try {
      console.log(`[Dynamic Analysis] Ensuring sandbox instance ${instanceId} is stopped...`);
      await ec2.send(new StopInstancesCommand({ InstanceIds: [instanceId] }));
      console.log(`[Dynamic Analysis] StopInstances command successfully dispatched for ${instanceId}.`);
    } catch (stopErr) {
      console.error(`[Dynamic Analysis] WARNING: Failed to stop sandbox instance ${instanceId}:`, stopErr);
    }
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
