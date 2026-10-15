process.env.ANDROID_STATIC_API = "";
process.env.IOS_STATIC_API = "";
process.env.MOCK_PDF = "true";
import dotenv from "dotenv";
dotenv.config();
process.env.ANDROID_STATIC_API = "";
process.env.IOS_STATIC_API = "";
process.env.MOCK_PDF = "true";
if (!process.env.AWS_REGION) process.env.AWS_REGION = "ap-southeast-2";
if (!process.env.S3_BUCKET) process.env.S3_BUCKET = "cmaa-s3-islab-sydney";

import assert from "node:assert";
import http from "node:http";
import express from "express";
import { v4 as uuidv4 } from "uuid";
import guestRoutes from "../guest_routes";
import newebpayRouter, { buildTradeInfoPayload } from "../newebpay";
import { GuestJob } from "../models/GuestJob";
import { db } from "../db";

console.log("==================================================");
console.log(" Running Guest E2E Full Lifecycle Integration Test");
console.log("==================================================");

async function runGuestE2ETest() {
  // Set up Express app with real routes
  const app = express();
  app.use(express.json());
  app.use("/guest", guestRoutes);
  app.use("/api/newebpay", express.urlencoded({ extended: false }), newebpayRouter);

  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const port = (server.address() as any).port;
  const baseUrl = `http://127.0.0.1:${port}`;

  const cleanups: Array<() => Promise<void> | void> = [];

  try {
    // ─────────────────────────────────────────────────────────────────────────
    // Phase 1: Create Job
    // ─────────────────────────────────────────────────────────────────────────
    const fileHash = "e2e-hash-" + Date.now();
    const createRes = await fetch(`${baseUrl}/guest/create-job`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        analysisType: "static",
        hash: fileHash,
        fileName: "e2e-sample.apk",
      }),
    });

    assert.strictEqual(createRes.status, 200, "create-job must return 200");
    const createData = (await createRes.json()) as { jobId: string; secretKey: string };
    assert.ok(createData.jobId, "jobId must be returned");
    assert.ok(createData.secretKey, "secretKey must be returned");
    const { jobId, secretKey } = createData;

    cleanups.push(() => {
      try {
        GuestJob.delete(jobId);
      } catch (_) {}
    });

    console.log("✓ Phase 1: POST /guest/create-job created job successfully");

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 2: Upload Binary (with valid ZIP PK\x03\x04 magic bytes)
    // ─────────────────────────────────────────────────────────────────────────
    // APK/ZIP magic header: 0x50, 0x4B, 0x03, 0x04
    const validZipHeader = Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00]);
    const blob = new Blob([validZipHeader, Buffer.from("dummy-apk-data-for-e2e-test")]);

    const formData = new FormData();
    formData.append("file", blob, "e2e-sample.apk");
    formData.append("jobId", jobId);
    formData.append("fileType", "apk");
    formData.append("analysisType", "static");

    const uploadRes = await fetch(`${baseUrl}/guest/upload`, {
      method: "POST",
      headers: {
        "x-guest-secret": secretKey,
      },
      body: formData,
    });

    assert.strictEqual(uploadRes.status, 200, "upload must return 200");
    const uploadData = (await uploadRes.json()) as { success: boolean; status: string };
    assert.strictEqual(uploadData.success, true);
    assert.strictEqual(uploadData.status, "analyzing");
    console.log("✓ Phase 2: POST /guest/upload accepted valid binary and triggered analysis");

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 3: Poll for Analysis Completion (Simulation Fallback)
    // ─────────────────────────────────────────────────────────────────────────
    let jobStatus: any = null;
    for (let i = 0; i < 30; i++) {
      const statusRes = await fetch(`${baseUrl}/guest/job-status/${jobId}`, {
        headers: { "x-guest-secret": secretKey },
      });
      assert.strictEqual(statusRes.status, 200);
      jobStatus = await statusRes.json();
      if (jobStatus.status === "done" || jobStatus.status === "error") {
        break;
      }
      await new Promise((r) => setTimeout(r, 200));
    }

    assert.strictEqual(jobStatus.status, "done", "Analysis must complete with status 'done'");
    assert.strictEqual(jobStatus.isPaid, false, "Job must initially be unpaid");
    assert.ok(jobStatus.summaryPreview, "summaryPreview must be generated");
    assert.strictEqual(
      jobStatus.downloadToken,
      undefined,
      "downloadToken must remain hidden for unpaid job (IDOR protection)"
    );
    console.log("✓ Phase 3: GET /guest/job-status/:jobId reported completion with preview");

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 4: Strict Unpaid Download Protection (402 Payment Required)
    // ─────────────────────────────────────────────────────────────────────────
    // Assign a temporary token to the unpaid job in DB to verify route enforcement
    const tempUnpaidToken = "unpaid-token-" + Date.now();
    GuestJob.update(jobId, { downloadToken: tempUnpaidToken });

    const unpaidDownloadRes = await fetch(`${baseUrl}/guest/report/${tempUnpaidToken}`, {
      headers: { "x-guest-secret": secretKey },
    });
    assert.strictEqual(
      unpaidDownloadRes.status,
      402,
      "Unpaid report download must be blocked with 402 Payment Required"
    );
    console.log("✓ Phase 4: GET /guest/report/:token strictly blocked unpaid download with 402");

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 5: Payment Gateway Checkout (NewebPay guest-checkout unlock)
    // ─────────────────────────────────────────────────────────────────────────
    const checkoutRes = await fetch(`${baseUrl}/api/newebpay/guest-checkout`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-guest-secret": secretKey,
      },
      body: JSON.stringify({ jobId, receiptEmail: "visitor@example.com" }),
    });

    assert.strictEqual(checkoutRes.status, 200, "guest-checkout must return 200");
    const checkoutData = (await checkoutRes.json()) as any;
    assert.ok(checkoutData.downloadToken, "downloadToken must be issued upon payment/unlock");
    const token = checkoutData.downloadToken;

    // Verify job is now unlocked via GET /guest/job-status/:jobId
    const paidStatusRes = await fetch(`${baseUrl}/guest/job-status/${jobId}`, {
      headers: { "x-guest-secret": secretKey },
    });
    const paidStatus = (await paidStatusRes.json()) as any;
    assert.strictEqual(paidStatus.isPaid, true, "Job must now be marked as isPaid: true");
    assert.strictEqual(
      paidStatus.downloadToken,
      token,
      "downloadToken must now be revealed to authenticated visitor"
    );
    console.log("✓ Phase 5: POST /api/newebpay/guest-checkout successfully unlocked job and revealed token");

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 6: Paid Report Download & Quota Enforcement (5 downloads limit)
    // ─────────────────────────────────────────────────────────────────────────
    for (let count = 1; count <= 5; count++) {
      const dlRes = await fetch(`${baseUrl}/guest/report/${token}?json=true`, {
        headers: { "x-guest-secret": secretKey },
      });
      assert.strictEqual(
        dlRes.status,
        200,
        `Download #${count} must succeed with 200`
      );
      const dlData = (await dlRes.json()) as any;
      assert.ok(dlData.url, "Presigned download URL must be present");
      assert.strictEqual(dlData.expiresIn, 60, "Expiration must be 60 seconds");
    }

    // 6th download must be rejected with 403 (Quota exceeded)
    const exhaustedRes = await fetch(`${baseUrl}/guest/report/${token}?json=true`, {
      headers: { "x-guest-secret": secretKey },
    });
    assert.strictEqual(
      exhaustedRes.status,
      403,
      "6th download attempt must be rejected with 403 (quota exhausted)"
    );
    console.log("✓ Phase 6: GET /guest/report/:token permitted exactly 5 downloads then enforced 403 quota lock");

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 7: Discard Job & Cooldown Enforcement
    // ─────────────────────────────────────────────────────────────────────────
    const discardRes = await fetch(`${baseUrl}/guest/discard-job`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-guest-secret": secretKey,
      },
      body: JSON.stringify({ jobId, secretKey }),
    });

    assert.strictEqual(discardRes.status, 200, "discard-job must return 200");
    const discardData = (await discardRes.json()) as any;
    assert.strictEqual(discardData.success, true);
    assert.strictEqual(discardData.cooldownSeconds, 600);

    const discardedJob = GuestJob.findByJobId(jobId);
    assert.strictEqual(discardedJob?.status, "expired", "Job status must transition to 'expired'");
    assert.strictEqual(discardedJob?.uploadPath, null, "uploadPath must be cleared");
    assert.strictEqual(discardedJob?.reportPath, null, "reportPath must be cleared");

    console.log("✓ Phase 7: POST /guest/discard-job purged artifacts and initiated cooldown");

    console.log("==================================================");
    console.log(" All Guest E2E Lifecycle Tests Passed (7/7) ✅");
    console.log("==================================================");
  } finally {
    for (const cleanup of cleanups) {
      try {
        await cleanup();
      } catch (_) {}
    }
    server.close();
  }
}

runGuestE2ETest().catch((err) => {
  console.error("Guest E2E Test Failed ❌:", err);
  process.exit(1);
});
