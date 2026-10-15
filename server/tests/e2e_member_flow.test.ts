// server/tests/e2e_member_flow.test.ts
process.env.NODE_ENV = "test";
process.env.TEST_MODE = "true";
process.env.ANDROID_STATIC_API = "";
process.env.IOS_STATIC_API = "";
process.env.MOCK_PDF = "true";
import dotenv from "dotenv";
dotenv.config();
process.env.NODE_ENV = "test";
process.env.TEST_MODE = "true";
process.env.ANDROID_STATIC_API = "";
process.env.IOS_STATIC_API = "";
process.env.MOCK_PDF = "true";
if (!process.env.AWS_REGION) process.env.AWS_REGION = "ap-southeast-2";
if (!process.env.S3_BUCKET) process.env.S3_BUCKET = "cmaa-s3-islab-sydney";

import assert from "node:assert";
import http from "node:http";
import { app } from "../index";
import { CreditBank } from "../services/creditBank";
import { FileMeta } from "../models/FileMeta";
import { db } from "../db";

console.log("==================================================");
console.log(" Running Member E2E Full Lifecycle Integration Test");
console.log("==================================================");

async function runMemberE2ETest() {
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const port = (server.address() as any).port;
  const baseUrl = `http://127.0.0.1:${port}`;

  const TEST_UID = "member-e2e-uid-" + Date.now();
  const authHeader = `Bearer test-token-${TEST_UID}`;

  const cleanups: Array<() => Promise<void> | void> = [];

  try {
    // ─────────────────────────────────────────────────────────────────────────
    // Phase 1: User Initialization (SIGNUP_CREDITS default = 0)
    // ─────────────────────────────────────────────────────────────────────────
    const initRes = await fetch(`${baseUrl}/api/initUser`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: authHeader,
      },
    });

    assert.strictEqual(initRes.status, 200, "initUser must return 200");
    const initData = (await initRes.json()) as any;
    assert.strictEqual(initData.uid, TEST_UID);
    assert.strictEqual(initData.credits, 0, "New account defaults to 0 credits (free signup credits withdrawn)");

    cleanups.push(() => {
      try {
        db.prepare("DELETE FROM users WHERE id = ?").run(TEST_UID);
        db.prepare("DELETE FROM file_meta WHERE user = ?").run(TEST_UID);
        db.prepare("DELETE FROM credit_ledger WHERE uid = ?").run(TEST_UID);
        db.prepare("DELETE FROM credit_audit_events WHERE uid = ?").run(TEST_UID);
      } catch (_) {}
    });

    // Verify GET /api/getCredits confirms 0 balance
    const zeroCreditsRes = await fetch(`${baseUrl}/api/getCredits`, {
      headers: { Authorization: authHeader },
    });
    assert.strictEqual(zeroCreditsRes.status, 200);
    const zeroCreditsData = (await zeroCreditsRes.json()) as any;
    assert.strictEqual(zeroCreditsData.credits, 0);
    console.log("✓ Phase 1: POST /api/initUser initialized user with 0 default credits");

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 2: Zero-Credit Gate (requireCredits Guard)
    // ─────────────────────────────────────────────────────────────────────────
    const validZipHeader = Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00]);
    const blob1 = new Blob([validZipHeader, Buffer.from("dummy-member-apk-bytes")]);

    const zeroFormData = new FormData();
    zeroFormData.append("file", blob1, "member-sample.apk");
    zeroFormData.append("type", "static");
    zeroFormData.append("hash", "hash-zero-credit-" + Date.now());

    const blockedUploadRes = await fetch(`${baseUrl}/upload`, {
      method: "POST",
      headers: { Authorization: authHeader },
      body: zeroFormData,
    });
    assert.strictEqual(
      blockedUploadRes.status,
      402,
      "Upload when balance is 0 must be blocked with 402 (requireCredits guard)"
    );
    console.log("✓ Phase 2: requireCredits guard rejected upload when balance was 0 (402)");

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 3: Credit Purchase / Grant via CreditBank
    // ─────────────────────────────────────────────────────────────────────────
    const orderNo = "ORDER-E2E-" + Date.now();
    const grantRes = await CreditBank.grantPurchase({
      uid: TEST_UID,
      credits: 1,
      orderNo,
      twdAmt: 1200,
    });
    assert.strictEqual(grantRes.ok, true, "grantPurchase must succeed");
    assert.strictEqual(grantRes.balance, 1, "Balance must become 1 after grant");

    const creditsRes = await fetch(`${baseUrl}/api/getCredits`, {
      headers: { Authorization: authHeader },
    });
    assert.strictEqual(creditsRes.status, 200);
    assert.strictEqual((await creditsRes.json()).credits, 1);
    console.log("✓ Phase 3: CreditBank.grantPurchase successfully credited 1 credit to user");

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 4: Binary Upload via POST /upload with Active Credit
    // ─────────────────────────────────────────────────────────────────────────
    const crypto = await import("node:crypto");
    const fileHash = crypto.createHash("sha256").update("member-sample-" + Date.now()).digest("hex");
    const blob2 = new Blob([validZipHeader, Buffer.from("dummy-member-apk-bytes-2")]);

    const uploadFormData = new FormData();
    uploadFormData.append("file", blob2, "member-sample.apk");
    uploadFormData.append("type", "static");
    uploadFormData.append("hash", fileHash);

    const uploadRes = await fetch(`${baseUrl}/upload`, {
      method: "POST",
      headers: { Authorization: authHeader },
      body: uploadFormData,
    });

    assert.strictEqual(uploadRes.status, 200, "POST /upload must return 200 with credit");
    const uploadData = (await uploadRes.json()) as any;
    assert.strictEqual(uploadData.message, "File uploaded");
    assert.ok(uploadData.meta?.id, "FileMeta id must be returned");
    const fileId = uploadData.meta.id;

    const fileInDb = FileMeta.findById(fileId);
    assert.ok(fileInDb);
    assert.strictEqual(fileInDb.status, "pending");
    assert.strictEqual(fileInDb.creditSpent, 0, "creditSpent must be 0 prior to analysis");
    console.log("✓ Phase 4: POST /upload ingested binary and registered FileMeta");

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 5: Trigger Analysis with Atomic Credit Deduction
    // ─────────────────────────────────────────────────────────────────────────
    const analyzeRes = await fetch(`${baseUrl}/android-static-analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: authHeader,
      },
      body: JSON.stringify({ hash: fileHash }),
    });

    assert.strictEqual(analyzeRes.status, 200, "analyze must return 200");
    const analyzeData = (await analyzeRes.json()) as any;
    assert.strictEqual(analyzeData.remainingCredits, 0, "Remaining credits must be 0 after deduction");

    // Verify balance in CreditBank
    const currentBalance = await CreditBank.getBalance(TEST_UID);
    assert.strictEqual(currentBalance, 0, "User balance must be 0 in CreditBank");

    const analyzingFile = FileMeta.findById(fileId);
    assert.strictEqual(analyzingFile?.creditSpent, 1, "creditSpent must be marked as 1");

    // Poll for analysis completion
    let completedFile: any = null;
    for (let i = 0; i < 20; i++) {
      completedFile = FileMeta.findById(fileId);
      if (completedFile?.status === "done" || completedFile?.status === "error") {
        break;
      }
      await new Promise((r) => setTimeout(r, 200));
    }
    assert.strictEqual(completedFile?.status, "done", "File status must transition to 'done'");
    console.log("✓ Phase 5: POST /android-static-analyze deducted credit atomically and completed");

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 6: Generate Report & Quota Decrement
    // ─────────────────────────────────────────────────────────────────────────
    const initialDownloads = completedFile.downloadsRemaining ?? 5;

    const reportRes = await fetch(`${baseUrl}/generate-report`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: authHeader,
      },
      body: JSON.stringify({
        hash: fileHash,
        type: "static",
        lang: "zh-TW",
      }),
    });

    assert.strictEqual(reportRes.status, 200, "generate-report must return 200");
    const reportData = (await reportRes.json()) as any;
    assert.ok(reportData.url, "Presigned download URL must be returned");

    const afterReportFile = FileMeta.findById(fileId);
    assert.strictEqual(
      afterReportFile?.downloadsRemaining,
      initialDownloads - 1,
      "downloadsRemaining must be decremented by 1 upon acquiring download URL"
    );
    console.log("✓ Phase 6: POST /generate-report issued download URL and decremented quota");

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 7: Credit Refund and Duplicate Refund Protection
    // ─────────────────────────────────────────────────────────────────────────
    // Grant 1 credit for refund testing
    const refundOrderNo = "ORDER-REFUND-" + Date.now();
    await CreditBank.grantPurchase({
      uid: TEST_UID,
      credits: 1,
      orderNo: refundOrderNo,
      twdAmt: 1200,
    });

    const mockFileId = 99999;
    const charge = await CreditBank.chargeForAnalysis({
      uid: TEST_UID,
      fileId: mockFileId,
      label: "Crash test",
    });
    assert.strictEqual(charge.ok, true);
    assert.strictEqual(charge.balance, 0);

    const refundRes = await CreditBank.refundFailedAnalysis({
      uid: TEST_UID,
      fileId: mockFileId,
      chargeRef: charge.chargeRef,
      reasonNote: "Simulated engine crash",
    });
    assert.strictEqual(refundRes.ok, true);
    assert.strictEqual(refundRes.balance, 1, "Balance must be restored to 1 upon refund");

    // Duplicate refund must be blocked
    const dupRefundRes = await CreditBank.refundFailedAnalysis({
      uid: TEST_UID,
      fileId: mockFileId,
      chargeRef: charge.chargeRef,
      reasonNote: "Second duplicate refund attempt",
    });
    assert.strictEqual(dupRefundRes.ok, false);
    assert.strictEqual(dupRefundRes.code, "duplicate_transaction");
    console.log("✓ Phase 7: Credit refund and duplicate refund guard verified");

    console.log("==================================================");
    console.log(" All Member E2E Lifecycle Tests Passed (7/7) ✅");
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

runMemberE2ETest().catch((err) => {
  console.error("Member E2E Test Failed ❌:", err);
  process.exit(1);
});
