// server/tests/e2e_security_hygiene.test.ts
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
import crypto from "node:crypto";
import { app } from "../index";
import guestRoutes from "../guest_routes";
import { GuestJob } from "../models/GuestJob";
import { FileMeta } from "../models/FileMeta";
import { DynamicCredentials } from "../models/DynamicCredentials";
import { isAllowedReportKey, getPresignedDownloadUrl } from "../s3";
import { purgeExpiredGuestJobs } from "../services/storageHygiene";
import { db } from "../db";

console.log("==================================================");
console.log(" Running Security & Hygiene Hardening Integration Test");
console.log("==================================================");

async function runSecurityHygieneTest() {
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const port = (server.address() as any).port;
  const baseUrl = `http://127.0.0.1:${port}`;

  const cleanups: Array<() => Promise<void> | void> = [];

  try {
    // ─────────────────────────────────────────────────────────────────────────
    // Phase 1: Guest IDOR Isolation Defense
    // ─────────────────────────────────────────────────────────────────────────
    const legitJobId = "legit-guest-job-" + Date.now();
    const legitSecret = "legit-secret-" + crypto.randomBytes(16).toString("hex");
    const attackerSecret = "attacker-secret-" + crypto.randomBytes(16).toString("hex");

    GuestJob.create({
      jobId: legitJobId,
      analysisType: "static",
      fileHash: "hash-idor-test",
      filename: "victim.apk",
      status: "done",
      secretKey: legitSecret,
    });

    GuestJob.update(legitJobId, {
      isPaid: 1,
      downloadToken: "legit-token-12345",
      reportPath: `guest/reports/${legitJobId}.pdf`,
    });

    cleanups.push(() => {
      try {
        GuestJob.delete(legitJobId);
      } catch (_) {}
    });

    // 1a. Attacker attempts to fetch job-status with forged secret
    const attackerStatusRes = await fetch(`${baseUrl}/guest/job-status/${legitJobId}`, {
      headers: { "x-guest-secret": attackerSecret },
    });
    assert.strictEqual(
      attackerStatusRes.status,
      403,
      "Attacker with invalid secret must be blocked with 403 on job-status"
    );

    // 1b. Attacker attempts to fetch report with valid token but invalid secret
    const attackerReportRes = await fetch(`${baseUrl}/guest/report/legit-token-12345`, {
      headers: { "x-guest-secret": attackerSecret },
    });
    assert.strictEqual(
      attackerReportRes.status,
      403,
      "Attacker with invalid secret must be blocked with 403 on report download"
    );

    // 1c. Attacker attempts to discard victim's job
    const attackerDiscardRes = await fetch(`${baseUrl}/guest/discard-job`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-guest-secret": attackerSecret,
      },
      body: JSON.stringify({ jobId: legitJobId, secretKey: attackerSecret }),
    });
    assert.strictEqual(
      attackerDiscardRes.status,
      403,
      "Attacker with invalid secret must be blocked with 403 on discard-job"
    );

    console.log("✓ Phase 1: Guest IDOR defenses strictly rejected unauthorized secret accesses (403)");

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 2: Member Cross-Tenant Isolation Defense
    // ─────────────────────────────────────────────────────────────────────────
    const userA = "tenant-a-" + Date.now();
    const userB = "tenant-b-" + Date.now();
    const userAAuth = `Bearer test-token-${userA}`;
    const userBAuth = `Bearer test-token-${userB}`;

    cleanups.push(() => {
      try {
        db.prepare("DELETE FROM users WHERE id IN (?, ?)").run(userA, userB);
        db.prepare("DELETE FROM file_meta WHERE user IN (?, ?)").run(userA, userB);
        db.prepare("DELETE FROM credit_ledger WHERE uid IN (?, ?)").run(userA, userB);
      } catch (_) {}
    });

    // Init both users
    await fetch(`${baseUrl}/api/initUser`, {
      method: "POST",
      headers: { Authorization: userAAuth },
    });
    await fetch(`${baseUrl}/api/initUser`, {
      method: "POST",
      headers: { Authorization: userBAuth },
    });

    const userASha = crypto.createHash("sha256").update("user-a-secret-apk").digest("hex");
    const fileA = FileMeta.create({
      user: userA,
      filename: "user-a-proprietary.apk",
      analysisType: "static",
      filePath: `uploads/${userA}/${userASha}/app.apk`,
      reportPath: `reports/${userA}/${userASha}/static.json`,
      hash: userASha,
      status: "done",
    });

    // User B attempts to delete User A's file
    const crossDeleteRes = await fetch(`${baseUrl}/uploads/${fileA.id}`, {
      method: "DELETE",
      headers: { Authorization: userBAuth },
    });
    assert.strictEqual(
      crossDeleteRes.status,
      404,
      "Cross-tenant DELETE /uploads/:id must return 404 (file not found in caller's tenant)"
    );

    // User B attempts to generate report for User A's file hash
    const crossReportRes = await fetch(`${baseUrl}/generate-report`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: userBAuth,
      },
      body: JSON.stringify({ hash: userASha, type: "static" }),
    });
    assert.strictEqual(
      crossReportRes.status,
      404,
      "Cross-tenant POST /generate-report must return 404 (report not found in caller's tenant)"
    );

    console.log("✓ Phase 2: Member tenant isolation strictly blocked cross-tenant access (404)");

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 3: S3 Report Download Whitelist & Path Traversal Guards
    // ─────────────────────────────────────────────────────────────────────────
    const dangerousKeys = [
      "reports/../../etc/passwd",
      "guest/../uploads/secret.apk",
      "uploads/user-1/hash/app.apk",
      "reports/user-1/hash/static.json",
      "guest/uploads/job-1.apk",
      "/absolute/path/traversal.pdf",
      "reports/user/invalid-short-hash/static.pdf",
    ];

    for (const badKey of dangerousKeys) {
      assert.strictEqual(
        isAllowedReportKey(badKey),
        false,
        `Key '${badKey}' must be rejected by isAllowedReportKey`
      );
      await assert.rejects(
        async () => {
          await getPresignedDownloadUrl(badKey);
        },
        /Access denied/,
        `getPresignedDownloadUrl must reject '${badKey}'`
      );
    }

    console.log("✓ Phase 3: S3 report whitelist strictly rejected traversal, non-PDF, and binary keys");

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 4: Dynamic Credentials Security Lifecycle Sweep
    // ─────────────────────────────────────────────────────────────────────────
    if (DynamicCredentials.supported()) {
      const rowId = 888888;
      DynamicCredentials.set(rowId, {
        username: "test-user-sweep",
        password: "test-password-sweep",
      });

      assert.strictEqual(DynamicCredentials.reveal(rowId)?.username, "test-user-sweep");

      // Backdate the credential's createdAt to simulate abandonment (e.g. 50 hours ago)
      db.prepare(
        "UPDATE dynamic_credentials SET createdAt = datetime('now', '-50 hours') WHERE fileId = ?"
      ).run(rowId);

      // Execute sweep
      const sweptCount = DynamicCredentials.sweep(48);
      assert.ok(sweptCount >= 1, "Abandoned credential older than 48 hours must be swept");
      assert.strictEqual(
        DynamicCredentials.reveal(rowId),
        null,
        "Swept credential must no longer be retrievable"
      );
      console.log("✓ Phase 4: DynamicCredentials.sweep successfully purged abandoned test accounts");
    } else {
      console.log("✓ Phase 4: DynamicCredentials not configured (skipped without error)");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 5: Storage Hygiene Purge for Expired Guest Jobs
    // ─────────────────────────────────────────────────────────────────────────
    const expiredJobId = "expired-guest-" + Date.now();
    GuestJob.create({
      jobId: expiredJobId,
      analysisType: "static",
      fileHash: "hash-expired-test",
      filename: "expired.apk",
      status: "done",
    });

    db.prepare("UPDATE guest_jobs SET createdAt = datetime('now', '-30 hours') WHERE jobId = ?").run(expiredJobId);

    cleanups.push(() => {
      try {
        GuestJob.delete(expiredJobId);
      } catch (_) {}
    });

    const purged = await purgeExpiredGuestJobs();
    assert.ok(purged.purged >= 1, "Expired guest job must be swept by purgeExpiredGuestJobs");

    const afterPurgeJob = GuestJob.findByJobId(expiredJobId);
    assert.strictEqual(afterPurgeJob?.status, "expired");
    assert.strictEqual(afterPurgeJob?.uploadPath, null);
    assert.strictEqual(afterPurgeJob?.reportPath, null);
    console.log("✓ Phase 5: purgeExpiredGuestJobs transitioned expired job to 'expired' and cleared paths");

    console.log("==================================================");
    console.log(" All Security & Hygiene Hardening Tests Passed (5/5) ✅");
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

runSecurityHygieneTest().catch((err) => {
  console.error("Security & Hygiene Test Failed ❌:", err);
  process.exit(1);
});
