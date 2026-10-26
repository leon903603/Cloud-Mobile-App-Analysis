import assert from "assert";
import crypto from "crypto";
import express from "express";
import { Server } from "http";
import { AddressInfo } from "net";
import fs from "fs";
import path from "path";

const TEST_DB_PATH = path.join(
  __dirname,
  `../data/test_http_${Date.now()}_${Math.random().toString(36).slice(2)}.db`
);
process.env.SQLITE_PATH = TEST_DB_PATH;

process.env.NODE_ENV = "test";
process.env.TURNSTILE_SECRET_KEY = "";
process.env.NEWEBPAY_MERCHANT_ID = "MOCK_MERCHANT";
process.env.NEWEBPAY_HASH_KEY = "12345678901234567890123456789012";
process.env.NEWEBPAY_HASH_IV = "1234567890123456";
if (!process.env.DYNAMIC_CRED_KEY || process.env.DYNAMIC_CRED_KEY.trim().length < 32) {
  process.env.DYNAMIC_CRED_KEY =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
}

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { db } = require("../db");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const guestRoutes = require("../guest_routes").default;
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { GuestJob } = require("../models/GuestJob");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const newebpayRouter = require("../newebpay").default;
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { ArtifactVault } = require("../services/artifactVault");

const HASH_KEY = process.env.NEWEBPAY_HASH_KEY!;
const HASH_IV = process.env.NEWEBPAY_HASH_IV!;

function buildSignedWebhookPayload(innerPayload: Record<string, unknown>) {
  const plain = JSON.stringify(innerPayload);
  const cipher = crypto.createCipheriv("aes-256-cbc", HASH_KEY, HASH_IV);
  const TradeInfo = cipher.update(plain, "utf8", "hex") + cipher.final("hex");
  const TradeSha = crypto
    .createHash("sha256")
    .update(`HashKey=${HASH_KEY}&${TradeInfo}&HashIV=${HASH_IV}`)
    .digest("hex")
    .toUpperCase();
  return { TradeInfo, TradeSha };
}

async function runTests() {
  console.log("==================================================");
  console.log(" Running HTTP Routes & NewebPay Webhook Regression");
  console.log("==================================================");

  const originalPurgeAll = ArtifactVault.purgeAllJobArtifacts;
  ArtifactVault.purgeAllJobArtifacts = async () => ({ purgedKeys: [] });

  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));
  app.use("/guest", guestRoutes);
  app.use("/api/newebpay", newebpayRouter);

  const server: Server = await new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });

  const { port } = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${port}`;
  const createdJobIds: string[] = [];
  const createdOrderNos: string[] = [];

  try {
    // 1. Create initial guest job & verify 409 session conflict
    const createRes = await fetch(`${baseUrl}/guest/create-job`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        analysisType: "static",
        hash: "a".repeat(64),
        fileName: "sample.apk",
      }),
    });
    assert.strictEqual(createRes.status, 200);
    const { jobId, secretKey } = (await createRes.json()) as { jobId: string; secretKey: string };
    assert(jobId && secretKey);
    createdJobIds.push(jobId);

    const conflictRes = await fetch(`${baseUrl}/guest/create-job`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        analysisType: "static",
        hash: "b".repeat(64),
        fileName: "second.apk",
        currentJobId: jobId,
      }),
    });
    assert.strictEqual(conflictRes.status, 409, "In-progress session must return 409");
    console.log("✓ Test 1: POST /guest/create-job 409 session conflict gate verified");

    // 2. Unpaid 'done' state: 403 unpaid block, timing-safe IDOR & 402 download gate
    const preassignedToken = crypto.randomBytes(32).toString("hex");
    GuestJob.update(jobId, {
      status: "done",
      isPaid: 0,
      reportPath: `guest/reports/${jobId}.pdf`,
      downloadToken: preassignedToken,
    });

    const unpaidBlockRes = await fetch(`${baseUrl}/guest/create-job`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        analysisType: "static",
        hash: "c".repeat(64),
        fileName: "third.apk",
        currentJobId: jobId,
      }),
    });
    assert.strictEqual(unpaidBlockRes.status, 403, "Unpaid completed job must return 403");

    const idorStatusRes = await fetch(`${baseUrl}/guest/job-status/${jobId}`, {
      headers: { "x-guest-secret": "wrong-secret-key" },
    });
    assert.strictEqual(idorStatusRes.status, 403, "Wrong secretKey must return 403");

    const validStatusRes = await fetch(`${baseUrl}/guest/job-status/${jobId}`, {
      headers: { "x-guest-secret": secretKey },
    });
    assert.strictEqual(validStatusRes.status, 200);
    const statusBody = (await validStatusRes.json()) as { isPaid: boolean; downloadToken?: string };
    assert.strictEqual(statusBody.isPaid, false);
    assert.strictEqual(statusBody.downloadToken, undefined, "Unpaid job must withhold downloadToken");

    const unpaidReportRes = await fetch(`${baseUrl}/guest/report/${preassignedToken}`, {
      headers: { "x-guest-secret": secretKey },
    });
    assert.strictEqual(unpaidReportRes.status, 402, "Unpaid report download must return 402");
    console.log("✓ Test 2: 403 unpaid block, timing-safe IDOR & 402 download gate verified");

    // 3. NewebPay Webhook: invalid TradeSha (400), 1-TWD tamper (400), unlock & idempotency
    const checkoutRes = await fetch(`${baseUrl}/api/newebpay/guest-checkout`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-guest-secret": secretKey },
      body: JSON.stringify({ jobId, email: "visitor@example.com" }),
    });
    assert.strictEqual(checkoutRes.status, 200);
    const checkoutBody = (await checkoutRes.json()) as { orderNo: string; twd: number };
    createdOrderNos.push(checkoutBody.orderNo);

    const validSigned = buildSignedWebhookPayload({
      Status: "SUCCESS",
      Result: { MerchantOrderNo: checkoutBody.orderNo, Amt: checkoutBody.twd, TradeNo: "T_001" },
    });
    const badShaRes = await fetch(`${baseUrl}/api/newebpay/notify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ TradeInfo: validSigned.TradeInfo, TradeSha: "0".repeat(64) }),
    });
    assert.strictEqual(badShaRes.status, 400, "Invalid TradeSha must return 400");

    const tamperedAmtSigned = buildSignedWebhookPayload({
      Status: "SUCCESS",
      Result: { MerchantOrderNo: checkoutBody.orderNo, Amt: 1, TradeNo: "T_TAMPER" },
    });
    const badAmtRes = await fetch(`${baseUrl}/api/newebpay/notify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(tamperedAmtSigned),
    });
    assert.strictEqual(badAmtRes.status, 400, "1-TWD tampered amount must return 400");
    assert.strictEqual(GuestJob.findByJobId(jobId)?.isPaid, 0);

    const okNotifyRes = await fetch(`${baseUrl}/api/newebpay/notify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(validSigned),
    });
    assert.strictEqual(okNotifyRes.status, 200);
    const unlockedJob = GuestJob.findByJobId(jobId);
    assert.strictEqual(unlockedJob?.isPaid, 1);
    assert.strictEqual(unlockedJob?.downloadsRemaining, 5);
    const issuedToken = unlockedJob?.downloadToken;
    assert(issuedToken);

    GuestJob.decrementDownloadsRemaining(jobId);
    const dupNotifyRes = await fetch(`${baseUrl}/api/newebpay/notify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(validSigned),
    });
    assert.strictEqual(dupNotifyRes.status, 200);
    assert.strictEqual(GuestJob.findByJobId(jobId)?.downloadsRemaining, 4);
    assert.strictEqual(GuestJob.findByJobId(jobId)?.downloadToken, issuedToken);
    console.log("✓ Test 3: NewebPay webhook signature/amount defense, unlock & idempotency verified");

    // 4. Discard Job & 10-minute Cooldown Gate (429)
    const discardJobId = `discard-job-${Date.now()}`;
    const discardSecret = crypto.randomBytes(24).toString("hex");
    createdJobIds.push(discardJobId);
    GuestJob.create({
      jobId: discardJobId,
      analysisType: "static",
      fileHash: "d".repeat(64),
      filename: "discard-target.apk",
      status: "pending",
      secretKey: discardSecret,
    });
    GuestJob.update(discardJobId, { status: "done", isPaid: 0 });

    const discardRes = await fetch(`${baseUrl}/guest/discard-job`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-guest-secret": discardSecret },
      body: JSON.stringify({ jobId: discardJobId }),
    });
    assert.strictEqual(discardRes.status, 200);
    assert.strictEqual(GuestJob.findByJobId(discardJobId)?.status, "expired");

    const cooldownRes = await fetch(`${baseUrl}/guest/create-job`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        analysisType: "static",
        hash: "e".repeat(64),
        fileName: "during-cooldown.apk",
        currentJobId: discardJobId,
      }),
    });
    assert.strictEqual(cooldownRes.status, 429, "Discard cooldown must return 429");
    console.log("✓ Test 4: POST /guest/discard-job & 10-minute cooldown (429) verified");

    console.log("==================================================");
    console.log(" All HTTP Routes & Webhook Regression Tests Passed (4/4) ✅");
    console.log("==================================================");
  } finally {
    ArtifactVault.purgeAllJobArtifacts = originalPurgeAll;
    for (const id of createdJobIds) GuestJob.delete(id);
    for (const orderNo of createdOrderNos) {
      db.prepare("DELETE FROM newebpay_orders WHERE orderNo = ?").run(orderNo);
    }
        await new Promise<void>((resolve) => server.close(() => resolve()));
    try {
      db.close();
    } catch {}
    for (const ext of ["", "-wal", "-shm"]) {
      const target = TEST_DB_PATH + ext;
      if (fs.existsSync(target)) {
        try {
          fs.unlinkSync(target);
        } catch {}
      }
    }
  }
}

runTests().catch((err) => {
  console.error("HTTP Routes & Webhook Regression Test Failed:", err);
  process.exit(1);
});


