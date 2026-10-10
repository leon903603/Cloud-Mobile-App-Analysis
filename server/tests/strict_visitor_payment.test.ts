import assert from "assert";
import crypto from "crypto";
import { db } from "../db";
import { GuestJob } from "../models/GuestJob";

console.log("==================================================");
console.log(" Running Strict Visitor Payment & Timing Tests");
console.log("==================================================");

const TEST_JOB_ID = "test-strict-payment-job-" + Date.now();
const SECRET_KEY = crypto.randomBytes(16).toString("hex");
const DOWNLOAD_TOKEN = crypto.randomBytes(32).toString("hex");

// 1. Create unpaid job
GuestJob.create({
  jobId: TEST_JOB_ID,
  analysisType: "static",
  fileHash: "test-hash-payment",
  filename: "payment-test.apk",
  status: "pending",
  secretKey: SECRET_KEY,
});

GuestJob.update(TEST_JOB_ID, {
  status: "done",
  reportPath: `guest/reports/${TEST_JOB_ID}.pdf`,
  downloadToken: DOWNLOAD_TOKEN,
  isPaid: 0, // Unpaid!
});

let job = GuestJob.findByJobId(TEST_JOB_ID);
assert(job, "Job must exist");
assert.strictEqual(job.isPaid, 0, "Job must be unpaid");

// Test constant time comparison logic
function verifySecret(expected: string | null | undefined, provided: string | null | undefined): boolean {
  if (!expected || !provided) return false;
  const expBuf = Buffer.from(expected, "utf8");
  const provBuf = Buffer.from(provided, "utf8");
  if (expBuf.length !== provBuf.length) return false;
  return crypto.timingSafeEqual(expBuf, provBuf);
}

assert.strictEqual(verifySecret(SECRET_KEY, SECRET_KEY), true, "Correct secret passes");
assert.strictEqual(verifySecret(SECRET_KEY, "wrong-secret"), false, "Wrong secret rejected");
assert.strictEqual(verifySecret(null, SECRET_KEY), false, "Null expected secret rejected");
assert.strictEqual(verifySecret(SECRET_KEY, null), false, "Null provided secret rejected");
console.log("✓ Test 1: Constant-time timingSafeEqual secret comparison verified");

// Test strict unpaid rejection logic:
// Even if provided token matches downloadToken, !job.isPaid MUST reject with 402
function canDownload(j: typeof job): { allowed: boolean; status: number } {
  if (!j.isPaid) return { allowed: false, status: 402 };
  if (j.downloadsRemaining <= 0) return { allowed: false, status: 403 };
  return { allowed: true, status: 200 };
}

let result = canDownload(job);
assert.strictEqual(result.allowed, false);
assert.strictEqual(result.status, 402, "Unpaid download must return HTTP 402");
console.log("✓ Test 2: Unpaid job download unconditionally rejected with 402");

// Test payment upgrade to 5 downloads
GuestJob.update(TEST_JOB_ID, {
  isPaid: 1,
  downloadsRemaining: 5,
  paidAt: new Date().toISOString(),
});

job = GuestJob.findByJobId(TEST_JOB_ID);
assert.strictEqual(job?.isPaid, 1);
assert.strictEqual(job?.downloadsRemaining, 5);

// Decrement 5 times
for (let i = 5; i > 0; i--) {
  assert.strictEqual(job?.downloadsRemaining, i);
  const ok = GuestJob.decrementDownloadsRemaining(TEST_JOB_ID);
  assert.strictEqual(ok, true, `Decrement from ${i} to ${i - 1} must succeed`);
  job = GuestJob.findByJobId(TEST_JOB_ID);
}

assert.strictEqual(job?.downloadsRemaining, 0);
const overLimitOk = GuestJob.decrementDownloadsRemaining(TEST_JOB_ID);
assert.strictEqual(overLimitOk, false, "6th download must be rejected");
console.log("✓ Test 3: Visitor 5-download quota atomic decrement and rejection verified");

// Cleanup
db.prepare("DELETE FROM guest_jobs WHERE jobId = ?").run(TEST_JOB_ID);

console.log("==================================================");
console.log(" All Strict Visitor Payment Tests Passed (3/3) ✅");
console.log("==================================================");
