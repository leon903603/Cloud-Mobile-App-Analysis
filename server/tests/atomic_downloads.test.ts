import assert from "assert";
import { db } from "../db";
import { GuestJob } from "../models/GuestJob";

console.log("==================================================");
console.log(" Running Atomic Download Quota Unit Tests");
console.log("==================================================");

async function runTests() {
  const testJobId = "test-atomic-quota-job";

  // Cleanup old test records
  GuestJob.delete(testJobId);

  // 1. Setup a test job with downloadsRemaining = 2
  db.prepare(`
    INSERT INTO guest_jobs (jobId, analysisType, fileHash, filename, status, isPaid, downloadsRemaining, createdAt, expiresAt)
    VALUES (?, 'static', 'dummy-hash', 'test.apk', 'done', 1, 2, datetime('now'), datetime('now', '+2 days'))
  `).run(testJobId);

  // Test 1: First decrement succeeds (2 -> 1)
  const dec1 = GuestJob.decrementDownloadsRemaining(testJobId);
  assert.strictEqual(dec1, true, "First decrement must succeed");
  const row1 = GuestJob.findByJobId(testJobId);
  assert.strictEqual(row1?.downloadsRemaining, 1);
  console.log("✓ Test 1: Decrement from 2 to 1 succeeded");

  // Test 2: Second decrement succeeds (1 -> 0)
  const dec2 = GuestJob.decrementDownloadsRemaining(testJobId);
  assert.strictEqual(dec2, true, "Second decrement must succeed");
  const row2 = GuestJob.findByJobId(testJobId);
  assert.strictEqual(row2?.downloadsRemaining, 0);
  console.log("✓ Test 2: Decrement from 1 to 0 succeeded");

  // Test 3: Third decrement fails (cannot decrement below 0)
  const dec3 = GuestJob.decrementDownloadsRemaining(testJobId);
  assert.strictEqual(dec3, false, "Third decrement must fail when remaining is 0");
  const row3 = GuestJob.findByJobId(testJobId);
  assert.strictEqual(row3?.downloadsRemaining, 0, "Downloads remaining must stay 0");
  console.log("✓ Test 3: Decrement blocked when quota exhausted (stayed at 0)");

  // Test 4: Concurrency simulation (10 parallel decrements on a job with 1 download)
  const concurrencyJobId = "test-concurrency-job";
  GuestJob.delete(concurrencyJobId);
  db.prepare(`
    INSERT INTO guest_jobs (jobId, analysisType, fileHash, filename, status, isPaid, downloadsRemaining, createdAt, expiresAt)
    VALUES (?, 'static', 'dummy-hash', 'test.apk', 'done', 1, 1, datetime('now'), datetime('now', '+2 days'))
  `).run(concurrencyJobId);

  const results = await Promise.all(
    Array.from({ length: 10 }, async () => GuestJob.decrementDownloadsRemaining(concurrencyJobId))
  );

  const successCount = results.filter((r) => r === true).length;
  const failureCount = results.filter((r) => r === false).length;

  assert.strictEqual(successCount, 1, "Exactly 1 concurrent request must succeed");
  assert.strictEqual(failureCount, 9, "Exactly 9 concurrent requests must be rejected");
  const finalRow = GuestJob.findByJobId(concurrencyJobId);
  assert.strictEqual(finalRow?.downloadsRemaining, 0);
  console.log("✓ Test 4: Concurrency test passed (10 parallel requests -> 1 success, 9 rejections)");

  // Cleanup
  GuestJob.delete(testJobId);
  GuestJob.delete(concurrencyJobId);

  console.log("==================================================");
  console.log(" All Atomic Quota Tests Passed (4/4) ✅");
  console.log("==================================================");
}

runTests().catch((err) => {
  console.error("Atomic quota tests failed:", err);
  process.exit(1);
});
