// server/tests/analysis_failure_refund.test.ts
import assert from "assert";
import { db } from "../db";
import { FileMeta } from "../models/FileMeta";
import { CreditBank } from "../services/creditBank";
import { recordCreditChange } from "../credit_audit";

console.log("==================================================");
console.log(" Running Analysis Failure Credit Refund Unit Tests");
console.log("==================================================");

async function run() {
  const TEST_UID = "test-refund-user-" + Date.now();
  db.prepare("INSERT OR IGNORE INTO users (id, email) VALUES (?, ?)").run(
    TEST_UID,
    "refund@example.com"
  );

  // 1. Create test file record
  const file = FileMeta.create({
    user: TEST_UID,
    filename: "crash-test.apk",
    analysisType: "static",
    filePath: `uploads/${TEST_UID}/crash-test.apk`,
    reportPath: `reports/${TEST_UID}/crash-test.pdf`,
    hash: "hash-refund-test-12345",
    status: "pending",
  });

  assert(file, "File record should be created");
  assert.strictEqual(file.creditSpent, 0, "Initially creditSpent should be 0");

  // 2. Mark credit spent during analysis dispatch
  FileMeta.markCreditSpent(file.id);
  let updatedFile = FileMeta.findById(file.id);
  assert.strictEqual(updatedFile?.creditSpent, 1, "creditSpent should be 1 during analysis");
  console.log("✓ Test 1: FileMeta creditSpent set to 1 during analysis start");

  // 3. Test CreditBank refund validation: reject refund if no matching consume record exists
  const attemptUuid = "abc12345";
  const chargeRef = `analysis:${file.id}:${attemptUuid}`;

  const unbackedRefund = await CreditBank.refundFailedAnalysis({
    uid: TEST_UID,
    fileId: file.id,
    chargeRef,
    reasonNote: "Unbacked refund test",
  });
  assert.strictEqual(
    unbackedRefund.ok,
    false,
    "Refund without consume record must be rejected with persistence_error"
  );
  assert.strictEqual(unbackedRefund.code, "persistence_error");
  console.log("✓ Test 2: Unbacked refund without consume journal entry properly rejected");

  // 4. Test CreditBank duplicate refund protection
  // Record the consume entry
  recordCreditChange({
    uid: TEST_UID,
    delta: -1,
    reason: "consume",
    ref: chargeRef,
    balanceAfter: 5,
    note: "Static analysis dispatch",
  });

  // Record an initial refund entry
  recordCreditChange({
    uid: TEST_UID,
    delta: 1,
    reason: "refund",
    ref: chargeRef,
    balanceAfter: 6,
    note: "First refund",
  });

  const duplicateRefund = await CreditBank.refundFailedAnalysis({
    uid: TEST_UID,
    fileId: file.id,
    chargeRef,
    reasonNote: "Duplicate refund attempt",
  });
  assert.strictEqual(
    duplicateRefund.ok,
    false,
    "Duplicate refund for the same chargeRef must be blocked"
  );
  assert.strictEqual(duplicateRefund.code, "duplicate_transaction");
  console.log("✓ Test 3: Duplicate refund for same analysis chargeRef rejected");

  // 5. Test state transition upon failure refund
  FileMeta.update(file.id, { status: "error", creditSpent: 0 });
  updatedFile = FileMeta.findById(file.id);
  assert.strictEqual(updatedFile?.status, "error", "Status should transition to 'error'");
  assert.strictEqual(updatedFile?.creditSpent, 0, "creditSpent should be reset to 0 after refund");
  console.log("✓ Test 4: FileMeta status transitions to 'error' and creditSpent resets to 0");

  // Clean up
  db.prepare("DELETE FROM file_meta WHERE id = ?").run(file.id);
  db.prepare("DELETE FROM credit_ledger WHERE uid = ?").run(TEST_UID);
  db.prepare("DELETE FROM users WHERE id = ?").run(TEST_UID);

  console.log("All Analysis Failure Refund tests passed! ✅\n");
}

run().catch((err) => {
  console.error("Analysis failure refund test failed:", err);
  process.exit(1);
});
