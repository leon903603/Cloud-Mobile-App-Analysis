// server/tests/creditBank.test.ts
import assert from "assert";
import { db as sqliteDb } from "../db";
import { CreditBank } from "../services/creditBank";
import { recordCreditChange } from "../credit_audit";

console.log("==================================================");
console.log(" Running CreditBank Deep Module Unit Tests");
console.log("==================================================");

async function runTests() {
  const TEST_UID = "bank-test-uid-" + Date.now();

  // Test 1: Verify credit_ledger SQLite CHECK constraint supports 'refund'
  const testRef = "analysis:999:test_attempt";
  const ok = recordCreditChange({
    uid: TEST_UID,
    delta: +1,
    reason: "refund",
    ref: testRef,
    balanceAfter: 5,
    note: "Testing refund CHECK constraint",
  });
  assert.strictEqual(ok, true, "credit_ledger must allow reason='refund' without throwing CHECK constraint error");
  console.log("✓ Test 1: SQLite schema migration and 'refund' reason constraint verified");

  // Clean up Test 1 ledger row
  sqliteDb.prepare("DELETE FROM credit_ledger WHERE uid = ?").run(TEST_UID);

  // Test 2: Double refund protection & matching consume requirement
  const mockFileId = 42;
  const mockChargeRef = `analysis:${mockFileId}:abc12345`;

  // Without consume record, refund must fail
  const unbackedRefund = await CreditBank.refundFailedAnalysis({
    uid: TEST_UID,
    fileId: mockFileId,
    chargeRef: mockChargeRef,
    reasonNote: "Unbacked refund attempt",
  });
  assert.strictEqual(unbackedRefund.ok, false, "Refund without matching consume record must be rejected");
  assert.strictEqual(unbackedRefund.code, "persistence_error");
  console.log("✓ Test 2: Unbacked refund without prior consume record properly blocked");

  // Insert a mock consume record
  recordCreditChange({
    uid: TEST_UID,
    delta: -1,
    reason: "consume",
    ref: mockChargeRef,
    balanceAfter: 2,
    note: "Mock analysis charge",
  });

  // Verify duplicate refund attempt is rejected
  recordCreditChange({
    uid: TEST_UID,
    delta: +1,
    reason: "refund",
    ref: mockChargeRef,
    balanceAfter: 3,
    note: "First refund",
  });

  const duplicateRefund = await CreditBank.refundFailedAnalysis({
    uid: TEST_UID,
    fileId: mockFileId,
    chargeRef: mockChargeRef,
    reasonNote: "Duplicate refund attempt",
  });
  assert.strictEqual(duplicateRefund.ok, false, "Duplicate refund for same chargeRef must be rejected");
  assert.strictEqual(duplicateRefund.code, "duplicate_transaction");
  console.log("✓ Test 3: Duplicate refund for same chargeRef properly blocked");

  // Test 4: Idempotent grantPurchase
  const orderNo = `ORDER_${Date.now()}`;
  recordCreditChange({
    uid: TEST_UID,
    delta: 5,
    reason: "purchase",
    ref: orderNo,
    balanceAfter: 10,
    note: "First purchase journal",
  });

  // Second grantPurchase call with same orderNo should detect existing journal and return balance safely
  const idempotentResult = await CreditBank.grantPurchase({
    uid: TEST_UID,
    orderNo,
    credits: 5,
    note: "Duplicate grant purchase",
  });
  assert.strictEqual(idempotentResult.ok, true, "grantPurchase must be idempotent for same orderNo");
  if (idempotentResult.ok) {
    assert.strictEqual(idempotentResult.balance, 10, "Balance should reflect recorded balanceAfter");
  }
  console.log("✓ Test 4: grantPurchase idempotency verified");

  // Clean up test rows
  sqliteDb.prepare("DELETE FROM credit_ledger WHERE uid = ?").run(TEST_UID);

  console.log("==================================================");
  console.log(" All CreditBank Module Unit Tests Passed (4/4) ✅");
  console.log("==================================================");
}

runTests().catch((err) => {
  console.error("CreditBank unit tests failed:", err);
  process.exit(1);
});
