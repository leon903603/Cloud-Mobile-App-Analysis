// tests/credit_audit_writes.test.js
const assert = require("assert");
const { db } = require("../dist/db");
const { recordCreditChange } = require("../dist/credit_audit");

console.log("==================================================");
console.log(" Running Credit Audit Ledger Writes & Idempotency Tests");
console.log("==================================================");

const testUid = "audit-writes-user-" + Date.now();

// 1. Idempotency test: duplicate (reason, ref) must return false and not insert a duplicate row
const orderRef = `ORDER_${Date.now()}`;
const firstWrite = recordCreditChange({
  uid: testUid,
  delta: 10,
  reason: "purchase",
  ref: orderRef,
  balanceAfter: 15,
  note: "First purchase write",
});
assert.strictEqual(firstWrite, true, "First purchase journal write should succeed");

const secondWrite = recordCreditChange({
  uid: testUid,
  delta: 10,
  reason: "purchase",
  ref: orderRef,
  balanceAfter: 25,
  note: "Duplicate purchase write attempt",
});
assert.strictEqual(secondWrite, false, "Second write with same reason & ref must return false (idempotent)");

const orderRows = db.prepare("SELECT * FROM credit_ledger WHERE reason = 'purchase' AND ref = ?").all(orderRef);
assert.strictEqual(orderRows.length, 1, "Only one ledger row should exist for the unique (reason, ref)");
assert.strictEqual(orderRows[0].balanceAfter, 15, "balanceAfter must reflect the initial write");
console.log("✓ Test 1: Idempotency enforced via (reason, ref) unique index on purchase orders");

// 2. Cross-reason shared ref test: consume and refund sharing the same ref: analysis:${fileId}:${attemptUuid}
const sharedAnalysisRef = `analysis:55:attempt_${Date.now()}`;

const consumeOk = recordCreditChange({
  uid: testUid,
  delta: -1,
  reason: "consume",
  ref: sharedAnalysisRef,
  balanceAfter: 14,
  note: "Analysis started",
});
assert.strictEqual(consumeOk, true, "Consume record must succeed");

const refundOk = recordCreditChange({
  uid: testUid,
  delta: +1,
  reason: "refund",
  ref: sharedAnalysisRef,
  balanceAfter: 15,
  note: "Analysis failed refund",
});
assert.strictEqual(refundOk, true, "Refund record with SAME ref as consume must succeed because reason differs");

const sharedRows = db.prepare("SELECT * FROM credit_ledger WHERE ref = ? ORDER BY id ASC").all(sharedAnalysisRef);
assert.strictEqual(sharedRows.length, 2, "Both consume and refund rows should coexist with shared ref");
assert.strictEqual(sharedRows[0].reason, "consume");
assert.strictEqual(sharedRows[0].delta, -1);
assert.strictEqual(sharedRows[1].reason, "refund");
assert.strictEqual(sharedRows[1].delta, 1);
console.log("✓ Test 2: Shared ref across 'consume' and 'refund' coexists without collision");

// Clean up
db.prepare("DELETE FROM credit_ledger WHERE uid = ?").run(testUid);

console.log("All Credit Audit Writes & Idempotency Tests Passed! ✅\n");
