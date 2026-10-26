// tests/credit_audit_gaps.test.js
const assert = require("assert");
const { db } = require("../db");
require("../newebpay");
const { recordCreditChange, reconcileUser } = require("../credit_audit");

console.log("==================================================");
console.log(" Running Credit Audit Gap Detection & Anomaly Tests");
console.log("==================================================");

const testUid = "audit-gaps-user-" + Date.now();
const orderNo = `ORD_GAP_${Date.now()}`;
const windowStart = "2020-01-01T00:00:00.000Z";
const windowEnd = "2099-01-01T00:00:00.000Z";

// Setup backing paid order in newebpay_orders so purchase is recognized as legitimate
db.prepare(`
  INSERT INTO newebpay_orders (orderNo, uid, credits, amt, status, paidAt)
  VALUES (?, ?, 10, 300, 'paid', strftime('%Y-%m-%dT%H:%M:%fZ','now'))
`).run(orderNo, testUid);

// 1. Setup ledger entries: 10 initial purchase, 1 consume, 1 refund => net ledger delta = 10
recordCreditChange({
  uid: testUid,
  delta: 10,
  reason: "purchase",
  ref: orderNo,
  balanceAfter: 10,
  note: "Purchase 10 credits",
});

const consumeRef = `analysis:100:gap_test_${Date.now()}`;
recordCreditChange({
  uid: testUid,
  delta: -1,
  reason: "consume",
  ref: consumeRef,
  balanceAfter: 9,
  note: "Consume 1 credit",
});

recordCreditChange({
  uid: testUid,
  delta: 1,
  reason: "refund",
  ref: consumeRef,
  balanceAfter: 10,
  note: "Refund 1 credit",
});

// Calculate ledger sum
const row = db
  .prepare("SELECT COALESCE(SUM(delta), 0) AS total, COUNT(*) AS count FROM credit_ledger WHERE uid = ?")
  .get(testUid);
assert.strictEqual(row.total, 10, "Ledger delta sum should be exactly 10");

// 2. Real reconcileUser Seam Tests
// Case A: Synchronized (Observed Firestore 10 vs expected 10 -> zero drift, no anomalies)
const syncAnomalies = reconcileUser(
  { uid: testUid, email: "gap@test.com", credits: 10 },
  0,
  windowStart,
  windowEnd
);
assert.strictEqual(syncAnomalies.length, 0, "Synchronized user should produce 0 anomalies");
console.log("[PASS] Test 1: Real reconcileUser verified: synchronized balance produces zero anomalies");

// Case B: Unexplained increase (Observed Firestore 13 vs expected 10 -> +3 drift)
const increaseAnomalies = reconcileUser(
  { uid: testUid, email: "gap@test.com", credits: 13 },
  0,
  windowStart,
  windowEnd
);
assert.strictEqual(increaseAnomalies.length, 1);
assert.strictEqual(increaseAnomalies[0].kind, "unexplained_increase");
assert.strictEqual(increaseAnomalies[0].drift, 3);
assert.strictEqual(increaseAnomalies[0].severity, "critical");
console.log("[PASS] Test 2: Real reconcileUser verified: unexplained increase (+3 gap) flagged as critical");

// Case C: Unexplained decrease (Observed Firestore 7 vs expected 10 -> -3 drift)
const decreaseAnomalies = reconcileUser(
  { uid: testUid, email: "gap@test.com", credits: 7 },
  0,
  windowStart,
  windowEnd
);
assert.strictEqual(decreaseAnomalies.length, 1);
assert.strictEqual(decreaseAnomalies[0].kind, "unexplained_decrease");
assert.strictEqual(decreaseAnomalies[0].drift, -3);
assert.strictEqual(decreaseAnomalies[0].severity, "warning");
console.log("[PASS] Test 3: Real reconcileUser verified: unexplained decrease (-3 gap) flagged as warning");

// 3. Reconcile correction write test
const correctionOk = recordCreditChange({
  uid: testUid,
  delta: -3,
  reason: "reconcile_correction",
  ref: `anomaly:999`,
  balanceAfter: 7,
  note: "Automatic clawback of unexplained credits",
});
assert.strictEqual(correctionOk, true, "reconcile_correction entry should be recorded");

const afterCorrection = db
  .prepare("SELECT COALESCE(SUM(delta), 0) AS total FROM credit_ledger WHERE uid = ?")
  .get(testUid);
assert.strictEqual(afterCorrection.total, 7, "Ledger total should be updated to 7 after correction");
console.log("[PASS] Test 4: Reconcile correction adjustment properly journaled");

// Clean up
db.prepare("DELETE FROM credit_ledger WHERE uid = ?").run(testUid);
db.prepare("DELETE FROM newebpay_orders WHERE orderNo = ?").run(orderNo);

console.log("All Credit Audit Gap & Anomaly Tests Passed! [OK]\n");