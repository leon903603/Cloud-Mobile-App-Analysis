// tests/credit_audit.test.js
const assert = require("assert");
const { db } = require("../dist/db");
const { recordCreditChange } = require("../dist/credit_audit");

console.log("==================================================");
console.log(" Running Credit Audit Table & Reason Constraint Tests");
console.log("==================================================");

// 1. Verify credit_ledger table schema (must have 8 columns with exact casing)
const columns = db.prepare("PRAGMA table_info(credit_ledger)").all();
const columnNames = columns.map((c) => c.name);

assert(columnNames.includes("id"), "credit_ledger must have 'id'");
assert(columnNames.includes("uid"), "credit_ledger must have 'uid'");
assert(columnNames.includes("delta"), "credit_ledger must have 'delta'");
assert(columnNames.includes("reason"), "credit_ledger must have 'reason'");
assert(columnNames.includes("ref"), "credit_ledger must have 'ref'");
assert(columnNames.includes("balanceAfter"), "credit_ledger must have 'balanceAfter'");
assert(columnNames.includes("note"), "credit_ledger must have 'note'");
assert(columnNames.includes("createdAt"), "credit_ledger must have 'createdAt' (camelCase)");
assert.strictEqual(columns.length, 8, "credit_ledger must have exactly 8 columns");
console.log("✓ Test 1: credit_ledger schema matches 8 required columns (including createdAt & balanceAfter)");

// 2. Verify all valid reasons are accepted by the CHECK constraint
const testUid = "audit-test-user-" + Date.now();
const validReasons = [
  "signup",
  "purchase",
  "consume",
  "refund",
  "admin_adjust",
  "reconcile_correction",
];

for (const reason of validReasons) {
  const ref = `test:${reason}:${Date.now()}`;
  const ok = recordCreditChange({
    uid: testUid,
    delta: reason === "consume" ? -1 : 1,
    reason,
    ref,
    balanceAfter: 10,
    note: `Testing reason '${reason}'`,
  });
  assert.strictEqual(ok, true, `recordCreditChange must succeed for valid reason '${reason}'`);
}
console.log("✓ Test 2: All 6 valid reasons (including 'refund') accepted by CHECK constraint");

// 3. Verify invalid reason is rejected by CHECK constraint
let rejected = false;
try {
  db.prepare(`
    INSERT INTO credit_ledger (uid, delta, reason, ref, balanceAfter, note)
    VALUES (?, ?, 'invalid_reason_test', ?, ?, ?)
  `).run(testUid, 1, `invalid-ref-${Date.now()}`, 10, "Invalid reason test");
} catch (err) {
  rejected = true;
  assert(err.message.includes("CHECK constraint failed"), "Error should be CHECK constraint violation");
}
assert.strictEqual(rejected, true, "Invalid reason must trigger CHECK constraint violation");
console.log("✓ Test 3: Invalid reason properly rejected by SQLite CHECK constraint");

// Clean up
db.prepare("DELETE FROM credit_ledger WHERE uid = ?").run(testUid);

console.log("All Credit Audit Schema & Reason Tests Passed! ✅\n");
