// server/tests/newebpay_receipt_email.test.ts
import assert from "assert";
import { db } from "../db";
import { buildGuestTradeInfoParams } from "../newebpay";

console.log("==================================================");
console.log(" Running NewebPay Receipt Email Integration Tests");
console.log("==================================================");

// 1. Verify buildGuestTradeInfoParams integrates and trims receiptEmail
const trimmedEmail = "user@example.com";
const untrimmedEmail = "   user@example.com   \n";

const paramsTrimmed = buildGuestTradeInfoParams({
  merchantId: "TEST_MERCHANT_ID",
  orderNo: "CMAAG123456789",
  amt: 1200,
  itemDesc: "Security Report",
  receiptEmail: untrimmedEmail,
});

assert.strictEqual(
  paramsTrimmed.get("Email"),
  trimmedEmail,
  "buildGuestTradeInfoParams must trim whitespace from receiptEmail"
);
assert.strictEqual(paramsTrimmed.get("MerchantOrderNo"), "CMAAG123456789");
assert.strictEqual(paramsTrimmed.get("Amt"), "1200");
assert.strictEqual(paramsTrimmed.get("RespondType"), "JSON");
console.log("✓ Test 1: buildGuestTradeInfoParams correctly formats and trims receiptEmail");

// 2. Verify empty or undefined receiptEmail defaults to empty string
const paramsEmpty = buildGuestTradeInfoParams({
  merchantId: "TEST_MERCHANT_ID",
  orderNo: "CMAAG987654321",
  amt: 1200,
  itemDesc: "Security Report",
  receiptEmail: undefined,
});
assert.strictEqual(paramsEmpty.get("Email"), "", "Undefined receiptEmail should result in empty string");
console.log("✓ Test 2: Missing receiptEmail defaults safely to empty string");

// 3. Verify SQLite newebpay_orders persistence of receiptEmail
const testOrderNo = "TEST_ORDER_EMAIL_" + Date.now();
db.prepare(`
  INSERT INTO newebpay_orders (orderNo, uid, credits, amt, usdAmt, fxRate, jobId, orderType, receiptEmail)
  VALUES (?, 'guest', 0, 1200, 40, 30.0, 'job-test-email', 'guest_report', ?)
`).run(testOrderNo, trimmedEmail);

const savedRow = db
  .prepare("SELECT orderNo, receiptEmail, orderType FROM newebpay_orders WHERE orderNo = ?")
  .get(testOrderNo) as { orderNo: string; receiptEmail: string; orderType: string } | undefined;

assert(savedRow, "Order row must be retrievable from SQLite");
assert.strictEqual(savedRow.receiptEmail, trimmedEmail, "Saved receiptEmail must match inserted value");
assert.strictEqual(savedRow.orderType, "guest_report");
console.log("✓ Test 3: SQLite newebpay_orders table stores and retrieves receiptEmail column");

// Cleanup test row
db.prepare("DELETE FROM newebpay_orders WHERE orderNo = ?").run(testOrderNo);

console.log("All NewebPay Receipt Email tests passed! ✅\n");
