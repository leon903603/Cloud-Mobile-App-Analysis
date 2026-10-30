// server/tests/newebpay_receipt_email.test.ts
import assert from "assert";
import { db } from "../db";
import { buildGuestTradeInfoParams, getGatewayUrl, aesDecrypt } from "../newebpay";
import crypto from "crypto";

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

// 4. Verify getGatewayUrl handles both base and full endpoints without duplicating path
const origEnv = process.env.NEWEBPAY_GATEWAY;
try {
  process.env.NEWEBPAY_GATEWAY = "https://core.newebpay.com/MPG/mpg_gateway";
  assert.strictEqual(getGatewayUrl(), "https://core.newebpay.com/MPG/mpg_gateway");

  process.env.NEWEBPAY_GATEWAY = "https://core.newebpay.com";
  assert.strictEqual(getGatewayUrl(), "https://core.newebpay.com/MPG/mpg_gateway");

  process.env.NEWEBPAY_GATEWAY = "https://core.newebpay.com/";
  assert.strictEqual(getGatewayUrl(), "https://core.newebpay.com/MPG/mpg_gateway");

  process.env.NEWEBPAY_GATEWAY = "https://ccore.newebpay.com/MPG/mpg_gateway/";
  assert.strictEqual(getGatewayUrl(), "https://ccore.newebpay.com/MPG/mpg_gateway");

  delete process.env.NEWEBPAY_GATEWAY;
  assert.strictEqual(getGatewayUrl(), "https://ccore.newebpay.com/MPG/mpg_gateway");
} finally {
  if (origEnv !== undefined) {
    process.env.NEWEBPAY_GATEWAY = origEnv;
  } else {
    delete process.env.NEWEBPAY_GATEWAY;
  }
}
console.log("✓ Test 4: getGatewayUrl normalization prevents duplicate /MPG/mpg_gateway paths");

// 5. Verify NewebPay 32-byte PKCS7 custom padding decryption
// When NewebPay encrypts TradeInfo via PHP, it uses 32-byte blocks.
// If pad > 16, default OpenSSL autoPadding throws bad decrypt.
const testKey = "12345678901234567890123456789012";
const testIv = "1234567890123456";
const samplePayload = JSON.stringify({ Status: "SUCCESS", MerchantOrderNo: "CMAA202610309999", Amt: 1 });

function newebpaySimulateEncrypt(plain: string, key: string, iv: string, padSize = 32): string {
  const pad = padSize - (Buffer.byteLength(plain) % padSize);
  const padded = plain + String.fromCharCode(pad).repeat(pad);
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  cipher.setAutoPadding(false);
  return cipher.update(padded, "utf8", "hex") + cipher.final("hex");
}

const enc32 = newebpaySimulateEncrypt(samplePayload, testKey, testIv, 32);
const dec32 = aesDecrypt(enc32, testKey, testIv);
assert.strictEqual(dec32, samplePayload, "aesDecrypt must successfully decrypt 32-byte padded NewebPay TradeInfo");

for (let padNeeded = 1; padNeeded <= 32; padNeeded++) {
  const dummy = "X".repeat(32 - padNeeded);
  const enc = newebpaySimulateEncrypt(dummy, testKey, testIv, 32);
  const dec = aesDecrypt(enc, testKey, testIv);
  assert.strictEqual(dec, dummy, `aesDecrypt must successfully decrypt padding size ${padNeeded}`);
}
console.log("✓ Test 5: NewebPay 32-byte PKCS7 padding decryption resilience verified (all 32 pad sizes)");

// 6. Verify whitespace & CRLF sanitization defense on HASH_KEY and HASH_IV
// If .env contains trailing spaces or Windows CRLF, production code must auto-trim.
const messyKey = "12345678901234567890123456789012  \r\n";
const messyIv = "1234567890123456 \r";
const sampleMsg = "SensitivePayloadToSanitize";

// Test aesDecrypt with messy key/iv overrides
const messyEnc = newebpaySimulateEncrypt(sampleMsg, testKey, testIv, 32);
const messyDec = aesDecrypt(messyEnc, messyKey, messyIv);
assert.strictEqual(messyDec, sampleMsg, "aesDecrypt must auto-trim trailing spaces/CRLF from key and IV");

console.log("✓ Test 6: Runtime sanitization auto-trims whitespace/CRLF from HASH_KEY and HASH_IV");

console.log("All NewebPay Receipt Email tests passed! ✅\n");
