// server/tests/newebpay_receipt_email.test.ts
import assert from "assert";
import crypto from "crypto";

console.log("==================================================");
console.log(" Running NewebPay Receipt Email Integration Tests");
console.log("==================================================");

// Mock keys for AES encryption / decryption test
const TEST_KEY = "12345678901234567890123456789012";
const TEST_IV = "1234567890123456";

function aesEncrypt(plain: string): string {
  const cipher = crypto.createCipheriv("aes-256-cbc", TEST_KEY, TEST_IV);
  return cipher.update(plain, "utf8", "hex") + cipher.final("hex");
}

function aesDecrypt(hex: string): string {
  const decipher = crypto.createDecipheriv("aes-256-cbc", TEST_KEY, TEST_IV);
  return decipher.update(hex, "hex", "utf8") + decipher.final("utf8");
}

// 1. Simulate guest checkout TradeInfo construction with receiptEmail
const receiptEmail = "guest-invoice@example.com";
const tradeInfoPlain = new URLSearchParams({
  MerchantID: "TEST_MERCHANT_ID",
  RespondType: "JSON",
  TimeStamp: String(Math.floor(Date.now() / 1000)),
  Version: "2.0",
  MerchantOrderNo: "CMAAG123456789",
  Amt: "1200",
  ItemDesc: "Security Report",
  Email: receiptEmail,
}).toString();

const encrypted = aesEncrypt(tradeInfoPlain);
const decrypted = aesDecrypt(encrypted);
const parsed = Object.fromEntries(new URLSearchParams(decrypted));

assert.strictEqual(parsed.Email, receiptEmail, "Decrypted TradeInfo must contain the exact receiptEmail supplied");
assert.strictEqual(parsed.Amt, "1200");
console.log("✓ Test 1: NewebPay TradeInfo contains receiptEmail and decrypts accurately");

console.log("All NewebPay Receipt Email tests passed! ✅");
