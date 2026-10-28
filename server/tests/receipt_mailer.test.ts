// server/tests/receipt_mailer.test.ts
import assert from "assert";
import fs from "fs";
import path from "path";
import os from "os";
import {
  generateReceiptHtml,
  generateOfficialSealSvg,
  sendReceiptEmailSafe,
  escapeHtml,
  ReceiptEmailPayload,
} from "../services/receiptMailer";
import {
  priceFor,
  generateReceiptSignature,
} from "../newebpay";

console.log("==================================================");
console.log(" Running Receipt Mailer & Official Receipt Unit Tests");
console.log("==================================================");

// 1. Verify Official Seal SVG Structural and XML Conformance (Anti-tautological)
const sealSvg = generateOfficialSealSvg();
assert(sealSvg.trim().startsWith("<svg") && sealSvg.trim().endsWith("</svg>"), "Seal must be a well-formed SVG root element");
assert(sealSvg.includes('xmlns="http://www.w3.org/2000/svg"'), "Seal must declare standard SVG XML namespace");
assert(sealSvg.includes('viewBox="0 0 170 170"'), "Seal must define precise viewBox dimensions");
assert(sealSvg.includes("<circle") && sealSvg.includes("<path") && sealSvg.includes("<text"), "Seal must contain vector geometry elements");
assert(!sealSvg.includes("isLab"), "Seal must not contain legacy deprecated brand identifier");
console.log("✓ Test 1: Official Seal SVG structural and XML specifications verified");

// 2. Verify Member Receipt HTML Document Conformance & Calculations (Anti-tautological)
const normalPayload: ReceiptEmailPayload = {
  orderNo: "CMAA202610271001",
  recipientEmail: "professor@university.edu.tw",
  credits: 1,
  amt: 1280,
  usdAmt: 40,
  orderType: "credits",
  tradeNo: "NW2026102788889999",
  paidAt: "2026-10-27T14:30:00.000Z",
  webReceiptUrl: "https://cmaa.solitesterror.com/api/newebpay/orders/CMAA202610271001/receipt?sig=mock123",
};

const normalHtml = generateReceiptHtml(normalPayload);
assert(normalHtml.startsWith("<!DOCTYPE html>"), "Receipt must generate complete HTML5 document");
assert(normalHtml.includes("<html") && normalHtml.includes("</html>"), "Receipt must contain closed html tag");
assert(normalHtml.includes(normalPayload.orderNo), "Receipt must render bound order number");
assert(normalHtml.includes(normalPayload.recipientEmail), "Receipt must render bound recipient email");
assert(normalHtml.includes("$40.00 USD (NT$ 1,280)"), "Receipt must accurately compute and render fee display");
assert(normalHtml.includes(normalPayload.tradeNo), "Receipt must bind gateway transaction reference");
assert(normalHtml.includes("@media print"), "Receipt must embed print CSS stylesheet for A4 output");
assert(normalHtml.includes("View &amp; Print Official Receipt (A4 / PDF) ↗"), "Receipt must render spec-compliant CTA link");
console.log("✓ Test 2: Standard member official receipt HTML contract and calculations verified");

// 3. Verify XSS & HTML Entity Escaping (Sanitizer Defense)
const xssPayload: ReceiptEmailPayload = {
  orderNo: 'CMAA"onmouseover="alert(1)',
  recipientEmail: '"><script>alert("xss")</script><a href="evil">@example.com',
  credits: 1,
  amt: 1280,
  orderType: "credits",
  tradeNo: '<script>fetch("http://attacker.com")</script>',
};
const xssHtml = generateReceiptHtml(xssPayload);
assert(!xssHtml.includes("<script>"), "HTML output must not contain raw unescaped <script> tags");
assert(xssHtml.includes("&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;"), "Injected script in email must be entity escaped");
assert(xssHtml.includes("CMAA&quot;onmouseover=&quot;alert(1)"), "Injected quotes in orderNo must be entity escaped");
console.log("✓ Test 3: XSS & HTML Entity Escaping effectively sanitizes malicious user inputs");

// 4. Verify 1 Dollar Test Probe Receipt HTML (NT$ 1.00 / US$ 1.00)
const probePayload: ReceiptEmailPayload = {
  orderNo: "CMAA202610279999",
  recipientEmail: "tester@cmaa.solitesterror.com",
  credits: 1,
  amt: 1,
  usdAmt: 1,
  orderType: "credits",
  tradeNo: "NW_PROBE_123456",
  paidAt: new Date().toISOString(),
};

const probeHtml = generateReceiptHtml(probePayload);
assert(probeHtml.includes("$1.00 USD (NT$ 1.00)"), "Probe receipt must correctly format 1 dollar fee");
console.log("✓ Test 4: Test probe receipt HTML correctly renders $1.00 USD (NT$ 1.00)");

// 5. Verify Guest Report Receipt HTML
const guestPayload: ReceiptEmailPayload = {
  orderNo: "CMAAG202610275555",
  recipientEmail: "guest_auditor@company.com",
  credits: 0,
  amt: 1280,
  usdAmt: 40,
  orderType: "guest_report",
  tradeNo: "NW_GUEST_998877",
  paidAt: new Date().toISOString(),
};

const guestHtml = generateReceiptHtml(guestPayload);
assert(guestHtml.includes("Single Security Analysis Report"), "Guest receipt must specify single report description");
console.log("✓ Test 5: Guest receipt HTML correctly identifies single report purchase");

// 6. Verify TEST_PAYMENT_PROBE Pricing Isolation & Production Guard
const origProbeEnv = process.env.TEST_PAYMENT_PROBE;
const origNodeEnv = process.env.NODE_ENV;
try {
  // Enabled in dev/test: Starter is 1 TWD / 1 USD, while Pro/Power remain full price
  process.env.NODE_ENV = "test";
  process.env.TEST_PAYMENT_PROBE = "true";
  const probeStarter = priceFor(1, "starter");
  assert.strictEqual(probeStarter.usd, 1, "Starter USD must be 1 when probe is true in test/dev");
  assert.strictEqual(probeStarter.twd, 1, "Starter TWD must be 1 when probe is true in test/dev");

  const probePro = priceFor(5, "pro");
  assert.strictEqual(probePro.usd, 200, "Pro USD must strictly remain 200 even if probe is true");
  assert(probePro.twd > 6000, "Pro TWD must strictly remain catalog price (~6400 TWD)");

  // Production Lockdown: Probe MUST be ignored when NODE_ENV === 'production'
  process.env.NODE_ENV = "production";
  const prodStarter = priceFor(1, "starter");
  assert.strictEqual(prodStarter.usd, 40, "Starter USD must strictly return to 40 in production regardless of probe flag");
  assert(prodStarter.twd > 1200, "Starter TWD must strictly remain catalog price in production");

  // Disabled in dev: Starter returns standard 40 USD
  process.env.NODE_ENV = "test";
  process.env.TEST_PAYMENT_PROBE = "false";
  const normalStarter = priceFor(1, "starter");
  assert.strictEqual(normalStarter.usd, 40, "Starter USD must return to 40 when probe is false");
  assert(normalStarter.twd > 1200, "Starter TWD must return to catalog price when probe is false");
} finally {
  if (origProbeEnv !== undefined) {
    process.env.TEST_PAYMENT_PROBE = origProbeEnv;
  } else {
    delete process.env.TEST_PAYMENT_PROBE;
  }
  if (origNodeEnv !== undefined) {
    process.env.NODE_ENV = origNodeEnv;
  } else {
    delete process.env.NODE_ENV;
  }
}
console.log("✓ Test 6: TEST_PAYMENT_PROBE strictly isolates 1 TWD to Starter and preserves Pro pricing & production lockdown");

// 7. Verify HMAC Receipt Signature Generator (IDOR Defense)
const sigOrderNo = "CMAA12345678";
const sigPaidAt = "2026-10-28T00:00:00.000Z";
const sig1 = generateReceiptSignature(sigOrderNo, sigPaidAt);
const sig2 = generateReceiptSignature(sigOrderNo, sigPaidAt);
const sigDifferentOrder = generateReceiptSignature("CMAA99999999", sigPaidAt);
const sigDifferentTime = generateReceiptSignature(sigOrderNo, "2026-10-28T01:00:00.000Z");

assert.strictEqual(sig1, sig2, "HMAC signature must be deterministic for identical parameters");
assert.strictEqual(sig1.length, 64, "Signature must be 64-character full SHA256 hex string");
assert.notStrictEqual(sig1, sigDifferentOrder, "Different order numbers must produce distinct signatures");
assert.notStrictEqual(sig1, sigDifferentTime, "Different paidAt times must produce distinct signatures");
console.log("✓ Test 7: generateReceiptSignature produces deterministic, tamper-proof IDOR verification tokens");

// 8. Verify Empty Email Graceful Display Fallback (No internal UID leakage)
const noEmailPayload: ReceiptEmailPayload = {
  ...normalPayload,
  recipientEmail: "",
};
const noEmailHtml = generateReceiptHtml(noEmailPayload);
assert(noEmailHtml.includes("Valued Customer"), "Empty recipientEmail must gracefully display 'Valued Customer'");
assert(!noEmailHtml.includes("guest"), "Receipt must not leak internal placeholder strings");
console.log("✓ Test 8: Empty recipient email gracefully falls back to 'Valued Customer' without UID leakage");

// 8.1 Verify buyerName & receiptIssuedAt Official Reimbursement Rendering
const claimedPayload: ReceiptEmailPayload = {
  ...normalPayload,
  buyerName: "National Taiwan University EE Lab",
  receiptIssuedAt: "2026-10-28T08:00:00.000Z",
};
const claimedHtml = generateReceiptHtml(claimedPayload);
assert(claimedHtml.includes("National Taiwan University EE Lab (professor@university.edu.tw)"), "Receipt must render company name with email in parentheses");
assert(claimedHtml.includes("October 28, 2026"), "Receipt must format receiptIssuedAt date");

const claimedNoEmailPayload: ReceiptEmailPayload = {
  ...normalPayload,
  recipientEmail: "",
  buyerName: "Cybersecurity Research Institute",
};
const claimedNoEmailHtml = generateReceiptHtml(claimedNoEmailPayload);
assert(claimedNoEmailHtml.includes("Cybersecurity Research Institute"), "Receipt must render company name when email is absent");
assert(!claimedNoEmailHtml.includes("()"), "Receipt must not render empty parentheses when email is absent");

const xssBuyerPayload: ReceiptEmailPayload = {
  ...normalPayload,
  buyerName: '<script>alert("hacked")</script>',
};
const xssBuyerHtml = generateReceiptHtml(xssBuyerPayload);
assert(!xssBuyerHtml.includes("<script>alert"), "buyerName must entity-escape script tags");
assert(xssBuyerHtml.includes("&lt;script&gt;alert"), "buyerName must contain escaped script tags");
console.log("✓ Test 8.1: buyerName, receiptIssuedAt & XSS escaping for official receipts verified");

// 9. Verify Graceful Degradation in sendReceiptEmailSafe
async function testMailerSafety() {
  const origKey = process.env.RESEND_API_KEY;
  try {
    delete process.env.RESEND_API_KEY;

    // Missing API Key -> Mock mode (does not throw, returns skipped: true)
    const resultNoKey = await sendReceiptEmailSafe(normalPayload);
    assert.strictEqual(resultNoKey.success, true);
    assert.strictEqual(resultNoKey.skipped, true);
    assert.strictEqual(resultNoKey.reason, "mock_mode_no_api_key");

    // Invalid email -> Safe rejection (does not throw)
    const resultBadEmail = await sendReceiptEmailSafe({
      ...normalPayload,
      recipientEmail: "invalid-email-string",
    });
    assert.strictEqual(resultBadEmail.success, false);
    assert.strictEqual(resultBadEmail.skipped, true);
    assert.strictEqual(resultBadEmail.reason, "missing_or_invalid_recipient");
  } finally {
    if (origKey !== undefined) {
      process.env.RESEND_API_KEY = origKey;
    }
  }
}

testMailerSafety().then(() => {
  console.log("✓ Test 9: sendReceiptEmailSafe graceful degradation & input guard verified");

  // Test Hygiene: Export sample HTML files only if explicitly requested
  if (process.env.EXPORT_RECEIPT_SAMPLES === "true") {
    const exportDir = os.tmpdir();
    const sampleNormalPath = path.join(exportDir, "sample_official_receipt.html");
    const sampleProbePath = path.join(exportDir, "sample_official_receipt_probe.html");

    fs.writeFileSync(sampleNormalPath, normalHtml, "utf8");
    fs.writeFileSync(sampleProbePath, probeHtml, "utf8");

    console.log(`\n[+] Exported presentation samples to tmpdir:`);
    console.log(`    - Standard ($40 USD): ${sampleNormalPath}`);
    console.log(`    - Test Probe ($1 TWD): ${sampleProbePath}`);
  }

  console.log("\nAll Receipt Mailer tests passed! ✅\n");
});
