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

// 1. Verify Official Seal SVG Output
const sealSvg = generateOfficialSealSvg();
assert(sealSvg.includes("<svg"), "Seal must be a valid SVG element");
assert(sealSvg.includes("SUPREMA TECHNOLOGIES LTD"), "Seal must contain company name 'SUPREMA TECHNOLOGIES LTD'");
assert(sealSvg.includes("OFFICIAL SEAL"), "Seal must contain 'OFFICIAL SEAL'");
assert(sealSvg.includes("SUPREMA"), "Seal center must contain 'SUPREMA'");
assert(!sealSvg.includes("isLab"), "Seal must strictly NOT contain 'isLab'");
assert(sealSvg.includes("VERIFIED &amp; SECURED"), "Seal must contain security verification tagline");
console.log("✓ Test 1: Official Seal SVG conforms to visual & branding specifications");

// 2. Verify Member Receipt HTML generation (Normal $40 USD)
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
assert(normalHtml.includes("OFFICIAL RECEIPT"), "Receipt must have 'OFFICIAL RECEIPT' title");
assert(normalHtml.includes("professor@university.edu.tw"), "Receipt must include recipient email");
assert(normalHtml.includes("CMAA202610271001"), "Receipt must include order number");
assert(normalHtml.includes("Suprema Technologies LTD"), "Receipt must state company entity");
assert(normalHtml.includes("Application Security Assessment Chance"), "Receipt must include official service scope");
assert(!normalHtml.includes("One Application Security Assessment Chance"), "Receipt must not contain 'One Application Security Assessment Chance'");
assert(normalHtml.includes("App Security Analysis Credits"), "Receipt must include item name");
assert(normalHtml.includes("Starter Package: 1 Analysis Credit"), "Receipt must display correct package description");
assert(normalHtml.includes("$40.00 USD (NT$ 1,280)"), "Receipt must show formatted fee");
assert(
  normalHtml.includes("Payment Method:") &&
    normalHtml.includes("Credit Card (NewebPay Payment Gateway)"),
  "Receipt must state payment gateway"
);
assert(normalHtml.includes("NW2026102788889999"), "Receipt must include gateway transaction number");
assert(normalHtml.includes("Please retain this receipt for your records and reimbursement purposes."), "Receipt must include reimbursement disclaimer");
assert(normalHtml.includes("suprematechnologiesltd@mail.solitesterror.com"), "Receipt must include contact email");
assert(normalHtml.includes("https://cmaa.solitesterror.com"), "Receipt must include official website");
assert(normalHtml.includes("@media print"), "Receipt must include print CSS rules");
assert(normalHtml.includes("View Official Stamped Receipt"), "Receipt must include official stamped receipt link");
console.log("✓ Test 2: Standard member official receipt HTML generated with 100% compliant fields");

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
assert(guestHtml.includes("Guest Single Analysis Report: 1 Analysis Credit"), "Guest receipt must specify single report description");
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
assert.strictEqual(sig1.length, 32, "Signature must be 32-character hex string");
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
