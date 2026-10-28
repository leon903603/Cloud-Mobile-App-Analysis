// server/tests/self_serve_receipt_and_history.test.ts
// Comprehensive unit & regression tests for SPEC-CMAA-PAY-002:
// Self-Serve Credit Journal & On-Demand Official Receipt System

process.env.NODE_ENV = "test";
process.env.NEWEBPAY_MERCHANT_ID = "MOCK_MERCHANT";
process.env.NEWEBPAY_HASH_KEY = "12345678901234567890123456789012";
process.env.NEWEBPAY_HASH_IV = "1234567890123456";

import assert from "assert";
import http from "http";
import crypto from "crypto";
import express from "express";
import { db } from "../db";
import newebpayRouter, { claimReceiptHandler } from "../newebpay";
import { getMemberCreditHistory } from "../services/creditHistory";
import { CreditBank } from "../services/creditBank";

console.log("==================================================");
console.log(" Running Self-Serve Receipt & Credit Journal Tests");
console.log("==================================================");

let server: http.Server;
let baseUrl: string;
const testUid = `user-pay2-${Date.now()}`;
const otherUid = `user-other-${Date.now()}`;
const testOrderNo = `CMAA_PAY2_${Date.now()}`;
const otherOrderNo = `CMAA_OTHER_${Date.now()}`;

async function main() {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));

  app.use("/api/newebpay", newebpayRouter);

  // Spec route aliases as configured in server/index.ts
  app.get("/api/orders/:orderNo/receipt", (req, res) => {
    const query = req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : "";
    return res.redirect(307, `/api/newebpay/orders/${encodeURIComponent(req.params.orderNo)}/receipt${query}`);
  });

  app.post("/api/orders/:orderNo/receipt/claim", (req: any, res: any) => {
    const authHeader = req.headers.authorization || "";
    if (authHeader.startsWith("Bearer test-token-")) {
      req.uid = authHeader.replace("Bearer test-token-", "");
    }
    return claimReceiptHandler(req, res);
  });

  app.get("/api/member/credits/history", async (req: any, res: any) => {
    const authHeader = req.headers.authorization || "";
    if (!authHeader.startsWith("Bearer test-token-")) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    const uid = authHeader.replace("Bearer test-token-", "");
    try {
      const history = await getMemberCreditHistory(uid, baseUrl);
      return res.json(history);
    } catch (err: any) {
      return res.status(500).json({ error: err?.message });
    }
  });

  await new Promise<void>((resolve) => {
    server = app.listen(0, "127.0.0.1", () => {
      const addr = server.address() as any;
      baseUrl = `http://127.0.0.1:${addr.port}`;
      process.env.CLIENT_URL = baseUrl;
      resolve();
    });
  });

  try {
    // ── Setup: Insert test orders & ledger rows ──────────────────────────────
    db.prepare("DELETE FROM file_meta WHERE id = 1001").run();
    db.prepare("DELETE FROM credit_ledger WHERE ref LIKE 'analysis:1001:%'").run();
    db.prepare("INSERT OR IGNORE INTO users (id, email) VALUES (?, ?)").run(testUid, "researcher@lab.edu");
    db.prepare("INSERT OR IGNORE INTO users (id, email) VALUES (?, ?)").run(otherUid, "other@lab.edu");

    const paidAt = new Date().toISOString();
    db.prepare(`
      INSERT INTO newebpay_orders (orderNo, uid, credits, amt, usdAmt, fxRate, status, paidAt, tradeNo, receiptEmail)
      VALUES (?, ?, 5, 6400, 200, 32.0, 'paid', ?, 'TN_TEST_123', 'researcher@lab.edu')
    `).run(testOrderNo, testUid, paidAt);

    db.prepare(`
      INSERT INTO newebpay_orders (orderNo, uid, credits, amt, usdAmt, fxRate, status, paidAt, tradeNo, receiptEmail)
      VALUES (?, ?, 1, 1280, 40, 32.0, 'paid', ?, 'TN_OTHER_123', 'other@lab.edu')
    `).run(otherOrderNo, otherUid, paidAt);

    // Populate credit_ledger for testUid
    // 1. Signup bonus (+10)
    db.prepare(`
      INSERT INTO credit_ledger (uid, delta, reason, ref, note, balanceAfter)
      VALUES (?, 10, 'signup', ?, 'Signup Bonus', 10)
    `).run(testUid, `seed:${testUid}`);

    // 2. Purchase (+5)
    db.prepare(`
      INSERT INTO credit_ledger (uid, delta, reason, ref, note, balanceAfter)
      VALUES (?, 5, 'purchase', ?, 'NewebPay TN_TEST_123', 15)
    `).run(testUid, testOrderNo);

    // 3. Analysis failure refund (+1)
    const refundRef = `analysis:1001:attempt_${Date.now()}`;
    db.prepare(`
      INSERT INTO credit_ledger (uid, delta, reason, ref, note, balanceAfter)
      VALUES (?, 1, 'refund', ?, 'Refund for failed analysis #1001', 16)
    `).run(testUid, refundRef);

    // 4. Positive Admin Adjust (+2)
    db.prepare(`
      INSERT INTO credit_ledger (uid, delta, reason, ref, note, balanceAfter)
      VALUES (?, 2, 'admin_adjust', ?, 'Customer satisfaction credit', 18)
    `).run(testUid, `anomaly:${testUid}`);

    // 5. Consume credit (-1) with fileId 1001
    // Insert file_meta for fileId 1001
    const dummyHash = "h".repeat(64);
    db.prepare(`
      INSERT INTO file_meta (id, user, filename, analysisType, filePath, reportPath, hash, status)
      VALUES (1001, ?, 'TargetBankingApp.apk', 'static', 'uploads/test/target.apk', 'reports/test/static.json', ?, 'done')
    `).run(testUid, dummyHash);

    db.prepare(`
      INSERT INTO credit_ledger (uid, delta, reason, ref, note, balanceAfter)
      VALUES (?, -1, 'consume', ?, 'Analysis run for #1001', 17)
    `).run(testUid, `analysis:1001:${testUid}`);

    // 6. Negative Admin Adjust (-1)
    db.prepare(`
      INSERT INTO credit_ledger (uid, delta, reason, ref, note, balanceAfter)
      VALUES (?, -1, 'admin_adjust', ?, 'Duplicate grant adjustment', 16)
    `).run(testUid, `adj:penalty:${testUid}`);

    // ── Test 1: getMemberCreditHistory double-entry parity & additions/deductions ──
    const history = await getMemberCreditHistory(testUid, baseUrl);
    assert(history.additions.length >= 4, "Must retrieve all 4 positive credit additions");
    assert(history.deductions.length >= 2, "Must retrieve both credit deductions");

    // Verify additions contents
    const purchaseRow = history.additions.find((a) => a.reason === "purchase");
    assert(purchaseRow, "Purchase addition row must exist");
    assert.strictEqual(purchaseRow.orderNo, testOrderNo);
    assert.strictEqual(purchaseRow.amt, 6400);
    assert.strictEqual(purchaseRow.usdAmt, 200);
    // Strict Access Control: Unclaimed receipt must have null receiptUrl
    assert.strictEqual(purchaseRow.receiptIssuedAt, null, "Unclaimed order receiptIssuedAt must be null");
    assert.strictEqual(purchaseRow.buyerName, null, "Unclaimed order buyerName must be null");
    assert.strictEqual(purchaseRow.receiptUrl, null, "Unclaimed order receiptUrl must be strictly null (anti-bypass)");

    const signupRow = history.additions.find((a) => a.reason === "signup");
    assert(signupRow, "Signup addition row must exist");
    assert.strictEqual(signupRow.delta, 10);

    const refundRow = history.additions.find((a) => a.reason === "refund");
    assert(refundRow, "Refund addition row must exist");
    assert.strictEqual(refundRow.delta, 1);

    // Verify deductions contents
    const consumeRow = history.deductions.find((d) => d.reason === "consume");
    assert(consumeRow, "Consume deduction row must exist");
    assert.strictEqual(consumeRow.fileId, 1001, "fileId must be parsed from composite ref");
    assert.strictEqual(consumeRow.filename, "TargetBankingApp.apk", "filename must match file_meta");
    assert.strictEqual(consumeRow.analysisType, "static", "analysisType must match file_meta");

    console.log("✓ Test 1: getMemberCreditHistory full additions/deductions & anti-bypass receiptUrl:null verified");

    // ── Test 2: HTTP GET /api/member/credits/history ────────────────────────
    const httpHistoryRes = await fetch(`${baseUrl}/api/member/credits/history`, {
      headers: { Authorization: `Bearer test-token-${testUid}` },
    });
    assert.strictEqual(httpHistoryRes.status, 200, "Authenticated history endpoint must return 200");
    const httpHistory = (await httpHistoryRes.json()) as any;
    assert.strictEqual(httpHistory.additions.length, history.additions.length);
    assert.strictEqual(httpHistory.deductions.length, history.deductions.length);

    // Negative: Unauthenticated request must return 401
    const unauthHistoryRes = await fetch(`${baseUrl}/api/member/credits/history`);
    assert.strictEqual(unauthHistoryRes.status, 401, "Unauthenticated request must return 401");
    console.log("✓ Test 2: HTTP GET /api/member/credits/history auth & response contract verified");

    // ── Test 3: Receipt Claim Validation & IDOR Protection ───────────────────
    // 3.1 Company name validation (< 2 chars or whitespace only)
    const emptyNameRes = await fetch(`${baseUrl}/api/orders/${testOrderNo}/receipt/claim`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer test-token-${testUid}`,
      },
      body: JSON.stringify({ companyName: "   " }),
    });
    assert.strictEqual(emptyNameRes.status, 400, "Whitespace companyName must return 400");

    const shortNameRes = await fetch(`${baseUrl}/api/orders/${testOrderNo}/receipt/claim`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer test-token-${testUid}`,
      },
      body: JSON.stringify({ companyName: "X" }),
    });
    assert.strictEqual(shortNameRes.status, 400, "< 2 char companyName must return 400");

    // 3.2 IDOR Defense: Claiming another user's order must fail with 403
    const idorClaimRes = await fetch(`${baseUrl}/api/orders/${otherOrderNo}/receipt/claim`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer test-token-${testUid}`,
      },
      body: JSON.stringify({ companyName: "Malicious Corp" }),
    });
    assert.strictEqual(idorClaimRes.status, 403, "Claiming another user's order must return 403 Forbidden");

    // 3.3 Non-existent order must fail with 404
    const notFoundClaimRes = await fetch(`${baseUrl}/api/orders/NON_EXISTENT_ORDER/receipt/claim`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer test-token-${testUid}`,
      },
      body: JSON.stringify({ companyName: "Valid Company" }),
    });
    assert.strictEqual(notFoundClaimRes.status, 404, "Non-existent order must return 404");

    console.log("✓ Test 3: Receipt Claim input validation, length bounds & IDOR defenses verified");

    // ── Test 4: Successful Claim & Once-Only Atomic Lock ────────────────────
    const validCompanyName = "National Taiwan University - Cyber Sec Lab";
    const claimRes = await fetch(`${baseUrl}/api/orders/${testOrderNo}/receipt/claim`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer test-token-${testUid}`,
      },
      body: JSON.stringify({ companyName: `  ${validCompanyName}  ` }),
    });
    assert.strictEqual(claimRes.status, 200, "Valid claim request must succeed with 200");
    const claimBody = (await claimRes.json()) as any;
    assert.strictEqual(claimBody.ok, true);
    assert.strictEqual(claimBody.buyerName, validCompanyName, "Buyer name must be trimmed");
    assert(claimBody.receiptIssuedAt, "receiptIssuedAt timestamp must be returned");
    assert(claimBody.receiptUrl.includes("/receipt?sig="), "Valid signed receipt URL must be returned");

    // 4.1 Verify once-only immutability lock: Second claim MUST return 409 Conflict
    const secondClaimRes = await fetch(`${baseUrl}/api/orders/${testOrderNo}/receipt/claim`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer test-token-${testUid}`,
      },
      body: JSON.stringify({ companyName: "Attempted Name Modification Corp" }),
    });
    assert.strictEqual(secondClaimRes.status, 409, "Second claim attempt must return 409 Conflict (immutable)");

    // 4.2 Verify alias route /api/newebpay/orders/:orderNo/receipt/claim also respects the lock
    const aliasClaimRes = await fetch(`${baseUrl}/api/newebpay/orders/${testOrderNo}/receipt/claim`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer test-token-${testUid}`,
      },
      body: JSON.stringify({ companyName: "Attempted Name Modification Corp" }),
    });
    assert.strictEqual(aliasClaimRes.status, 409, "Alias route must also return 409 Conflict");

    // 4.3 Verify history now returns the active receiptUrl
    const updatedHistory = await getMemberCreditHistory(testUid, baseUrl);
    const updatedPurchaseRow = updatedHistory.additions.find((a) => a.orderNo === testOrderNo);
    assert(updatedPurchaseRow, "Updated purchase row must exist");
    assert.strictEqual(updatedPurchaseRow.buyerName, validCompanyName);
    assert(updatedPurchaseRow.receiptIssuedAt !== null, "receiptIssuedAt must be populated");
    assert(updatedPurchaseRow.receiptUrl !== null, "receiptUrl must now be accessible");
    assert(updatedPurchaseRow.receiptUrl.includes("sig="), "receiptUrl must contain valid signature");

    console.log("✓ Test 4: Successful claim, once-only 409 lock & history receiptUrl unlocking verified");

    // ── Test 5: Official Receipt HTML Rendering with buyerName ──────────────
    const receiptUrlToFetch = claimBody.receiptUrl.startsWith("http")
      ? claimBody.receiptUrl
      : `${baseUrl}${claimBody.receiptUrl}`;
    const receiptPageRes = await fetch(receiptUrlToFetch);
    assert.strictEqual(receiptPageRes.status, 200, "Official receipt web view must return 200 OK");
    const receiptHtml = await receiptPageRes.text();
    assert(receiptHtml.includes(validCompanyName), "Receipt HTML must contain claimed company name");
    assert(receiptHtml.includes("researcher@lab.edu"), "Receipt HTML must include user account email");
    assert(receiptHtml.includes("OFFICIAL RECEIPT"), "Receipt HTML must include official title");
    assert(receiptHtml.includes("SUPREMA TECHNOLOGIES LTD"), "Receipt HTML must include company issuer");
    assert(receiptHtml.includes("<svg"), "Receipt HTML must include official vector seal");

    console.log("✓ Test 5: Official receipt web view rendering with buyerName and vector seal verified");

    // ── Test 6: Webhook Email Decoupling Verification ───────────────────────
    // Payment notification unlocks credits or job without sending emails
    const webhookOrderNo = `CMAA_NOTIFY_${Date.now()}`;
    db.prepare(`
      INSERT INTO newebpay_orders (orderNo, uid, credits, amt, usdAmt, fxRate, status)
      VALUES (?, ?, 1, 1280, 40, 32.0, 'pending')
    `).run(webhookOrderNo, testUid);

    // Call notify directly via mocked internal payment
    const hashKey = process.env.NEWEBPAY_HASH_KEY || "12345678901234567890123456789012";
    const hashIv = process.env.NEWEBPAY_HASH_IV || "1234567890123456";

    function encryptTradeInfo(plain: string): string {
      const cipher = crypto.createCipheriv("aes-256-cbc", hashKey.padEnd(32, "0").slice(0, 32), hashIv.padEnd(16, "0").slice(0, 16));
      return cipher.update(plain, "utf8", "hex") + cipher.final("hex");
    }

    const tradeInfoStr = new URLSearchParams({
      Status: "SUCCESS",
      MerchantOrderNo: webhookOrderNo,
      Amt: "1280",
      TradeNo: "TN_NOTIFY_999",
    }).toString();
    const tradeInfo = encryptTradeInfo(tradeInfoStr);
    const tradeSha = crypto
      .createHash("sha256")
      .update(`HashKey=${hashKey}&${tradeInfo}&HashIV=${hashIv}`)
      .digest("hex")
      .toUpperCase();

    const origGrant = CreditBank.grantPurchase;
    try {
      CreditBank.grantPurchase = async () => ({ ok: true, balance: 10 });

      const notifyRes = await fetch(`${baseUrl}/api/newebpay/notify`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          Status: "SUCCESS",
          MerchantID: process.env.NEWEBPAY_MERCHANT_ID || "TEST_MERCHANT",
          Version: "2.0",
          TradeInfo: tradeInfo,
          TradeSha: tradeSha,
        }).toString(),
      });

      assert.strictEqual(notifyRes.status, 200, "Webhook notify must return 200 OK");
      const notifyText = await notifyRes.text();
      assert.strictEqual(notifyText, "ok");

      // Verify order is paid
      const paidOrderRow = db.prepare("SELECT status, receiptSentAt, buyerName, receiptIssuedAt FROM newebpay_orders WHERE orderNo = ?").get(webhookOrderNo) as any;
      assert.strictEqual(paidOrderRow.status, "paid", "Order status must be updated to paid");
      assert.strictEqual(paidOrderRow.receiptSentAt, null, "Decoupled webhook must NEVER send automated receipt email");
      assert.strictEqual(paidOrderRow.receiptIssuedAt, null, "receiptIssuedAt must remain null until on-demand claimed");

      console.log("✓ Test 6: Webhook decoupling verified: 200 OK, zero automated email sending");
    } finally {
      CreditBank.grantPurchase = origGrant;
    }

    console.log("\nAll Self-Serve Receipt & Credit Journal Unit Tests Passed! ✅\n");
  } finally {
    // Teardown
    db.prepare("DELETE FROM newebpay_orders WHERE orderNo IN (?, ?, ?)").run(testOrderNo, otherOrderNo, `CMAA_NOTIFY_${Date.now()}`);
    db.prepare("DELETE FROM credit_ledger WHERE uid IN (?, ?)").run(testUid, otherUid);
    db.prepare("DELETE FROM file_meta WHERE id = 1001").run();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

main().catch((err) => {
  console.error("Test failed with error:", err);
  if (server) server.close();
  process.exit(1);
});
