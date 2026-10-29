// server/newebpay.ts — NewebPay MPG checkout for credit purchases.
// Replaces the Stripe flow: the frontend fetches signed form fields here, then
// foreground-form-posts them to the MPG gateway (iframe/background post is forbidden
// by NewebPay — error MPG02005). Spec: NDNF-1.2.3.

import express from "express";
import crypto from "crypto";
import { getAuth } from "firebase-admin/auth";
import { db } from "./db";
import { getTwdPerUsd } from "./fx";
import { CreditBank } from "./services/creditBank";

import { GuestJob } from "./models/GuestJob";
import {
  sendReceiptEmailSafe,
  generateReceiptHtml,
  type ReceiptEmailPayload,
} from "./services/receiptMailer";
import { getMemberCreditHistory } from "./services/creditHistory";

const router = express.Router();

// ── Config (fill these in .env once the merchant account is approved) ──────
const MERCHANT_ID = process.env.NEWEBPAY_MERCHANT_ID ?? "";
const HASH_KEY = process.env.NEWEBPAY_HASH_KEY ?? "";
const HASH_IV = process.env.NEWEBPAY_HASH_IV ?? "";
// Test: https://ccore.newebpay.com  ·  Production: https://core.newebpay.com
export function getGatewayUrl(): string {
  const raw = (process.env.NEWEBPAY_GATEWAY ?? "https://ccore.newebpay.com").trim().replace(/\/+$/, "");
  return raw.endsWith("/MPG/mpg_gateway") ? raw : `${raw}/MPG/mpg_gateway`;
}
export function getClientUrl(): string {
  return (process.env.CLIENT_URL ?? "").replace(/\/+$/, "");
}
const CLIENT_URL = process.env.CLIENT_URL ?? "";
// 1 credit = 1 upload, priced in USD — the platform is international and USD is
// the listed price everywhere. NewebPay can only *charge* TWD (MPG Amt is an
// integer in TWD; the spec has no currency parameter), so each order converts
// USD→TWD at checkout using the cached rate from fx.ts. The TWD figure therefore
// moves with the market while the USD price stays fixed.
const USD_PER_CREDIT = Number(process.env.USD_PER_CREDIT ?? 40);

// Same package ids as the frontend BuyCredits component.
const VALID_PACKAGES: Record<string, number> = {
  starter: 1,
  pro: 5,
  power: 10,
  enterprise: 25,
};

/** USD list price and the TWD actually charged, at today's rate. */
export function priceFor(credits: number, packageId?: string) {
  const isProbeAllowed = process.env.NODE_ENV !== "production";
  if (process.env.TEST_PAYMENT_PROBE === "true" && isProbeAllowed && packageId?.toLowerCase() === "starter") {
    return {
      usd: 1,
      twd: 1,
      rate: 1,
      source: "test_probe",
      fetchedAt: new Date().toISOString(),
      stale: false,
    };
  }
  const { rate, source, fetchedAt, stale } = getTwdPerUsd();
  const usd = credits * USD_PER_CREDIT;
  return { usd, twd: Math.round(usd * rate), rate, source, fetchedAt, stale };
}

if (process.env.TEST_PAYMENT_PROBE === "true") {
  if (process.env.NODE_ENV === "production") {
    throw new Error("[FATAL SECURITY] TEST_PAYMENT_PROBE cannot be enabled in production environment!");
  }
  console.warn("====================================================================");
  console.warn(" [SECURITY WARNING] TEST_PAYMENT_PROBE IS ENABLED!");
  console.warn(" Starter Package credit price is overridden to NT$ 1.00 / US$ 1.00.");
  console.warn(" ENSURE THIS FLAG IS DISABLED IN REAL PRODUCTION DEPLOYMENTS.");
  console.warn("====================================================================");
}

db.exec(`
  CREATE TABLE IF NOT EXISTS newebpay_orders (
    orderNo   TEXT PRIMARY KEY,          -- MerchantOrderNo sent to NewebPay
    uid       TEXT NOT NULL,             -- Firebase uid to credit on success
    credits   INTEGER NOT NULL,
    amt       INTEGER NOT NULL,          -- charged amount in TWD
    status    TEXT NOT NULL DEFAULT 'pending'
              CHECK (status IN ('pending','paid','failed')),
    tradeNo   TEXT,                      -- NewebPay trade number (on success)
    createdAt TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  );
`);

// Added when pricing moved from fixed TWD to USD-pegged. `amt` stays the TWD
// charged (that is what NewebPay echoes back and what the notify guard compares);
// these record what the TWD was derived from, for receipts and reconciliation.
// `paidAt` was added with the credit audit: reconciliation needs to know *when* a
// payment was confirmed, not when the order was opened, to place it in the right
// daily window (an order can be created one day and paid the next).
for (const [col, decl] of [
  ["usdAmt", "REAL"],
  ["fxRate", "REAL"],
  ["paidAt", "TEXT"],
  ["jobId", "TEXT"],
  ["orderType", "TEXT DEFAULT 'credits'"],
  ["receiptEmail", "TEXT"],
  ["receiptSentAt", "TEXT"],
  ["buyerName", "TEXT"],
  ["receiptIssuedAt", "TEXT"],
] as const) {
  const exists = (db.prepare("PRAGMA table_info(newebpay_orders)").all() as {
    name: string;
  }[]).some((c) => c.name === col);
  if (!exists) db.exec(`ALTER TABLE newebpay_orders ADD COLUMN ${col} ${decl}`);
}

// The credit audit asks "which orders did this user pay for in this window?" once
// per user per night; the primary key on orderNo is no help for that. Declared
// after the ALTER loop because it names a column that loop may have just added.
db.exec(`
  CREATE INDEX IF NOT EXISTS newebpay_orders_uid_paid
    ON newebpay_orders (uid, status, paidAt);
  CREATE INDEX IF NOT EXISTS newebpay_orders_jobId
    ON newebpay_orders (jobId);
`);

const insertOrder = db.prepare(
  `INSERT INTO newebpay_orders (orderNo, uid, credits, amt, usdAmt, fxRate, orderType, receiptEmail)
   VALUES (?, ?, ?, ?, ?, ?, 'credits', ?)`
);
const insertGuestOrder = db.prepare(
  `INSERT INTO newebpay_orders (orderNo, uid, credits, amt, usdAmt, fxRate, jobId, orderType, receiptEmail)
   VALUES (?, 'guest', 0, ?, ?, ?, ?, 'guest_report', ?)`
);
const findOrder = db.prepare("SELECT * FROM newebpay_orders WHERE orderNo = ?");
// Atomic pending→paid transition makes the notify handler idempotent.
const markPaid = db.prepare(
  `UPDATE newebpay_orders
      SET status = 'paid', tradeNo = ?, paidAt = ?
    WHERE orderNo = ? AND status = 'pending'`
);
// Dedicated atomic statement for receipt delivery state (decoupled idempotency).
const markReceiptSent = db.prepare(
  `UPDATE newebpay_orders
      SET receiptSentAt = ?
    WHERE orderNo = ? AND receiptSentAt IS NULL`
);

interface OrderRow {
  orderNo: string;
  uid: string;
  credits: number;
  amt: number;
  status: string;
  jobId?: string | null;
  orderType?: string | null;
  tradeNo?: string | null;
  createdAt?: string | null;
  usdAmt?: number | null;
  fxRate?: number | null;
  paidAt?: string | null;
  receiptEmail?: string | null;
  receiptSentAt?: string | null;
  buyerName?: string | null;
  receiptIssuedAt?: string | null;
}


function buildReceiptPayload(
  order: OrderRow,
  paidAt: string,
  tradeNo: string,
  webReceiptUrl: string,
  recipientEmail?: string
): ReceiptEmailPayload {
  return {
    orderNo: order.orderNo,
    recipientEmail: recipientEmail || order.receiptEmail || "",
    credits: order.credits,
    amt: order.amt,
    usdAmt: order.usdAmt ?? (order.amt / (order.fxRate || 32)),
    orderType: (order.orderType as any) || "credits",
    tradeNo: tradeNo || order.tradeNo || "",
    paidAt,
    webReceiptUrl,
    buyerName: order.buyerName || undefined,
    receiptIssuedAt: order.receiptIssuedAt || undefined,
  };
}

export function generateReceiptSignature(orderNo: string, paidAt?: string | null): string {
  const secret = HASH_KEY || HASH_IV || process.env.RECEIPT_SIGNATURE_SECRET || "cmaa_receipt_secret_salt";
  return crypto
    .createHmac("sha256", secret)
    .update(`${orderNo}:${paidAt || ""}`)
    .digest("hex");
}

// ── Crypto helpers (manual §4.1) ────────────────────────────────────────────
function aesEncrypt(plain: string): string {
  const key = process.env.NEWEBPAY_HASH_KEY || HASH_KEY;
  const iv = process.env.NEWEBPAY_HASH_IV || HASH_IV;
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  return cipher.update(plain, "utf8", "hex") + cipher.final("hex");
}

function aesDecrypt(hex: string): string {
  const key = process.env.NEWEBPAY_HASH_KEY || HASH_KEY;
  const iv = process.env.NEWEBPAY_HASH_IV || HASH_IV;
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  return decipher.update(hex, "hex", "utf8") + decipher.final("utf8");
}

function tradeSha(encryptedTradeInfo: string): string {
  const key = process.env.NEWEBPAY_HASH_KEY || HASH_KEY;
  const iv = process.env.NEWEBPAY_HASH_IV || HASH_IV;
  return crypto
    .createHash("sha256")
    .update(`HashKey=${key}&${encryptedTradeInfo}&HashIV=${iv}`)
    .digest("hex")
    .toUpperCase();
}

// Decrypted TradeInfo is JSON when RespondType=JSON, querystring otherwise.
function parseTradeInfo(plain: string): any {
  try {
    return JSON.parse(plain);
  } catch {
    return Object.fromEntries(new URLSearchParams(plain));
  }
}

// ── Auth middleware (same contract as checkout.ts) ──────────────────────────
async function requireAuth(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) {
  const token = req.headers.authorization?.split("Bearer ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  if (process.env.NODE_ENV === "test" && token.startsWith("test-token-")) {
    const uid = token.replace("test-token-", "");
    (req as any).uid = uid;
    (req as any).email = `${uid}@example.com`;
    return next();
  }

  try {
    const decoded = await getAuth().verifyIdToken(token);
    if (!decoded.email_verified) {
      return res.status(403).json({ error: "email_not_verified" });
    }
    (req as any).uid = decoded.uid;
    (req as any).email = decoded.email;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// ── GET /api/newebpay/pricing ───────────────────────────────────────────────
// Public. Lets the frontend show the exact TWD it is about to charge next to the
// USD list price, so the gateway page never reveals an amount the user has not
// already seen. Keep the package ids in sync with CREDIT_PACKAGES on the client.
router.get("/pricing", (_req, res) => {
  const { rate, source, fetchedAt, stale } = getTwdPerUsd();
  return res.json({
    usdPerCredit: USD_PER_CREDIT,
    currency: "TWD", // what NewebPay actually charges
    rate,
    rateSource: source,
    rateFetchedAt: fetchedAt,
    rateIsFallback: stale,
    packages: Object.entries(VALID_PACKAGES).map(([id, credits]) => {
      const { usd, twd } = priceFor(credits, id);
      return { id, credits, usd, twd };
    }),
  });
});

// ── POST /api/newebpay/checkout ─────────────────────────────────────────────
// Returns the signed fields the frontend form-posts to the MPG gateway.
router.post("/checkout", requireAuth, async (req, res) => {
  const { packageId } = req.body;
  const credits = VALID_PACKAGES[packageId];
  if (!credits) return res.status(400).json({ error: "Invalid package" });

  const uid = (req as any).uid as string;
  const email = (req as any).email as string;
  const { usd, twd: amt, rate } = priceFor(credits, packageId);

  // If NewebPay keys are not configured, allow local development testing simulation
  if (!MERCHANT_ID || !HASH_KEY || !HASH_IV) {
    if (process.env.NODE_ENV !== "production") {
      const simOrderNo = `SIM${Date.now()}`;
      await CreditBank.grantPurchase({
        uid,
        orderNo: simOrderNo,
        credits,
        note: `Dev simulation · ${credits} credits`,
      });
      console.log(`[Dev Simulation] Auto-credited ${credits} to user ${uid}`);
      return res.json({
        simulated: true,
        message: "Payment simulated successfully in development mode.",
        credits,
        amt,
      });
    }
    return res.status(503).json({ error: "NewebPay is not configured" });
  }

  // MerchantOrderNo: unique, ≤30 chars, [A-Za-z0-9_] only.
  const orderNo = `CMAA${Date.now()}${Math.floor(Math.random() * 9000 + 1000)}`;
  const receiptEmail = (req.body?.receiptEmail as string)?.trim() || (email ?? "");
  insertOrder.run(orderNo, uid, credits, amt, usd, rate, receiptEmail);

  const tradeInfoPlain = new URLSearchParams({
    MerchantID: MERCHANT_ID,
    RespondType: "JSON",
    TimeStamp: String(Math.floor(Date.now() / 1000)),
    Version: "2.0",
    LangType: "en",
    MerchantOrderNo: orderNo,
    Amt: String(amt),
    // ItemDesc is Varchar(50); the USD price is included so the gateway page and
    // the customer's receipt both show what the TWD figure was derived from.
    ItemDesc: `${credits} Analysis Credits (US$${usd})`,
    Email: receiptEmail,
    NotifyURL: `${CLIENT_URL}/api/newebpay/notify`,
    ReturnURL: `${CLIENT_URL}/api/newebpay/return`,
    ClientBackURL: `${CLIENT_URL}/app`,
    CREDIT: "1",
  }).toString();

  const encrypted = aesEncrypt(tradeInfoPlain);

  return res.json({
    gateway: getGatewayUrl(),
    merchantID: MERCHANT_ID,
    tradeInfo: encrypted,
    tradeSha: tradeSha(encrypted),
    version: "2.0",
    // Echoed back so the client can confirm the figures it displayed are the
    // ones that were signed, rather than a rate that moved mid-session.
    usd,
    twd: amt,
    rate,
  });
});

export function buildGuestTradeInfoParams(params: {
  merchantId: string;
  orderNo: string;
  amt: number;
  itemDesc: string;
  receiptEmail?: string;
  clientUrl?: string;
}): URLSearchParams {
  return new URLSearchParams({
    MerchantID: params.merchantId,
    RespondType: "JSON",
    TimeStamp: String(Math.floor(Date.now() / 1000)),
    Version: "2.0",
    LangType: "en",
    MerchantOrderNo: params.orderNo,
    Amt: String(params.amt),
    ItemDesc: params.itemDesc,
    Email: (params.receiptEmail ?? "").trim(),
    NotifyURL: `${params.clientUrl ?? CLIENT_URL}/api/newebpay/notify`,
    ReturnURL: `${params.clientUrl ?? CLIENT_URL}/api/newebpay/return`,
    ClientBackURL: `${params.clientUrl ?? CLIENT_URL}/app`,
    CREDIT: "1",
  });
}

// ── POST /api/newebpay/guest-checkout ─────────────────────────────────────────
// Public endpoint for anonymous users to pay for a completed analysis report.
// Strict business rule: Only allowed if the job is 'done' and not yet paid!
router.post("/guest-checkout", async (req, res) => {
  const { jobId, email } = req.body ?? {};
  if (!jobId || typeof jobId !== "string") {
    return res.status(400).json({ error: "Missing or invalid jobId" });
  }

  const job = GuestJob.findByJobId(jobId);
  if (!job) {
    return res.status(404).json({ error: "Job not found" });
  }

  // Verify guest secretKey
  const clientSecret = (req.headers["x-guest-secret"] as string) || (req.body?.secretKey as string);
  if (job.secretKey && (!clientSecret || job.secretKey !== clientSecret)) {
    return res.status(403).json({ error: "forbidden", message: "Invalid or missing authorization secret." });
  }

  if (job.status !== "done") {
    return res.status(400).json({ error: "Report is not ready yet. Please wait for analysis to complete." });
  }

  if (job.isPaid) {
    return res.status(400).json({ error: "This report has already been paid for and unlocked." });
  }

  // If NewebPay keys are not configured, allow local development testing simulation
  if (!MERCHANT_ID || !HASH_KEY || !HASH_IV) {
    if (process.env.NODE_ENV !== "production") {
      const downloadToken = crypto.randomBytes(32).toString("hex");
      GuestJob.update(jobId, {
        isPaid: 1,
        downloadToken,
        downloadsRemaining: 5,
        paidAt: new Date().toISOString(),
      });
      console.log(`[Dev Simulation] Auto-unlocked guest report ${jobId} with token ${downloadToken.slice(0, 8)}...`);
      return res.json({
        simulated: true,
        message: "Payment simulated successfully in development mode.",
        jobId,
        downloadToken,
      });
    }
    return res.status(503).json({ error: "NewebPay is not configured" });
  }

  // 1 single report = USD_PER_CREDIT (default 40)
  const { usd, twd: amt, rate } = priceFor(1);

  const orderNo = `CMAAG${Date.now()}${Math.floor(Math.random() * 9000 + 1000)}`;
  const receiptEmail = (req.body?.receiptEmail as string)?.trim() || (email as string)?.trim() || "";
  insertGuestOrder.run(orderNo, amt, usd, rate, jobId, receiptEmail);

  const tradeInfoPlain = buildGuestTradeInfoParams({
    merchantId: MERCHANT_ID,
    orderNo,
    amt,
    itemDesc: `Security Report: ${job.filename || "App Analysis"} (US$${usd})`,
    receiptEmail,
  }).toString();

  const encrypted = aesEncrypt(tradeInfoPlain);

  return res.json({
    gateway: getGatewayUrl(),
    merchantID: MERCHANT_ID,
    tradeInfo: encrypted,
    tradeSha: tradeSha(encrypted),
    version: "2.0",
    usd,
    twd: amt,
    rate,
    orderNo,
    jobId,
  });
});

// Shared verify+decrypt for notify/return payloads. Returns null if invalid.
function verifyPayload(body: any): any | null {
  const { TradeInfo, TradeSha } = body ?? {};
  if (!TradeInfo || !TradeSha) return null;
  if (tradeSha(TradeInfo) !== TradeSha) {
    console.error("NewebPay: TradeSha mismatch");
    return null;
  }
  try {
    return parseTradeInfo(aesDecrypt(TradeInfo));
  } catch (err) {
    console.error("NewebPay: TradeInfo decrypt failed", err);
    return null;
  }
}

// ── POST /api/newebpay/notify ───────────────────────────────────────────────
// Background payment notification. NewebPay retries unless we answer HTTP 200.
router.post("/notify", async (req, res) => {
  const info = verifyPayload(req.body);
  if (!info) return res.status(400).send("invalid payload");

  const result = info.Result ?? info;
  const orderNo = result.MerchantOrderNo;
  const order = findOrder.get(orderNo) as OrderRow | undefined;

  if (!order) {
    console.error("NewebPay notify: unknown order", orderNo);
    return res.status(400).send("unknown order");
  }

  if (info.Status !== "SUCCESS") {
    console.warn(`NewebPay notify: order ${orderNo} failed (${info.Status})`);
    return res.status(200).send("ok");
  }

  if (Number(result.Amt) !== order.amt) {
    console.error(
      `NewebPay notify: amount mismatch on ${orderNo} (got ${result.Amt}, expected ${order.amt})`
    );
    return res.status(400).send("amount mismatch");
  }

  // Idempotent: only the first successful notify credits the user or unlocks report.
  const paidAt = new Date().toISOString();
  const updated = markPaid.run(result.TradeNo ?? null, paidAt, orderNo);
  if (updated.changes === 1) {
    if (order.orderType === "guest_report" && order.jobId) {
      const downloadToken = crypto.randomBytes(32).toString("hex");
      GuestJob.update(order.jobId, {
        isPaid: 1,
        downloadToken,
        downloadsRemaining: 5,
        paidAt,
      });
      console.log(`NewebPay: unlocked guest report ${order.jobId} (${orderNo})`);
    } else {
      await CreditBank.grantPurchase({
        uid: order.uid,
        orderNo,
        credits: order.credits,
        note: `NewebPay ${result.TradeNo ?? "?"} · NT$${order.amt}`,
      });
      console.log(`NewebPay: credited ${order.credits} to ${order.uid} (${orderNo})`);
    }
  }

  return res.status(200).send("ok");
});

// ── POST /api/newebpay/return ───────────────────────────────────────────────
// Browser lands here after payment; credits are granted by /notify, this only
// routes the user back to the app with a status flag.
router.post("/return", (req, res) => {
  const info = verifyPayload(req.body);
  const ok = info?.Status === "SUCCESS";
  const result = info?.Result ?? info;
  const orderNo = result?.MerchantOrderNo;
  const order = orderNo ? (findOrder.get(orderNo) as OrderRow | undefined) : undefined;

  if (order && order.orderType === "guest_report" && order.jobId) {
    const job = GuestJob.findByJobId(order.jobId);
    const tokenParam = job?.downloadToken ? `&token=${job.downloadToken}` : "";
    return res.redirect(
      `${CLIENT_URL}/app?guest_job=${order.jobId}&payment=${ok ? "success" : "failed"}${tokenParam}`
    );
  }

  return res.redirect(`${CLIENT_URL}/app?credits=${ok ? "success" : "failed"}`);
});

// ── GET /api/newebpay/orders/:orderNo/receipt ──────────────────────────────
// Browser-viewable official receipt route.
// Bypasses Gmail/Outlook inline SVG stripping and provides seamless A4 printing.
// IDOR defense: requires valid HMAC signature generated at payment time.
router.get("/orders/:orderNo/receipt", (req, res) => {
  const { orderNo } = req.params;
  const order = findOrder.get(orderNo) as OrderRow | undefined;
  if (!order) {
    return res.status(404).send("Receipt not found");
  }
  if (order.status !== "paid") {
    return res.status(400).send("Order has not been paid yet");
  }

  const expectedSig = generateReceiptSignature(orderNo, order.paidAt);
  const clientSig = typeof req.query.sig === "string" ? req.query.sig.trim() : "";
  const validSig =
    clientSig.length === expectedSig.length &&
    crypto.timingSafeEqual(Buffer.from(clientSig), Buffer.from(expectedSig));

  if (!validSig) {
    return res
      .status(403)
      .send("Unauthorized: Invalid receipt verification signature");
  }

  const html = generateReceiptHtml({
    orderNo: order.orderNo,
    recipientEmail: order.receiptEmail || "",
    credits: order.credits,
    amt: order.amt,
    usdAmt: order.usdAmt ?? (order.amt / (order.fxRate || 32)),
    orderType: (order.orderType as any) || "credits",
    tradeNo: order.tradeNo || undefined,
    paidAt: order.paidAt || undefined,
    webReceiptUrl: `${getClientUrl()}/api/newebpay/orders/${orderNo}/receipt?sig=${expectedSig}`,
    isWeb: true,
    buyerName: order.buyerName || undefined,
    receiptIssuedAt: order.receiptIssuedAt || undefined,
  });

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  return res.send(html);
});

// ── POST /api/newebpay/orders/:orderNo/receipt/claim ──────────────────────
// On-demand formal receipt claim for members.
// Validates ownership, paid status, companyName length (2-120 chars), and enforces once-only lock.
export const claimReceiptHandler = async (req: express.Request, res: express.Response) => {
  const { orderNo } = req.params;
  const order = findOrder.get(orderNo) as OrderRow | undefined;
  if (!order) {
    return res.status(404).json({ error: "Order not found" });
  }

  const requesterUid = (req as any).uid;
  if (order.uid !== requesterUid) {
    return res.status(403).json({ error: "Forbidden: Not the owner of this order" });
  }

  if (order.status !== "paid") {
    return res.status(400).json({ error: "Order has not been paid yet" });
  }

  const { companyName } = req.body || {};
  if (
    typeof companyName !== "string" ||
    companyName.trim().length < 2 ||
    companyName.trim().length > 120
  ) {
    return res.status(400).json({
      error: "Invalid company name. Must be a non-empty string between 2 and 120 characters.",
    });
  }

  const sanitizedBuyerName = companyName.trim();
  const receiptIssuedAt = new Date().toISOString();

  // Strict once-only atomic lock
  const updateResult = db
    .prepare(
      `UPDATE newebpay_orders
          SET buyerName = ?, receiptIssuedAt = ?
        WHERE orderNo = ? AND receiptIssuedAt IS NULL`
    )
    .run(sanitizedBuyerName, receiptIssuedAt, orderNo);

  if (updateResult.changes === 0) {
    return res.status(409).json({
      error: "Receipt has already been claimed for this order and cannot be modified.",
      buyerName: order.buyerName,
      receiptIssuedAt: order.receiptIssuedAt,
    });
  }

  const sig = generateReceiptSignature(orderNo, order.paidAt);
  const clientUrl = getClientUrl();
  const receiptUrl = `${clientUrl}/api/newebpay/orders/${orderNo}/receipt?sig=${sig}`;

  return res.json({
    ok: true,
    receiptUrl,
    buyerName: sanitizedBuyerName,
    receiptIssuedAt,
  });
};

router.post("/orders/:orderNo/receipt/claim", requireAuth, claimReceiptHandler);

// ── GET /api/newebpay/member/credits/history ──────────────────────────────
// Authenticated route returning user's double-entry credit journal
export const memberCreditHistoryHandler = async (req: express.Request, res: express.Response) => {
  const uid = (req as any).uid;
  if (!uid) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  try {
    const history = await getMemberCreditHistory(uid, getClientUrl());
    return res.json(history);
  } catch (err: any) {
    console.error("[Member Credit History Error]:", err);
    return res.status(500).json({ error: "Failed to retrieve credit history" });
  }
};

router.get("/member/credits/history", requireAuth, memberCreditHistoryHandler);

// ── POST /api/newebpay/orders/:orderNo/resend-receipt ──────────────────────
// @deprecated Kept for backward compatibility with existing tests and scripts.
router.post("/orders/:orderNo/resend-receipt", requireAuth, async (req, res) => {
  const { orderNo } = req.params;
  const order = findOrder.get(orderNo) as OrderRow | undefined;
  if (!order) return res.status(404).json({ error: "Order not found" });
  if (order.status !== "paid") return res.status(400).json({ error: "Order not paid" });

  const requesterUid = (req as any).uid;
  const requesterEmail = (req as any).email;
  const adminEmail = process.env.ADMIN_EMAIL || "suprematechnologiesltd@solitesterror.com";
  const isAuthorized =
    order.uid === requesterUid ||
    order.receiptEmail === requesterEmail ||
    requesterEmail === adminEmail ||
    requesterEmail === "suprematechnologiesltd@mail.solitesterror.com";

  if (!isAuthorized) {
    return res.status(403).json({ error: "Forbidden" });
  }

  const paidAt = order.paidAt || new Date().toISOString();
  const sig = generateReceiptSignature(orderNo, paidAt);
  const webReceiptUrl = `${CLIENT_URL}/api/newebpay/orders/${orderNo}/receipt?sig=${sig}`;

  const payload = buildReceiptPayload(order, paidAt, order.tradeNo ?? "", webReceiptUrl, order.receiptEmail || requesterEmail);
  const sendResult = await sendReceiptEmailSafe(payload);

  if (sendResult.success) {
    db.prepare("UPDATE newebpay_orders SET receiptSentAt = ? WHERE orderNo = ?").run(
      new Date().toISOString(),
      orderNo
    );
  }

  return res.json({ success: sendResult.success, sendResult });
});

export default router;

