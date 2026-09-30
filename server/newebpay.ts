// server/newebpay.ts — NewebPay MPG checkout for credit purchases.
// Replaces the Stripe flow: the frontend fetches signed form fields here, then
// foreground-form-posts them to the MPG gateway (iframe/background post is forbidden
// by NewebPay — error MPG02005). Spec: NDNF-1.2.3.

import express from "express";
import crypto from "crypto";
import { getAuth } from "firebase-admin/auth";
import { db } from "./db";
import { getTwdPerUsd } from "./fx";
import { recordCreditChange } from "./credit_audit";

import { GuestJob } from "./models/GuestJob";

const router = express.Router();

// ── Config (fill these in .env once the merchant account is approved) ──────
const MERCHANT_ID = process.env.NEWEBPAY_MERCHANT_ID ?? "";
const HASH_KEY = process.env.NEWEBPAY_HASH_KEY ?? "";
const HASH_IV = process.env.NEWEBPAY_HASH_IV ?? "";
// Test: https://ccore.newebpay.com  ·  Production: https://core.newebpay.com
const GATEWAY_BASE = process.env.NEWEBPAY_GATEWAY ?? "https://ccore.newebpay.com";
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
function priceFor(credits: number) {
  const { rate, source, fetchedAt, stale } = getTwdPerUsd();
  const usd = credits * USD_PER_CREDIT;
  return { usd, twd: Math.round(usd * rate), rate, source, fetchedAt, stale };
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
  `INSERT INTO newebpay_orders (orderNo, uid, credits, amt, usdAmt, fxRate, orderType)
   VALUES (?, ?, ?, ?, ?, ?, 'credits')`
);
const insertGuestOrder = db.prepare(
  `INSERT INTO newebpay_orders (orderNo, uid, credits, amt, usdAmt, fxRate, jobId, orderType)
   VALUES (?, 'guest', 0, ?, ?, ?, ?, 'guest_report')`
);
const findOrder = db.prepare("SELECT * FROM newebpay_orders WHERE orderNo = ?");
// Atomic pending→paid transition makes the notify handler idempotent.
const markPaid = db.prepare(
  `UPDATE newebpay_orders
      SET status = 'paid', tradeNo = ?, paidAt = strftime('%Y-%m-%dT%H:%M:%fZ','now')
    WHERE orderNo = ? AND status = 'pending'`
);

interface OrderRow {
  orderNo: string;
  uid: string;
  credits: number;
  amt: number;
  status: string;
  jobId?: string | null;
  orderType?: string | null;
}

// ── Crypto helpers (manual §4.1) ────────────────────────────────────────────
function aesEncrypt(plain: string): string {
  const cipher = crypto.createCipheriv("aes-256-cbc", HASH_KEY, HASH_IV);
  return cipher.update(plain, "utf8", "hex") + cipher.final("hex");
}

function aesDecrypt(hex: string): string {
  const decipher = crypto.createDecipheriv("aes-256-cbc", HASH_KEY, HASH_IV);
  return decipher.update(hex, "hex", "utf8") + decipher.final("utf8");
}

function tradeSha(encryptedTradeInfo: string): string {
  return crypto
    .createHash("sha256")
    .update(`HashKey=${HASH_KEY}&${encryptedTradeInfo}&HashIV=${HASH_IV}`)
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
      const { usd, twd } = priceFor(credits);
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
  const { usd, twd: amt, rate } = priceFor(credits);

  // If NewebPay keys are not configured, allow local development testing simulation
  if (!MERCHANT_ID || !HASH_KEY || !HASH_IV) {
    if (process.env.NODE_ENV !== "production") {
      const { getFirestore, FieldValue } = await import("firebase-admin/firestore");
      const ref = getFirestore().collection("users").doc(uid);
      await ref.set({ credits: FieldValue.increment(credits) }, { merge: true });
      const simOrderNo = `SIM${Date.now()}`;
      recordCreditChange({
        uid,
        delta: credits,
        reason: "purchase",
        ref: simOrderNo,
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
  insertOrder.run(orderNo, uid, credits, amt, usd, rate);

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
    Email: email ?? "",
    NotifyURL: `${CLIENT_URL}/api/newebpay/notify`,
    ReturnURL: `${CLIENT_URL}/api/newebpay/return`,
    ClientBackURL: `${CLIENT_URL}/app`,
    CREDIT: "1",
  }).toString();

  const encrypted = aesEncrypt(tradeInfoPlain);

  return res.json({
    gateway: `${GATEWAY_BASE}/MPG/mpg_gateway`,
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
        downloadsRemaining: 3,
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
  insertGuestOrder.run(orderNo, amt, usd, rate, jobId);

  const tradeInfoPlain = new URLSearchParams({
    MerchantID: MERCHANT_ID,
    RespondType: "JSON",
    TimeStamp: String(Math.floor(Date.now() / 1000)),
    Version: "2.0",
    LangType: "en",
    MerchantOrderNo: orderNo,
    Amt: String(amt),
    ItemDesc: `Security Report: ${job.filename || "App Analysis"} (US$${usd})`,
    Email: email ?? "",
    NotifyURL: `${CLIENT_URL}/api/newebpay/notify`,
    ReturnURL: `${CLIENT_URL}/api/newebpay/return`,
    ClientBackURL: `${CLIENT_URL}/app`,
    CREDIT: "1",
  }).toString();

  const encrypted = aesEncrypt(tradeInfoPlain);

  return res.json({
    gateway: `${GATEWAY_BASE}/MPG/mpg_gateway`,
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
  const updated = markPaid.run(result.TradeNo ?? null, orderNo);
  if (updated.changes === 1) {
    if (order.orderType === "guest_report" && order.jobId) {
      const downloadToken = crypto.randomBytes(32).toString("hex");
      GuestJob.update(order.jobId, {
        isPaid: 1,
        downloadToken,
        downloadsRemaining: 3,
        paidAt: new Date().toISOString(),
      });
      console.log(`NewebPay: unlocked guest report ${order.jobId} (${orderNo})`);
    } else {
      const { getFirestore, FieldValue } = await import("firebase-admin/firestore");
      const ref = getFirestore().collection("users").doc(order.uid);
      await ref.set({ credits: FieldValue.increment(order.credits) }, { merge: true });
      console.log(`NewebPay: credited ${order.credits} to ${order.uid} (${orderNo})`);

      // Journal the grant so the daily audit can account for the new balance.
      // After the Firestore write, and never allowed to fail the request: an
      // unjournaled grant is detected and backfilled from this paid order tomorrow.
      const balanceAfter = await ref
        .get()
        .then((s) => Number(s.data()?.credits ?? 0))
        .catch(() => null);
      recordCreditChange({
        uid: order.uid,
        delta: order.credits,
        reason: "purchase",
        ref: orderNo,
        balanceAfter,
        note: `NewebPay ${result.TradeNo ?? "?"} · NT$${order.amt}`,
      });
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

export default router;

