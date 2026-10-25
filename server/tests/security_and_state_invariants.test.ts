import assert from "assert";
import crypto from "crypto";

if (!process.env.DYNAMIC_CRED_KEY || process.env.DYNAMIC_CRED_KEY.trim().length < 32) {
  process.env.DYNAMIC_CRED_KEY =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
}

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { db } = require("../db");
// eslint-disable-next-line @typescript-eslint/no-var-requires
require("../newebpay");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { FileMeta } = require("../models/FileMeta");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { User } = require("../models/User");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { seal, unseal, sealingAvailable } = require("../secretbox");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { DynamicCredentials } = require("../models/DynamicCredentials");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { recordCreditChange, reconcileUser } = require("../credit_audit");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { getTwdPerUsd } = require("../fx");

async function runTests() {
  console.log("==================================================");
  console.log(" Running Security & State Invariants Tests");
  console.log("==================================================");

  // 1. FX Sanity Clamping (reject poisoned rates outside [20, 45])
  {
    const prevFx = db
      .prepare("SELECT rate, source, fetchedAt FROM fx_rates WHERE pair = 'USD/TWD'")
      .get() as { rate: number; source: string; fetchedAt: string } | undefined;

    try {
      db.prepare(
        `INSERT INTO fx_rates (pair, rate, source, fetchedAt)
         VALUES ('USD/TWD', 0.031, 'poisoned-low', ?)
         ON CONFLICT(pair) DO UPDATE SET
           rate = excluded.rate, source = excluded.source, fetchedAt = excluded.fetchedAt`
      ).run(new Date().toISOString());

      const clampedLow = getTwdPerUsd();
      assert.strictEqual(clampedLow.stale, true, "Poisoned low rate (0.031) must be rejected");
      assert.strictEqual(clampedLow.source, "fallback");
      assert(clampedLow.rate >= 20 && clampedLow.rate <= 45);

      db.prepare(
        `UPDATE fx_rates SET rate = 999.9, source = 'poisoned-high', fetchedAt = ? WHERE pair = 'USD/TWD'`
      ).run(new Date().toISOString());

      const clampedHigh = getTwdPerUsd();
      assert.strictEqual(clampedHigh.stale, true, "Poisoned high rate (999.9) must be rejected");
      assert(clampedHigh.rate >= 20 && clampedHigh.rate <= 45);
      console.log("✓ Test 1: FX sanity clamping rejected poisoned rates (0.031, 999.9)");
    } finally {
      if (prevFx) {
        db.prepare(
          `INSERT OR REPLACE INTO fx_rates (pair, rate, source, fetchedAt) VALUES ('USD/TWD', ?, ?, ?)`
        ).run(prevFx.rate, prevFx.source, prevFx.fetchedAt);
      } else {
        db.prepare("DELETE FROM fx_rates WHERE pair = 'USD/TWD'").run();
      }
    }
  }

  // 2. FileMeta.claim() 10-way parallel atomic race lock & release() rollback
  {
    const testUser = `claim-user-${Date.now()}`;
    User.create(testUser, `${testUser}@test.com`);
    const testHash = crypto.randomBytes(16).toString("hex");
    const row = FileMeta.create({
      user: testUser,
      filename: "race-lock.apk",
      analysisType: "static",
      filePath: `uploads/${testUser}/${testHash}/race-lock.apk`,
      reportPath: `reports/${testUser}/${testHash}/static.json`,
      hash: testHash,
      status: "pending",
    });

    try {
      const results = await Promise.all(
        Array.from({ length: 10 }, () => Promise.resolve().then(() => FileMeta.claim(row.id)))
      );
      assert.strictEqual(results.filter(Boolean).length, 1, "Only 1 of 10 racers may claim");
      assert.strictEqual(results.filter((r) => !r).length, 9, "9 racers must be rejected");
      assert.strictEqual(FileMeta.findById(row.id)?.status, "analyzing");

      FileMeta.release(row.id);
      assert.strictEqual(FileMeta.findById(row.id)?.status, "pending");
      assert.strictEqual(FileMeta.claim(row.id), true, "Must be claimable after release()");
      console.log("✓ Test 2: FileMeta.claim() 10-way atomic race lock & release() rollback verified");
    } finally {
      FileMeta.delete(row.id);
      db.prepare("DELETE FROM users WHERE id = ?").run(testUser);
    }
  }

  // 3. SecretBox AES-256-GCM seal/unseal, tamper rejection & DynamicCredentials 30-day sweep
  {
    assert.strictEqual(sealingAvailable(), true);
    const rawSecret = "p@ssw0rd-with-trailing-space ";
    const sealed = seal(rawSecret);
    const parts = sealed.split(".");
    assert.strictEqual(parts.length, 4);
    assert.strictEqual(parts[0], "v1");
    assert.strictEqual(unseal(sealed), rawSecret);

    const tagBuf = Buffer.from(parts[2], "base64");
    tagBuf[0] ^= 0xff;
    const tampered = [parts[0], parts[1], tagBuf.toString("base64"), parts[3]].join(".");
    assert.throws(() => unseal(tampered), "Tampered GCM auth tag must throw on unseal()");

    const credUser = `cred-user-${Date.now()}`;
    User.create(credUser, `${credUser}@test.com`);
    const expiredMeta = FileMeta.create({
      user: credUser,
      filename: "expired-dyn.apk",
      analysisType: "dynamic",
      filePath: `uploads/${credUser}/h1/expired-dyn.apk`,
      reportPath: `reports/${credUser}/h1/dynamic.json`,
      hash: crypto.randomBytes(16).toString("hex"),
      status: "pending",
    });
    const freshMeta = FileMeta.create({
      user: credUser,
      filename: "fresh-dyn.apk",
      analysisType: "dynamic",
      filePath: `uploads/${credUser}/h2/fresh-dyn.apk`,
      reportPath: `reports/${credUser}/h2/dynamic.json`,
      hash: crypto.randomBytes(16).toString("hex"),
      status: "pending",
    });

    try {
      DynamicCredentials.set(expiredMeta.id, { username: "old@test.com", password: "old-secret" });
      DynamicCredentials.set(freshMeta.id, { username: "new@test.com", password: "new-secret" });

      const thirtyOneDaysAgo = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000).toISOString();
      db.prepare("UPDATE dynamic_credentials SET updatedAt = ? WHERE fileId = ?").run(
        thirtyOneDaysAgo,
        expiredMeta.id
      );

      const sweptCount = DynamicCredentials.sweep(30);
      assert(sweptCount >= 1, "Sweep must purge credentials older than 30 days");
      assert.strictEqual(DynamicCredentials.reveal(expiredMeta.id), null);
      assert.deepStrictEqual(DynamicCredentials.reveal(freshMeta.id), {
        username: "new@test.com",
        password: "new-secret",
      });
      console.log("✓ Test 3: SecretBox AES-256-GCM seal/unseal, tamper defense & 30d sweep verified");
    } finally {
      DynamicCredentials.remove(expiredMeta.id);
      DynamicCredentials.remove(freshMeta.id);
      FileMeta.delete(expiredMeta.id);
      FileMeta.delete(freshMeta.id);
      db.prepare("DELETE FROM users WHERE id = ?").run(credUser);
    }
  }

  // 4. reconcileUser() anti-fraud invariants
  {
    const uid = `invariant-audit-${Date.now()}`;
    const bogusOrderNo = `ORD_BOGUS_${Date.now()}`;
    const uncreditedOrderNo = `ORD_UNCRED_${Date.now()}`;
    const windowStart = "2020-01-01T00:00:00.000Z";
    const windowEnd = "2099-01-01T00:00:00.000Z";

    try {
      recordCreditChange({
        uid,
        delta: 5,
        reason: "purchase",
        ref: bogusOrderNo,
        balanceAfter: 5,
        note: "Forged purchase grant",
      });

      db.prepare(
        `INSERT INTO newebpay_orders (orderNo, uid, credits, amt, status, paidAt)
         VALUES (?, ?, 10, 1280, 'paid', strftime('%Y-%m-%dT%H:%M:%fZ','now'))`
      ).run(uncreditedOrderNo, uid);

      recordCreditChange({
        uid,
        delta: -1,
        reason: "consume",
        ref: `analysis:777:${Date.now()}`,
        balanceAfter: 99,
        note: "Spend while balance was illicitly inflated",
      });

      const anomalies = reconcileUser(
        { uid, email: "invariant@test.com", credits: 4 },
        0,
        windowStart,
        windowEnd
      ) as Array<{ kind: string }>;

      const kinds = new Set(anomalies.map((a) => a.kind));
      assert(kinds.has("unbacked_grant"), "Must detect unbacked_grant");
      assert(kinds.has("uncredited_payment"), "Must detect uncredited_payment");
      assert(kinds.has("ledger_balance_mismatch"), "Must detect ledger_balance_mismatch");
      console.log("✓ Test 4: reconcileUser() anti-fraud invariants verified");
    } finally {
      db.prepare("DELETE FROM credit_ledger WHERE uid = ?").run(uid);
      db.prepare("DELETE FROM newebpay_orders WHERE orderNo IN (?, ?)").run(
        bogusOrderNo,
        uncreditedOrderNo
      );
    }
  }

  console.log("==================================================");
  console.log(" All Security & State Invariants Tests Passed (4/4) ✅");
  console.log("==================================================");
}

runTests().catch((err) => {
  console.error("Security & State Invariants Test Failed:", err);
  process.exit(1);
});

