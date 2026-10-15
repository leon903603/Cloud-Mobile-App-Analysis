// server/credit_audit.ts — daily credit reconciliation ("did anyone mint credits?").
//
// Balances live in Firestore (users/{uid}.credits) as a bare number, so anything
// able to write that document — a leaked service account, a bug, an exploited
// endpoint — can hand itself credits with no trace. This module gives that number
// something to be checked against:
//
//   1. credit_ledger    — append-only journal in SQLite, written by every code path
//                         that legitimately changes a balance (signup, purchase,
//                         consume, admin adjustment, correction).
//   2. credit_snapshots — every user's balance, once a day, at a fixed time.
//   3. runCreditAudit() — for each user: yesterday's snapshot + today's ledger
//                         entries must equal today's balance. Anything else is an
//                         anomaly, recorded in credit_anomalies and alerted on.
//
// The ledger alone is not enough: a grant could be journaled and still be bogus.
// So every `purchase` entry is additionally matched against a `paid` row in
// newebpay_orders — i.e. money NewebPay actually confirmed — and every `signup`
// entry against the one-per-user seed. A hacker who both raises the Firestore
// balance *and* forges a ledger row still fails the payment-backing check.
//
// Two checks exist because a day-over-day comparison alone has blind spots:
//   • paid orders are matched in both directions, so a payment that was charged
//     and never credited (drift of exactly zero) is found as well as one that was
//     credited and never journaled;
//   • each entry's recorded balanceAfter is checked against the range the day's
//     deltas allow, so a balance that was raised, spent down and put back before
//     the next snapshot still leaves a trace.
//
// Nothing here writes to Firestore unless CREDIT_AUDIT_AUTO_CLAMP is on, and even
// then it only ever removes unexplained credits — it never grants.

import crypto from "crypto";
import express from "express";
import rateLimit from "express-rate-limit";
import { getFirestore } from "firebase-admin/firestore";
import { db } from "./db";

// ── Config ──────────────────────────────────────────────────────────────────
/**
 * Credits a brand-new account is seeded with. The audit enforces this exact
 * value. Zero by default: free signup credits were withdrawn, so a new account
 * seeds nothing and journals nothing.
 */
export const SIGNUP_CREDITS = Number(process.env.SIGNUP_CREDITS ?? 0);

/**
 * Seed amount granted before free signup credits were withdrawn. A `signup`
 * entry is re-examined whenever it falls inside an open window, so without this
 * every account created in the day or so before that change would be reported
 * as `invalid_signup_amount` — critical severity — on the next nightly run.
 * Set to 0 once no window can still contain a pre-change signup.
 */
const LEGACY_SIGNUP_CREDITS = Number(process.env.LEGACY_SIGNUP_CREDITS ?? 10);

const ENABLED = (process.env.CREDIT_AUDIT_ENABLED ?? "true") !== "false";
/** Wall-clock time of the daily run, "HH:MM", in the offset below. */
const RUN_TIME = process.env.CREDIT_AUDIT_TIME ?? "03:30";
/** Minutes east of UTC for RUN_TIME. Default 480 = UTC+8 (Taipei), the service's home. */
const TZ_OFFSET_MIN = Number(process.env.CREDIT_AUDIT_TZ_OFFSET_MIN ?? 480);
/** Optional Slack/Discord-compatible webhook for critical findings. */
const WEBHOOK_URL = process.env.CREDIT_AUDIT_WEBHOOK_URL ?? "";
/**
 * When true, an unexplained *increase* is clawed back automatically (balance set
 * to the reconciled value). Off by default: a bug in a new credit path would
 * otherwise silently delete real customer credits. Decreases are never "fixed" —
 * handing out credits from an automated job is exactly what we're guarding against.
 */
const AUTO_CLAMP = (process.env.CREDIT_AUDIT_AUTO_CLAMP ?? "false") === "true";
const ADMIN_TOKEN = process.env.ADMIN_API_TOKEN ?? "";
/**
 * Days of snapshot history to keep. 0 disables pruning. The ledger and the
 * anomaly record are never pruned — they are the evidence — and neither is any
 * user's most recent snapshot, whatever its age.
 */
const RETENTION_DAYS = Number(process.env.CREDIT_AUDIT_RETENTION_DAYS ?? 180);

const FIRESTORE_PAGE = 500;

// ── Schema ──────────────────────────────────────────────────────────────────
db.exec(`
  -- Append-only. Never UPDATE or DELETE rows here: the whole point is that the
  -- journal is harder to tamper with than the balance it explains.
  CREATE TABLE IF NOT EXISTS credit_ledger (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    uid          TEXT NOT NULL,
    delta        INTEGER NOT NULL,          -- + granted, - spent
    reason       TEXT NOT NULL CHECK (reason IN
                   ('signup','purchase','consume','refund','admin_adjust','reconcile_correction')),
    ref          TEXT,                      -- orderNo / upload id / anomaly id
    balanceAfter INTEGER,                   -- balance observed right after the write
    note         TEXT,
    createdAt    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  );

  -- Makes journaling idempotent for anything with a natural key (one order = one
  -- grant), so a retried NewebPay notify can't produce two ledger rows.
  CREATE UNIQUE INDEX IF NOT EXISTS credit_ledger_ref
    ON credit_ledger (reason, ref) WHERE ref IS NOT NULL;
  CREATE INDEX IF NOT EXISTS credit_ledger_uid_time ON credit_ledger (uid, createdAt);

  CREATE TABLE IF NOT EXISTS credit_snapshots (
    snapshotDate TEXT NOT NULL,             -- YYYY-MM-DD in the audit timezone
    uid          TEXT NOT NULL,
    email        TEXT,
    credits      INTEGER NOT NULL,          -- as observed, before any correction
    -- ISO instant; the ledger window boundary. Per row, not per run: a user whose
    -- balance was re-read mid-run is pinned to the instant of *that* read, and
    -- reconciliation reads the boundary back per user.
    takenAt      TEXT NOT NULL,
    runId        INTEGER,                   -- which run wrote it; see user_disappeared
    PRIMARY KEY (snapshotDate, uid)
  );

  -- Every run opens by asking for each user's latest snapshot by takenAt; the
  -- primary key is (snapshotDate, uid), which does not serve that at all.
  CREATE INDEX IF NOT EXISTS credit_snapshots_takenAt ON credit_snapshots (takenAt);

  CREATE TABLE IF NOT EXISTS credit_audit_runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    auditDate    TEXT NOT NULL,
    trigger      TEXT NOT NULL,             -- 'schedule' | 'startup' | 'manual' | 'cli'
    startedAt    TEXT NOT NULL,
    finishedAt   TEXT,
    usersChecked INTEGER NOT NULL DEFAULT 0,
    baselined    INTEGER NOT NULL DEFAULT 0, -- users seen for the first time
    -- What this run found, frozen at the moment it finished. Deliberately not
    -- kept in step with credit_anomalies.status: "the run that reported it" is
    -- the useful reading, not "how many are still open" (query for that).
    anomalies    INTEGER NOT NULL DEFAULT 0,
    critical     INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT 'running'
                 CHECK (status IN ('running','ok','anomalies','error')),
    error        TEXT
  );

  CREATE TABLE IF NOT EXISTS credit_anomalies (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    runId           INTEGER NOT NULL REFERENCES credit_audit_runs(id),
    auditDate       TEXT NOT NULL,
    uid             TEXT NOT NULL,
    email           TEXT,
    kind            TEXT NOT NULL,
    severity        TEXT NOT NULL CHECK (severity IN ('critical','warning')),
    previousCredits INTEGER,
    currentCredits  INTEGER,
    ledgerDelta     INTEGER,
    expectedCredits INTEGER,
    -- Size of the problem, signed. Its meaning follows the kind: for the balance
    -- kinds it is currentCredits - expectedCredits, for the grant kinds it is
    -- the suspect grant itself, for uncredited_payment it is what the customer
    -- is owed. Not derivable from the neighbouring columns — don't assume.
    drift           INTEGER,
    detail          TEXT,                   -- JSON
    status          TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open','acknowledged','corrected','dismissed')),
    resolution      TEXT,
    detectedAt      TEXT NOT NULL,
    resolvedAt      TEXT
  );

  CREATE INDEX IF NOT EXISTS credit_anomalies_open
    ON credit_anomalies (status, detectedAt);
`);

// runId arrived after credit_snapshots did, so a database created by an earlier
// build needs it added rather than recreated. Rows from before it existed keep a
// null, which reads as "not from the last run" — silence rather than false alarms.
if (
  !(db.prepare("PRAGMA table_info(credit_snapshots)").all() as { name: string }[]).some(
    (c) => c.name === "runId"
  )
) {
  db.exec("ALTER TABLE credit_snapshots ADD COLUMN runId INTEGER");
}

// Migration: ensure credit_ledger CHECK constraint supports 'refund'
const ledgerTableInfo = db
  .prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='credit_ledger'")
  .get() as { sql: string } | undefined;
if (ledgerTableInfo && !ledgerTableInfo.sql.includes("'refund'")) {
  db.transaction(() => {
    db.exec(`
      CREATE TABLE credit_ledger_migration_new (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        uid          TEXT NOT NULL,
        delta        INTEGER NOT NULL,
        reason       TEXT NOT NULL CHECK (reason IN
                       ('signup','purchase','consume','refund','admin_adjust','reconcile_correction')),
        ref          TEXT,
        balanceAfter INTEGER,
        note         TEXT,
        createdAt    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
      );
      INSERT INTO credit_ledger_migration_new (id, uid, delta, reason, ref, balanceAfter, note, createdAt)
        SELECT id, uid, delta, reason, ref, balanceAfter, note, createdAt FROM credit_ledger;
      DROP TABLE credit_ledger;
      ALTER TABLE credit_ledger_migration_new RENAME TO credit_ledger;
      CREATE UNIQUE INDEX IF NOT EXISTS credit_ledger_ref
        ON credit_ledger (reason, ref) WHERE ref IS NOT NULL;
      CREATE INDEX IF NOT EXISTS credit_ledger_uid_time ON credit_ledger (uid, createdAt);
    `);
  })();
}

// ── Ledger ──────────────────────────────────────────────────────────────────
export type LedgerReason =
  | "signup"
  | "purchase"
  | "consume"
  | "refund"
  | "admin_adjust"
  | "reconcile_correction";

/** Reasons allowed to hand out credits. Anything else with delta > 0 is an anomaly. */
const GRANT_REASONS: LedgerReason[] = ["signup", "purchase", "refund", "admin_adjust"];

const insertLedger = db.prepare(
  `INSERT INTO credit_ledger (uid, delta, reason, ref, balanceAfter, note, createdAt)
   VALUES (@uid, @delta, @reason, @ref, @balanceAfter, @note,
           COALESCE(@at, strftime('%Y-%m-%dT%H:%M:%fZ','now')))`
);

export interface LedgerEntry {
  uid: string;
  /** Signed change: +N granted, -N spent. */
  delta: number;
  reason: LedgerReason;
  /** Natural key where one exists (orderNo, upload id). Makes the write idempotent. */
  ref?: string | null;
  /** Balance read back from Firestore after the write, when known. */
  balanceAfter?: number | null;
  note?: string | null;
  /**
   * Pin the entry's timestamp instead of using "now". Only the audit uses this,
   * to place its own corrections on a known side of a snapshot boundary rather
   * than trusting that a few milliseconds elapsed.
   */
  at?: string | null;
}

/**
 * Journal a credit change. Call *after* the Firestore write succeeds, so the
 * ledger never claims a change that did not happen.
 *
 * Never throws — a failed journal write must not fail a paid customer's purchase.
 * It will surface the next morning as an anomaly instead, which is the safe
 * direction. Returns false if the entry was a duplicate (same reason+ref).
 */
export function recordCreditChange(entry: LedgerEntry): boolean {
  try {
    insertLedger.run({
      uid: entry.uid,
      delta: entry.delta,
      reason: entry.reason,
      ref: entry.ref ?? null,
      balanceAfter: entry.balanceAfter ?? null,
      note: entry.note ?? null,
      at: entry.at ?? null,
    });
    return true;
  } catch (err: any) {
    if (String(err?.code) === "SQLITE_CONSTRAINT_UNIQUE") return false; // already journaled
    console.error("credit-audit: FAILED to journal credit change", entry, err);
    return false;
  }
}

// ── Reconciliation ──────────────────────────────────────────────────────────
// Each user's most recent snapshot before this run — "since we last looked",
// not "yesterday", so a second run on the same day reconciles against the
// morning's figures instead of re-examining a window it already closed.
// (SQLite takes the bare columns from the row that supplied the MAX.)
//
// The bound is inclusive: this run's own snapshot is not written until later, so
// everything here is from an earlier run, and `<` would discard a snapshot that
// happens to share our millisecond — which then reconciles against a window that
// already had its corrections applied.
const previousSnapshots = db.prepare(
  `SELECT uid, credits, snapshotDate, runId, MAX(takenAt) AS takenAt
     FROM credit_snapshots WHERE takenAt <= ? GROUP BY uid`
);
const upsertSnapshot = db.prepare(`
  INSERT INTO credit_snapshots (snapshotDate, uid, email, credits, takenAt, runId)
  VALUES (?, ?, ?, ?, ?, ?)
  ON CONFLICT(snapshotDate, uid) DO UPDATE SET
    email = excluded.email, credits = excluded.credits,
    takenAt = excluded.takenAt, runId = excluded.runId
`);
const ledgerInWindow = db.prepare(
  `SELECT * FROM credit_ledger
    WHERE uid = ? AND createdAt > ? AND createdAt <= ?
    ORDER BY id`
);
// newebpay_orders is created by newebpay.ts at import time, so these two are
// prepared on first use — otherwise this module could only ever be imported after
// that one, which is not a constraint worth carrying in every entry point.
function lazy(sql: string) {
  let stmt: ReturnType<typeof db.prepare> | null = null;
  return () => (stmt ??= db.prepare(sql));
}
const paidOrdersInWindow = lazy(
  `SELECT orderNo, uid, credits, amt, tradeNo, paidAt FROM newebpay_orders
    WHERE uid = ? AND status = 'paid'
      AND COALESCE(paidAt, createdAt) > ? AND COALESCE(paidAt, createdAt) <= ?`
);
const findPaidOrder = lazy(
  "SELECT * FROM newebpay_orders WHERE orderNo = ? AND status = 'paid'"
);
const countSignupGrants = db.prepare(
  "SELECT COUNT(*) AS n FROM credit_ledger WHERE uid = ? AND reason = 'signup'"
);
const insertRun = db.prepare(
  `INSERT INTO credit_audit_runs (auditDate, trigger, startedAt) VALUES (?, ?, ?)`
);
const finishRun = db.prepare(
  `UPDATE credit_audit_runs
      SET finishedAt = ?, usersChecked = ?, baselined = ?, anomalies = ?,
          critical = ?, status = ?, error = ?
    WHERE id = ?`
);
const insertAnomaly = db.prepare(`
  INSERT INTO credit_anomalies
    (runId, auditDate, uid, email, kind, severity, previousCredits, currentCredits,
     ledgerDelta, expectedCredits, drift, detail, detectedAt)
  VALUES
    (@runId, @auditDate, @uid, @email, @kind, @severity, @previousCredits, @currentCredits,
     @ledgerDelta, @expectedCredits, @drift, @detail, @detectedAt)
`);

export type AnomalyKind =
  | "unexplained_increase"
  | "unexplained_decrease"
  | "unjournaled_purchase"
  | "uncredited_payment"
  | "ledger_balance_mismatch"
  | "unbacked_grant"
  | "duplicate_signup_grant"
  | "invalid_signup_amount"
  | "unknown_grant_reason"
  | "invalid_balance"
  | "user_disappeared";

/**
 * Kinds worth reading a fresh balance for before alerting. These are the ones a
 * write landing mid-run can manufacture; the rest are statements about records
 * already written, which a second look cannot change.
 */
const RECHECK_KINDS = new Set<AnomalyKind>([
  "unexplained_increase",
  "unexplained_decrease",
  "uncredited_payment",
]);

interface Anomaly {
  uid: string;
  email: string | null;
  kind: AnomalyKind;
  severity: "critical" | "warning";
  previousCredits: number | null;
  currentCredits: number | null;
  ledgerDelta: number | null;
  expectedCredits: number | null;
  drift: number | null;
  detail: Record<string, unknown>;
}

export interface AuditRunSummary {
  runId: number;
  auditDate: string;
  usersChecked: number;
  baselined: number;
  anomalies: Anomaly[];
  criticalCount: number;
  status: "ok" | "anomalies" | "error";
  error?: string;
}

interface FsUser {
  uid: string;
  email: string | null;
  credits: number;
  /**
   * Set when users/{uid}.credits was not a whole number — a string, an object, a
   * fraction, Infinity. Carries the original value so the alert can quote it.
   * Present means `credits` is a placeholder and must not be reconciled against.
   */
  rawCredits?: unknown;
}

/** Every user document in Firestore, paged so a large collection can't blow memory. */
async function readAllBalances(): Promise<FsUser[]> {
  const fs = getFirestore();
  const out: FsUser[] = [];
  let cursor: FirebaseFirestore.QueryDocumentSnapshot | undefined;

  for (;;) {
    let q = fs.collection("users").orderBy("__name__").limit(FIRESTORE_PAGE);
    if (cursor) q = q.startAfter(cursor);
    const snap = await q.get();
    if (snap.empty) break;

    for (const doc of snap.docs) {
      const data = doc.data();
      // A missing field is a fresh document and reads as 0. Anything present but
      // not a whole number is refused rather than coerced: NaN would poison every
      // comparison below it and then fail the NOT NULL snapshot insert, taking the
      // whole run down over one bad document.
      const raw = data.credits;
      const n = Number(raw ?? 0);
      const valid = Number.isSafeInteger(n);
      out.push({
        uid: doc.id,
        email: typeof data.email === "string" ? data.email : null,
        credits: valid ? n : 0,
        ...(valid ? {} : { rawCredits: raw }),
      });
    }
    if (snap.size < FIRESTORE_PAGE) break;
    cursor = snap.docs[snap.docs.length - 1];
  }
  return out;
}

interface LedgerRow {
  id: number;
  uid: string;
  delta: number;
  reason: LedgerReason;
  ref: string | null;
  balanceAfter: number | null;
  createdAt: string;
}

interface PaidOrder {
  orderNo: string;
  uid: string;
  credits: number;
  amt: number;
  tradeNo: string | null;
  paidAt: string | null;
}

/**
 * Reconcile one user against the previous snapshot.
 * `windowStart` is the previous snapshot's instant, `windowEnd` this run's instant.
 */
export function reconcileUser(
  user: FsUser,
  previousCredits: number,
  windowStart: string,
  windowEnd: string
): Anomaly[] {
  const found: Anomaly[] = [];
  const entries = ledgerInWindow.all(user.uid, windowStart, windowEnd) as LedgerRow[];
  const ledgerDelta = entries.reduce((s, e) => s + e.delta, 0);
  const expected = previousCredits + ledgerDelta;
  const drift = user.credits - expected;

  const base = {
    uid: user.uid,
    email: user.email,
    previousCredits,
    currentCredits: user.credits,
    ledgerDelta,
    expectedCredits: expected,
  };

  // ── 1. Is every grant in the journal actually backed by something real? ──
  // A forged ledger row is the obvious way to make the arithmetic above balance,
  // so grants are matched against evidence outside the ledger: a NewebPay order
  // that reached `paid` (which only the signature-verified notify handler sets),
  // or the one-time signup seed.
  for (const e of entries) {
    if (e.delta <= 0) continue;

    if (!GRANT_REASONS.includes(e.reason)) {
      found.push({
        ...base,
        kind: "unknown_grant_reason",
        severity: "critical",
        drift: e.delta,
        detail: { ledgerId: e.id, reason: e.reason, delta: e.delta, ref: e.ref },
      });
      continue;
    }

    if (e.reason === "purchase") {
      const order = e.ref ? (findPaidOrder().get(e.ref) as any) : undefined;
      if (!order || order.uid !== user.uid || Number(order.credits) !== e.delta) {
        found.push({
          ...base,
          kind: "unbacked_grant",
          severity: "critical",
          drift: e.delta,
          detail: {
            ledgerId: e.id,
            orderNo: e.ref,
            grantedCredits: e.delta,
            orderFound: !!order,
            orderUid: order?.uid ?? null,
            orderCredits: order?.credits ?? null,
            orderStatus: order?.status ?? null,
          },
        });
      }
    }

    if (e.reason === "signup") {
      const seeds = (countSignupGrants.get(user.uid) as { n: number }).n;
      if (seeds > 1) {
        found.push({
          ...base,
          kind: "duplicate_signup_grant",
          severity: "critical",
          drift: e.delta,
          detail: { ledgerId: e.id, signupGrants: seeds },
        });
      }
      // The legacy amount is accepted as well, so seeds handed out before free
      // signup credits were withdrawn are not retroactively called forgeries.
      if (e.delta !== SIGNUP_CREDITS && e.delta !== LEGACY_SIGNUP_CREDITS) {
        found.push({
          ...base,
          kind: "invalid_signup_amount",
          severity: "critical",
          drift: e.delta - SIGNUP_CREDITS,
          detail: { ledgerId: e.id, granted: e.delta, expected: SIGNUP_CREDITS },
        });
      }
    }

    if (e.reason === "refund") {
      const matchedConsume = e.ref
        ? (db
            .prepare(
              `SELECT id, createdAt FROM credit_ledger 
               WHERE uid = ? AND reason = 'consume' AND ref = ? AND delta = -1`
            )
            .get(user.uid, e.ref) as { id: number; createdAt: string } | undefined)
        : undefined;

      if (!e.ref || e.delta !== 1 || !matchedConsume || matchedConsume.createdAt > e.createdAt) {
        found.push({
          ...base,
          kind: "unbacked_grant",
          severity: "critical",
          drift: e.delta,
          detail: {
            ledgerId: e.id,
            reason: "refund",
            ref: e.ref,
            grantedCredits: e.delta,
            consumeFound: !!matchedConsume,
            consumeCreatedAt: matchedConsume?.createdAt ?? null,
            refundCreatedAt: e.createdAt,
          },
        });
      }
    }
  }

  // ── 2. Do the confirmed payments and the balance agree? ─────────────────
  // Looked up whether or not the balance drifted. A payment fails in two opposite
  // ways and only one of them moves a balance:
  //   • credited but not journaled  → drift is positive; the paperwork is behind
  //   • never credited at all       → drift is *zero*, because nothing happened.
  // The second is invisible to a day-over-day comparison, and it is the one that
  // costs a customer money: notify() marks the order paid in SQLite before it
  // touches Firestore, so a crash in between charges the card and delivers
  // nothing — and NewebPay's retry finds the order already `paid` and moves on.
  const journaledOrders = new Set(
    entries.filter((e) => e.reason === "purchase" && e.ref).map((e) => e.ref as string)
  );
  const unjournaled = (
    paidOrdersInWindow().all(user.uid, windowStart, windowEnd) as PaidOrder[]
  ).filter((o) => !journaledOrders.has(o.orderNo));
  const unjournaledCredits = unjournaled.reduce((s, o) => s + Number(o.credits), 0);

  // The credits did arrive and only the journal write was lost: file it so
  // tomorrow reconciles, and read it as bookkeeping rather than theft.
  const backfilled = unjournaled.length > 0 && drift > 0 && unjournaledCredits === drift;
  if (backfilled) {
    for (const o of unjournaled) {
      recordCreditChange({
        uid: user.uid,
        delta: Number(o.credits),
        reason: "purchase",
        ref: o.orderNo,
        note: "backfilled by credit audit (payment confirmed, journal write missed)",
        // Filed at the window's own boundary: the balance being reconciled
        // already contains these credits, so leaving the entry to fall into
        // the *next* window would count the same purchase twice and read as a
        // drop tomorrow.
        at: windowEnd,
      });
    }
    found.push({
      ...base,
      kind: "unjournaled_purchase",
      severity: "warning",
      drift,
      detail: {
        backfilledOrders: unjournaled.map((o) => o.orderNo),
        backfilledCredits: unjournaledCredits,
      },
    });
  } else if (drift !== 0) {
    found.push({
      ...base,
      kind: drift > 0 ? "unexplained_increase" : "unexplained_decrease",
      severity: drift > 0 ? "critical" : "warning",
      drift,
      detail: {
        window: { from: windowStart, to: windowEnd },
        ledgerEntries: entries.map((e) => ({
          id: e.id,
          delta: e.delta,
          reason: e.reason,
          ref: e.ref,
          at: e.createdAt,
        })),
        unjournaledPaidCredits: unjournaledCredits,
      },
    });
  }

  // Money confirmed, balance unmoved (or moved by some unrelated amount). The
  // credits are never granted from here — an audit that hands out credits is a
  // credit-granting API with extra steps, and that is the thing being guarded
  // against. A human grants them with POST /adjust.
  if (unjournaled.length > 0 && !backfilled) {
    found.push({
      ...base,
      kind: "uncredited_payment",
      severity: "critical",
      drift: -unjournaledCredits,
      detail: {
        owedCredits: unjournaledCredits,
        // With no drift at all, the balance provably never moved for these
        // orders. With drift, it moved by the wrong amount and a human has to
        // decide how much of it was this.
        balanceUnmoved: drift === 0,
        orders: unjournaled.map((o) => ({
          orderNo: o.orderNo,
          credits: o.credits,
          amt: o.amt,
          tradeNo: o.tradeNo,
          paidAt: o.paidAt,
        })),
      },
    });
  }

  // ── 3. Did the balance ever leave the range the journal allows? ─────────
  // Each entry records the balance read back straight after its own write, so
  // the journal carries a handful of directly observed balances from *during*
  // the day. Their order is not trustworthy — concurrent requests journal in
  // whatever order they finish — but the envelope is: from the previous
  // snapshot, no interleaving of these deltas can put the balance above
  // prev + (everything granted) or below prev + (everything spent). A reading
  // outside it is a balance change nothing in the journal accounts for.
  //
  // This is what catches an attacker who covers their tracks: mint credits at
  // 10:00, spend them through the normal endpoint, put the balance back before
  // 03:30. Both snapshots agree and the spends are honestly journaled, so the
  // day-over-day comparison reconciles to zero — but the balances observed while
  // spending are far above anything the day's deltas could have reached.
  const ceiling = previousCredits + entries.reduce((s, e) => s + Math.max(e.delta, 0), 0);
  const floor = previousCredits + entries.reduce((s, e) => s + Math.min(e.delta, 0), 0);
  for (const e of entries) {
    if (e.balanceAfter === null || e.balanceAfter === undefined) continue;
    if (e.balanceAfter <= ceiling && e.balanceAfter >= floor) continue;
    const above = e.balanceAfter > ceiling;
    found.push({
      ...base,
      kind: "ledger_balance_mismatch",
      severity: above ? "critical" : "warning",
      drift: e.balanceAfter - (above ? ceiling : floor),
      detail: {
        ledgerId: e.id,
        reason: e.reason,
        ref: e.ref,
        observedBalance: e.balanceAfter,
        allowedRange: [floor, ceiling],
        at: e.createdAt,
      },
    });
  }

  return found;
}

/** Balance as of *now*, used to re-check a candidate anomaly before alerting. */
async function readBalance(uid: string): Promise<number> {
  const snap = await getFirestore().collection("users").doc(uid).get();
  return snap.exists ? Number(snap.data()?.credits ?? 0) : 0;
}

/**
 * Clamp a balance back to the reconciled value. Only ever removes credits, and
 * only in a transaction that re-checks the balance is still what we measured, so
 * a purchase landing mid-audit is not clobbered.
 */
async function clawBack(
  uid: string,
  observed: number,
  expected: number,
  anomalyId: number,
  /** Timestamp to file the correction under. See LedgerEntry.at. */
  at?: string
) {
  const ref = getFirestore().collection("users").doc(uid);
  const applied = await getFirestore().runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const current = snap.exists ? Number(snap.data()?.credits ?? 0) : 0;
    if (current !== observed) return null; // moved since the audit read — leave it alone
    if (expected >= current) return null; // never grants
    if (expected < 0) return null; // a corrupt ledger must not drive a balance negative
    tx.update(ref, { credits: expected });
    return expected;
  });

  if (applied === null) return false;
  recordCreditChange({
    uid,
    delta: expected - observed,
    reason: "reconcile_correction",
    ref: `anomaly:${anomalyId}`,
    balanceAfter: expected,
    note: "unexplained credits removed by credit audit",
    at,
  });
  return true;
}

const markAnomaly = db.prepare(
  "UPDATE credit_anomalies SET status = ?, resolution = ?, resolvedAt = ? WHERE id = ?"
);

// ── Retention ───────────────────────────────────────────────────────────────
// One row per user per day on an 8 GB disk shared with the analysis database, so
// snapshots are swept. Two things are deliberately never swept: the ledger,
// which is the record everything else is checked against, and any user's most
// recent snapshot — dropping that would re-baseline the account on the next run,
// quietly accepting whatever its balance had become in the meantime.
const pruneSnapshots = db.prepare(`
  DELETE FROM credit_snapshots
   WHERE takenAt < ?
     AND takenAt < (SELECT MAX(s.takenAt) FROM credit_snapshots s
                     WHERE s.uid = credit_snapshots.uid)
`);
// Runs that found nothing carry no information once they are out of retention.
// Ones that did are kept: credit_anomalies points at them.
const pruneRuns = db.prepare(`
  DELETE FROM credit_audit_runs
   WHERE startedAt < ?
     AND id NOT IN (SELECT runId FROM credit_anomalies)
`);

function pruneHistory(): { snapshots: number; runs: number } | null {
  if (!Number.isFinite(RETENTION_DAYS) || RETENTION_DAYS <= 0) return null;
  const cutoff = new Date(Date.now() - RETENTION_DAYS * 86_400_000).toISOString();
  try {
    return {
      snapshots: pruneSnapshots.run(cutoff).changes,
      runs: pruneRuns.run(cutoff).changes,
    };
  } catch (err) {
    // Housekeeping must never be the reason an audit reports failure.
    console.error("credit-audit: prune failed —", (err as Error).message);
    return null;
  }
}

let inFlight: Promise<AuditRunSummary> | null = null;

/**
 * Snapshot every balance and reconcile it against each user's previous snapshot
 * plus the ledger entries since. Safe to run more than once a day: the snapshot
 * upserts on (date, uid) and the second run's window starts where the first
 * one's ended.
 *
 * Concurrent callers share one pass. The scheduled run and a POST /run can land
 * together, and while the claw-back itself is safe under that (it re-reads the
 * balance inside a transaction), two passes over the same window would file the
 * same anomaly twice and leave a second run half-reconciling a window the first
 * had already corrected.
 */
export function runCreditAudit(trigger = "manual"): Promise<AuditRunSummary> {
  if (inFlight) return inFlight;
  inFlight = executeRun(trigger).finally(() => {
    inFlight = null;
  });
  return inFlight;
}

async function executeRun(trigger: string): Promise<AuditRunSummary> {
  const startedAt = new Date().toISOString();
  const auditDate = auditDateFor(new Date());
  const runId = Number(insertRun.run(auditDate, trigger, startedAt).lastInsertRowid);

  try {
    const users = await readAllBalances();
    // Taken after the read so anything written during it falls inside the window
    // rather than being credited to tomorrow. Candidates are re-checked below.
    const takenAt = new Date().toISOString();

    const prev = new Map<
      string,
      { credits: number; takenAt: string; snapshotDate: string; runId: number | null }
    >();
    for (const r of previousSnapshots.all(takenAt) as any[]) {
      prev.set(r.uid, {
        credits: r.credits,
        takenAt: r.takenAt,
        snapshotDate: r.snapshotDate,
        runId: r.runId,
      });
    }

    let baselined = 0;
    const candidates: Anomaly[] = [];

    for (const user of users) {
      if (user.rawCredits !== undefined) {
        // Nothing sensible to reconcile against, and snapshotting it would make
        // the garbage tomorrow's baseline. Report it and leave the account's
        // last good snapshot standing.
        candidates.push({
          uid: user.uid,
          email: user.email,
          kind: "invalid_balance",
          severity: "critical",
          previousCredits: prev.get(user.uid)?.credits ?? null,
          currentCredits: null,
          ledgerDelta: null,
          expectedCredits: null,
          drift: null,
          detail: { rawCredits: String(user.rawCredits), type: typeof user.rawCredits },
        });
        continue;
      }

      const before = prev.get(user.uid);
      if (!before) {
        // First time we've seen this account: nothing to compare against, so this
        // run only establishes its baseline. (Also the state right after deploy.)
        baselined++;
        continue;
      }
      candidates.push(
        ...reconcileUser(user, before.credits, before.takenAt, takenAt)
      );
    }

    // A user document that vanished is worth a look — deleting and recreating an
    // account is one way to try to re-claim the signup seed. Only accounts present
    // at the *previous run* count: a user's last snapshot lives on forever, so
    // comparing against all of them would re-report every old deletion nightly.
    // Keyed on runId rather than takenAt, because takenAt is per user now and a
    // run's rows no longer all share one instant.
    const lastRunId = [...prev.values()].reduce(
      (max, p) => (p.runId !== null && p.runId > max ? p.runId : max),
      -1
    );
    const seen = new Set(users.map((u) => u.uid));
    for (const [uid, before] of prev) {
      if (seen.has(uid) || before.runId !== lastRunId) continue;
      candidates.push({
        uid,
        email: null,
        kind: "user_disappeared",
        severity: "warning",
        previousCredits: before.credits,
        currentCredits: null,
        ledgerDelta: null,
        expectedCredits: null,
        drift: null,
        detail: { lastSeen: before.snapshotDate },
      });
    }

    // Re-check drift anomalies against a fresh read: a purchase or an upload
    // landing while we paged through Firestore would otherwise page someone at
    // 03:30 over a race, not a break-in.
    const confirmed: Anomaly[] = [];
    // Balances the recheck re-read, and when. A second read is strictly later and
    // it is the one that settled the question, so it — not the paging read — is
    // what gets snapshotted. Otherwise a race we correctly dismissed tonight
    // becomes tomorrow's baseline as a figure this run already judged wrong, and
    // reappears as drift in the opposite direction.
    const rechecked = new Map<string, { credits: number; at: string }>();
    for (const a of candidates) {
      if (!RECHECK_KINDS.has(a.kind)) {
        confirmed.push(a);
        continue;
      }
      const recheckAt = new Date().toISOString();
      const nowCredits = await readBalance(a.uid);
      rechecked.set(a.uid, { credits: nowCredits, at: recheckAt });
      const fresh = reconcileUser(
        { uid: a.uid, email: a.email, credits: nowCredits },
        a.previousCredits as number,
        prev.get(a.uid)!.takenAt,
        recheckAt
      );
      // Still saying the same thing → real. Explained by a payment that landed
      // mid-run → downgraded to the (now backfilled) bookkeeping warning. Gone
      // → it was the race, drop it. A payment that finished crediting between the
      // two reads takes the same route: the fresh pass finds the ledger row and
      // reports nothing.
      const still =
        fresh.find((x) => x.kind === a.kind) ??
        fresh.find((x) => x.kind === "unjournaled_purchase");
      if (still) confirmed.push({ ...still, email: a.email });
    }

    // Snapshot the balance as observed. If a claw-back follows, it rewrites the
    // row it just wrote — see the AUTO_CLAMP block for why the corrected figure
    // has to be what tomorrow starts from.
    const writeSnapshots = db.transaction((rows: FsUser[]) => {
      for (const u of rows) {
        const r = rechecked.get(u.uid);
        upsertSnapshot.run(
          auditDate,
          u.uid,
          u.email,
          r?.credits ?? u.credits,
          r?.at ?? takenAt,
          runId
        );
      }
    });
    writeSnapshots(users.filter((u) => u.rawCredits === undefined));

    const stored = db.transaction((rows: Anomaly[]) =>
      rows.map((a) =>
        Number(
          insertAnomaly.run({
            runId,
            auditDate,
            uid: a.uid,
            email: a.email,
            kind: a.kind,
            severity: a.severity,
            previousCredits: a.previousCredits,
            currentCredits: a.currentCredits,
            ledgerDelta: a.ledgerDelta,
            expectedCredits: a.expectedCredits,
            drift: a.drift,
            detail: JSON.stringify(a.detail),
            detectedAt: new Date().toISOString(),
          }).lastInsertRowid
        )
      )
    )(confirmed);

    if (AUTO_CLAMP) {
      for (let i = 0; i < confirmed.length; i++) {
        const a = confirmed[i];
        if (a.kind !== "unexplained_increase") continue;
        // The correction is filed *at* the snapshot boundary and the snapshot is
        // rewritten to the corrected figure, so today's books close balanced.
        // Deriving that from wall-clock ordering instead would leave the
        // correction in a gap between the two windows on a fast run.
        const at = rechecked.get(a.uid)?.at ?? takenAt;
        const ok = await clawBack(
          a.uid,
          a.currentCredits as number,
          a.expectedCredits as number,
          stored[i],
          at
        );
        if (ok) {
          upsertSnapshot.run(auditDate, a.uid, a.email, a.expectedCredits, at, runId);
        }
        markAnomaly.run(
          ok ? "corrected" : "open",
          ok
            ? `auto-clamped ${a.currentCredits} → ${a.expectedCredits}`
            : "auto-clamp skipped: balance changed during audit",
          ok ? new Date().toISOString() : null,
          stored[i]
        );
      }
    }

    const criticalCount = confirmed.filter((a) => a.severity === "critical").length;
    const status = confirmed.length ? "anomalies" : "ok";
    finishRun.run(
      new Date().toISOString(),
      users.length,
      baselined,
      confirmed.length,
      criticalCount,
      status,
      null,
      runId
    );

    const pruned = pruneHistory();
    if (pruned && (pruned.snapshots || pruned.runs)) {
      console.log(
        `credit-audit: pruned ${pruned.snapshots} snapshots and ${pruned.runs} empty runs ` +
          `older than ${RETENTION_DAYS} days`
      );
    }

    const summary: AuditRunSummary = {
      runId,
      auditDate,
      usersChecked: users.length,
      baselined,
      anomalies: confirmed,
      criticalCount,
      status,
    };
    await report(summary);
    return summary;
  } catch (err) {
    const message = (err as Error).message;
    console.error("credit-audit: run failed —", err);
    finishRun.run(new Date().toISOString(), 0, 0, 0, 0, "error", message, runId);
    return {
      runId,
      auditDate,
      usersChecked: 0,
      baselined: 0,
      anomalies: [],
      criticalCount: 0,
      status: "error",
      error: message,
    };
  }
}

// ── Alerting ────────────────────────────────────────────────────────────────
async function report(s: AuditRunSummary) {
  if (!s.anomalies.length) {
    console.log(
      `credit-audit ${s.auditDate}: ok — ${s.usersChecked} users, ${s.baselined} baselined`
    );
    return;
  }

  // Distinctive prefix so a log alarm can key off it.
  console.error(
    `CREDIT-AUDIT-ALERT ${s.auditDate}: ${s.anomalies.length} anomalies ` +
      `(${s.criticalCount} critical) across ${s.usersChecked} users`
  );
  for (const a of s.anomalies) {
    console.error(
      `CREDIT-AUDIT-ALERT   [${a.severity}] ${a.kind} uid=${a.uid} ` +
        `prev=${a.previousCredits} now=${a.currentCredits} ledger=${a.ledgerDelta} ` +
        `expected=${a.expectedCredits} drift=${a.drift} ${JSON.stringify(a.detail)}`
    );
  }

  if (!WEBHOOK_URL || !s.criticalCount) return;
  const lines = s.anomalies
    .filter((a) => a.severity === "critical")
    .slice(0, 20)
    .map(
      (a) =>
        `• ${a.kind} — uid \`${a.uid}\` (${a.email ?? "?"}): ` +
        `expected ${a.expectedCredits}, has ${a.currentCredits} (drift ${a.drift})`
    );
  const text = `*CMAA credit audit ${s.auditDate}* — ${s.criticalCount} critical anomalies\n${lines.join("\n")}`;
  try {
    await fetch(WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      // `text` for Slack, `content` for Discord — one payload works with both.
      body: JSON.stringify({ text, content: text }),
      signal: AbortSignal.timeout(8000),
    });
  } catch (err) {
    console.error("credit-audit: webhook failed —", (err as Error).message);
  }
}

// ── Scheduling ──────────────────────────────────────────────────────────────
/** Calendar date in the audit timezone — the key snapshots are stored under. */
function auditDateFor(at: Date): string {
  return new Date(at.getTime() + TZ_OFFSET_MIN * 60_000).toISOString().slice(0, 10);
}

/** Next occurrence of RUN_TIME in the audit timezone, as a UTC instant. */
export function nextRunAt(now = new Date()): Date {
  const [h, m] = RUN_TIME.split(":").map(Number);
  const offsetMs = TZ_OFFSET_MIN * 60_000;
  // Shift into the audit timezone so UTC getters read as local wall clock.
  const local = new Date(now.getTime() + offsetMs);
  const target = new Date(local);
  target.setUTCHours(h || 0, m || 0, 0, 0);
  if (target <= local) target.setUTCDate(target.getUTCDate() + 1);
  return new Date(target.getTime() - offsetMs);
}

const lastRunDate = db.prepare(
  "SELECT MAX(auditDate) AS d FROM credit_audit_runs WHERE status IN ('ok','anomalies')"
);

/**
 * Run daily at RUN_TIME, and once at startup if today's run was missed (a
 * container restart at the wrong moment must not silently skip a day — a gap in
 * the snapshots is a gap in the only record of what balances used to be).
 */
export function startCreditAudit(): void {
  if (!ENABLED) {
    console.log("credit-audit: disabled (CREDIT_AUDIT_ENABLED=false)");
    return;
  }

  const today = auditDateFor(new Date());
  const last = (lastRunDate.get() as { d: string | null }).d;
  if (last !== today) {
    // Delayed so startup isn't competing with the rest of boot; also gives
    // Firestore credentials time to be ready.
    setTimeout(() => void runCreditAudit(last ? "startup" : "startup-baseline"), 30_000).unref();
  }

  const schedule = () => {
    const at = nextRunAt();
    console.log(`credit-audit: next run ${at.toISOString()} (${RUN_TIME} UTC+${TZ_OFFSET_MIN / 60})`);
    setTimeout(async () => {
      try {
        await runCreditAudit("schedule");
      } finally {
        schedule();
      }
    }, at.getTime() - Date.now()).unref();
  };
  schedule();
}

// ── Admin API ───────────────────────────────────────────────────────────────
// Guarded by a static token rather than Firebase: there is no admin role in the
// user model, and this must stay reachable when Firebase itself is the suspect.
function tokenMatches(provided: string): boolean {
  const a = crypto.createHash("sha256").update(provided).digest();
  const b = crypto.createHash("sha256").update(ADMIN_TOKEN).digest();
  return crypto.timingSafeEqual(a, b);
}

function requireAdmin(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) {
  if (!ADMIN_TOKEN) {
    return res.status(503).json({ error: "admin API disabled (ADMIN_API_TOKEN unset)" });
  }
  const header = req.headers["x-admin-token"];
  const provided =
    (typeof header === "string" ? header : undefined) ??
    req.headers.authorization?.split("Bearer ")[1];
  if (!provided || !tokenMatches(provided)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

export const creditAuditRouter = express.Router();

// Blunts brute-forcing the static token. Every request arrives from the nginx
// container, so per-IP buckets would all be the same bucket anyway — one global
// budget for these routes, stated outright rather than left to look per-client.
creditAuditRouter.use(
  rateLimit({
    windowMs: 60_000,
    limit: 30,
    keyGenerator: () => "admin",
    standardHeaders: true,
    legacyHeaders: false,
    validate: { xForwardedForHeader: false, keyGeneratorIpFallback: false },
  })
);
creditAuditRouter.use(requireAdmin);

creditAuditRouter.get("/runs", (req, res) => {
  const limit = Math.min(Number(req.query.limit ?? 30), 200);
  res.json(
    db
      .prepare("SELECT * FROM credit_audit_runs ORDER BY id DESC LIMIT ?")
      .all(limit)
  );
});

creditAuditRouter.get("/anomalies", (req, res) => {
  const limit = Math.min(Number(req.query.limit ?? 100), 500);
  const status = req.query.status as string | undefined;
  const rows = status
    ? db
        .prepare(
          "SELECT * FROM credit_anomalies WHERE status = ? ORDER BY id DESC LIMIT ?"
        )
        .all(status, limit)
    : db
        .prepare("SELECT * FROM credit_anomalies ORDER BY id DESC LIMIT ?")
        .all(limit);
  res.json(rows.map((r: any) => ({ ...r, detail: safeJson(r.detail) })));
});

creditAuditRouter.get("/ledger", (req, res) => {
  const limit = Math.min(Number(req.query.limit ?? 200), 1000);
  const uid = req.query.uid as string | undefined;
  res.json(
    uid
      ? db
          .prepare(
            "SELECT * FROM credit_ledger WHERE uid = ? ORDER BY id DESC LIMIT ?"
          )
          .all(uid, limit)
      : db.prepare("SELECT * FROM credit_ledger ORDER BY id DESC LIMIT ?").all(limit)
  );
});

creditAuditRouter.get("/snapshots", (req, res) => {
  const limit = Math.min(Number(req.query.limit ?? 100), 1000);
  const uid = req.query.uid as string | undefined;
  res.json(
    uid
      ? db
          .prepare(
            "SELECT * FROM credit_snapshots WHERE uid = ? ORDER BY snapshotDate DESC LIMIT ?"
          )
          .all(uid, limit)
      : db
          .prepare(
            "SELECT * FROM credit_snapshots ORDER BY snapshotDate DESC, uid LIMIT ?"
          )
          .all(limit)
  );
});

// Confirmed payments with nothing in the journal to match, all-time. The nightly
// `uncredited_payment` finding only ever sees one window, so it names each of
// these exactly once and then the window moves past them; this is the standing
// list of who is still owed credits, and it empties itself as they are granted.
const uncreditedOrders = lazy(`
  SELECT o.orderNo, o.uid, o.credits, o.amt, o.tradeNo, o.paidAt, o.createdAt
    FROM newebpay_orders o
   WHERE o.status = 'paid'
     AND NOT EXISTS (SELECT 1 FROM credit_ledger l
                      WHERE l.reason = 'purchase' AND l.ref = o.orderNo)
   ORDER BY COALESCE(o.paidAt, o.createdAt) DESC
   LIMIT ?
`);

creditAuditRouter.get("/uncredited-orders", (req, res) => {
  const limit = Math.min(Number(req.query.limit ?? 200), 1000);
  res.json(uncreditedOrders().all(limit));
});

const findLedgerByRef = db.prepare(
  "SELECT id FROM credit_ledger WHERE reason = 'purchase' AND ref = ?"
);
/** Orders being granted right now — see the comment in the route below. */
const grantsInFlight = new Set<string>();

/**
 * Grant the credits for a payment that was confirmed but never delivered: the
 * remediation for `uncredited_payment`. Deliberately not automatic — the audit
 * never hands out credits — and deliberately journaled as the `purchase` it
 * should have been, under the order's own number, so the unique (reason, ref)
 * index makes a repeat call a no-op and the order drops off the list above.
 */
creditAuditRouter.post("/uncredited-orders/:orderNo/credit", async (req, res) => {
  const orderNo = req.params.orderNo;
  const order = findPaidOrder().get(orderNo) as PaidOrder | undefined;
  if (!order) return res.status(404).json({ error: "no paid order with that number" });
  if (findLedgerByRef.get(orderNo)) {
    return res.status(409).json({ error: "order already credited" });
  }
  // The ledger row is only written once Firestore confirms, so two calls arriving
  // together would both get past that check. One backend process, so a set closes
  // the window; the unique index handles everything after the first completes.
  if (grantsInFlight.has(orderNo)) {
    return res.status(409).json({ error: "grant already in progress" });
  }

  grantsInFlight.add(orderNo);
  try {
    const ref = getFirestore().collection("users").doc(order.uid);
    const balance = await getFirestore().runTransaction(async (tx) => {
      const snap = await tx.get(ref);
      if (!snap.exists) throw new Error("user_not_found");
      const next = Number(snap.data()?.credits ?? 0) + Number(order.credits);
      tx.update(ref, { credits: next });
      return next;
    });
    recordCreditChange({
      uid: order.uid,
      delta: Number(order.credits),
      reason: "purchase",
      ref: orderNo,
      balanceAfter: balance,
      note: `granted by admin for confirmed payment ${order.tradeNo ?? "?"} · NT$${order.amt}`,
    });
    console.warn(
      `credit-audit: granted ${order.credits} to ${order.uid} for uncredited order ${orderNo}`
    );
    res.json({ orderNo, uid: order.uid, credits: order.credits, balance });
  } catch (err) {
    const message = (err as Error).message;
    res.status(message === "user_not_found" ? 404 : 500).json({ error: message });
  } finally {
    grantsInFlight.delete(orderNo);
  }
});

/** Run the audit now (e.g. after an incident, or to verify a fix). */
creditAuditRouter.post("/run", async (_req, res) => {
  const summary = await runCreditAudit("manual");
  res.json(summary);
});

/**
 * Resolve an anomaly.
 *   acknowledge — seen, balance left alone
 *   dismiss     — false positive
 *   correct     — claw the unexplained credits back to the reconciled value
 */
creditAuditRouter.post("/anomalies/:id/resolve", async (req, res) => {
  const id = Number(req.params.id);
  const { action, note } = req.body ?? {};
  const row = db.prepare("SELECT * FROM credit_anomalies WHERE id = ?").get(id) as any;
  if (!row) return res.status(404).json({ error: "Not found" });

  if (action === "correct") {
    if (row.expectedCredits === null || row.currentCredits === null) {
      return res.status(400).json({ error: "Anomaly has no reconciled balance to apply" });
    }
    if (row.expectedCredits >= row.currentCredits) {
      // Correcting upward would make this endpoint a credit-granting API — the
      // exact hole the audit exists to close. Do it by hand with admin_adjust.
      return res.status(400).json({ error: "Correction would grant credits; refused" });
    }
    const ok = await clawBack(row.uid, row.currentCredits, row.expectedCredits, id);
    if (!ok) {
      return res
        .status(409)
        .json({ error: "Balance changed since the audit; re-run the audit first" });
    }
    markAnomaly.run("corrected", note ?? "corrected via admin API", new Date().toISOString(), id);
    return res.json({ status: "corrected", uid: row.uid, credits: row.expectedCredits });
  }

  if (action === "acknowledge" || action === "dismiss") {
    markAnomaly.run(
      action === "dismiss" ? "dismissed" : "acknowledged",
      note ?? null,
      new Date().toISOString(),
      id
    );
    return res.json({ status: action });
  }

  return res.status(400).json({ error: "action must be acknowledge, dismiss or correct" });
});

/**
 * Deliberate manual balance change (support credit, refund). Goes through the
 * ledger so tomorrow's audit does not flag it — which is the point: any change
 * that does not come through here is, by definition, unexplained.
 */
creditAuditRouter.post("/adjust", async (req, res) => {
  const { uid, delta, note } = req.body ?? {};
  const n = Number(delta);
  if (typeof uid !== "string" || !uid || !Number.isInteger(n) || n === 0) {
    return res.status(400).json({ error: "uid and a non-zero integer delta are required" });
  }

  const ref = getFirestore().collection("users").doc(uid);
  try {
    const balance = await getFirestore().runTransaction(async (tx) => {
      const snap = await tx.get(ref);
      if (!snap.exists) throw new Error("user_not_found");
      const current = Number(snap.data()?.credits ?? 0);
      const next = current + n;
      if (next < 0) throw new Error("would_go_negative");
      tx.update(ref, { credits: next });
      return next;
    });
    recordCreditChange({
      uid,
      delta: n,
      reason: "admin_adjust",
      ref: `adjust:${crypto.randomUUID()}`,
      balanceAfter: balance,
      note: typeof note === "string" ? note : null,
    });
    console.warn(`credit-audit: admin adjusted ${uid} by ${n} → ${balance} (${note ?? "no note"})`);
    res.json({ uid, delta: n, credits: balance });
  } catch (err) {
    const message = (err as Error).message;
    const status = message === "user_not_found" ? 404 : message === "would_go_negative" ? 400 : 500;
    res.status(status).json({ error: message });
  }
});

function safeJson(s: string | null) {
  if (!s) return null;
  try {
    return JSON.parse(s);
  } catch {
    return s;
  }
}
