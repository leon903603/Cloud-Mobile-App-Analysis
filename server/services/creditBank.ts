import crypto from "crypto";
import { getFirestore } from "firebase-admin/firestore";
import { db as sqliteDb } from "../db";
import {
  recordCreditChange,
  SIGNUP_CREDITS,
  LedgerReason,
} from "../credit_audit";

export { LedgerReason };

export type CreditErrorCode =
  | "insufficient_credits"
  | "user_not_found"
  | "duplicate_transaction"
  | "would_go_negative"
  | "invalid_amount"
  | "persistence_error";

export type CreditResult<T = { balance: number }> =
  | ({ ok: true } & T)
  | { ok: false; code: CreditErrorCode; message: string };

export interface CreditBankPort {
  getBalance(uid: string): Promise<number>;
  ensureUserSeeded(
    uid: string,
    email?: string | null
  ): Promise<CreditResult<{ balance: number; seeded: boolean }>>;
  consumeCreditForAnalysis(params: {
    uid: string;
    fileId: number;
    attemptUuid?: string;
    analysisType?: string;
    label?: string;
  }): Promise<CreditResult<{ balance: number; chargeRef: string }>>;
  chargeForAnalysis(params: {
    uid: string;
    fileId: number;
    label: string;
    attemptUuid?: string;
  }): Promise<CreditResult<{ balance: number; chargeRef: string }>>;
  refundFailedAnalysis(params: {
    uid: string;
    fileId: number;
    chargeRef?: string;
    attemptUuid?: string;
    reasonNote?: string;
    reasonDetail?: string;
  }): Promise<CreditResult<{ balance: number }>>;
  grantPurchase(params: {
    uid: string;
    orderNo?: string;
    orderId?: string;
    credits?: number;
    creditsToAdd?: number;
    note?: string;
    amountTwd?: number;
  }): Promise<CreditResult<{ balance: number; alreadyGranted?: boolean }>>;
  adminAdjust(params: {
    uid: string;
    delta: number;
    note?: string | null;
  }): Promise<CreditResult<{ balance: number; adjustRef: string }>>;
  clawBackToExpected(params: {
    uid: string;
    observed: number;
    expected: number;
    anomalyId: number;
    at?: string;
  }): Promise<boolean>;
  reconcileUser?(uid: string): Promise<{ ledgerDeltaSum: number; firestoreBalance: number; status: string }>;
}

class CreditBankService implements CreditBankPort {
  /**
   * Helper to write to ledger with non-blocking async retry and critical error logging
   */
  private async journalWithRetry(entry: {
    uid: string;
    delta: number;
    reason: LedgerReason;
    ref?: string | null;
    balanceAfter?: number | null;
    note?: string | null;
    at?: string | null;
  }): Promise<boolean> {
    const maxRetries = 3;
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      const ok = recordCreditChange(entry);
      if (ok) return true;
      // If failed due to duplicate ref, don't retry, it's already recorded
      const exists = entry.ref
        ? sqliteDb
            .prepare("SELECT id FROM credit_ledger WHERE reason = ? AND ref = ?")
            .get(entry.reason, entry.ref)
        : null;
      if (exists) return true;

      if (attempt < maxRetries) {
        await new Promise((resolve) => setTimeout(resolve, 50 * attempt));
      }
    }
    console.error(
      "[CRITICAL-LEDGER-DRIFT] Failed to journal credit change after retries:",
      entry
    );
    return false;
  }

  async getBalance(uid: string): Promise<number> {
    try {
      const doc = await getFirestore().collection("users").doc(uid).get();
      return doc.exists ? Number(doc.data()?.credits ?? 0) : 0;
    } catch (err) {
      console.error("[CreditBank] Error fetching balance for uid:", uid, err);
      return 0;
    }
  }

  async ensureUserSeeded(
    uid: string,
    email?: string | null
  ): Promise<CreditResult<{ balance: number; seeded: boolean }>> {
    if (!uid) {
      return { ok: false, code: "user_not_found", message: "Missing uid" };
    }

    const docRef = getFirestore().collection("users").doc(uid);
    let seeded = false;
    let finalBalance = 0;

    try {
      await getFirestore().runTransaction(async (tx) => {
        const snap = await tx.get(docRef);
        if (!snap.exists) {
          seeded = true;
          finalBalance = SIGNUP_CREDITS;
          tx.set(
            docRef,
            {
              credits: SIGNUP_CREDITS,
              email: email ?? null,
              createdAt: new Date().toISOString(),
            },
            { merge: true }
          );
        } else {
          finalBalance = Number(snap.data()?.credits ?? 0);
        }
      });

      if (seeded && SIGNUP_CREDITS > 0) {
        await this.journalWithRetry({
          uid,
          delta: SIGNUP_CREDITS,
          reason: "signup",
          ref: uid,
          balanceAfter: finalBalance,
          note: "Initial signup grant",
        });
      }

      return { ok: true, balance: finalBalance, seeded };
    } catch (err: any) {
      console.error("[CreditBank] ensureUserSeeded error:", err);
      return {
        ok: false,
        code: "persistence_error",
        message: err?.message || "Failed to seed user credits",
      };
    }
  }

  async consumeCreditForAnalysis(params: {
    uid: string;
    fileId: number;
    attemptUuid?: string;
    analysisType?: string;
    label?: string;
  }): Promise<CreditResult<{ balance: number; chargeRef: string }>> {
    const { uid, fileId } = params;
    const attemptUuid = params.attemptUuid || crypto.randomBytes(4).toString("hex");
    const chargeRef = `analysis:${fileId}:${attemptUuid}`;
    const label = params.label || `${(params.analysisType || "analysis").toUpperCase()} analysis: #${fileId} (attempt ${attemptUuid})`;

    // Pre-flight check: SQLite writable & idempotency
    try {
      const existing = sqliteDb
        .prepare("SELECT id FROM credit_ledger WHERE reason = 'consume' AND ref = ?")
        .get(chargeRef);
      if (existing) {
        return {
          ok: false,
          code: "duplicate_transaction",
          message: "Charge reference already exists",
        };
      }
    } catch (err: any) {
      console.error("[CreditBank] Pre-flight sqlite check failed:", err);
      return {
        ok: false,
        code: "persistence_error",
        message: "Storage not ready for transactions",
      };
    }

    const docRef = getFirestore().collection("users").doc(uid);
    let remaining: number | null = null;

    try {
      remaining = await getFirestore().runTransaction(async (tx) => {
        const snap = await tx.get(docRef);
        const current = snap.exists ? Number(snap.data()?.credits ?? 0) : 0;
        if (current <= 0) return null;
        const nextCredits = current - 1;
        tx.update(docRef, { credits: nextCredits });
        return nextCredits;
      });
    } catch (err: any) {
      console.error("[CreditBank] consumeCreditForAnalysis transaction error:", err);
      return {
        ok: false,
        code: "persistence_error",
        message: err?.message || "Transaction failed",
      };
    }

    if (remaining === null) {
      return {
        ok: false,
        code: "insufficient_credits",
        message: "Insufficient credits to perform analysis",
      };
    }

    // Journal AFTER transaction succeeds, passing balanceAfter
    await this.journalWithRetry({
      uid,
      delta: -1,
      reason: "consume",
      ref: chargeRef,
      balanceAfter: remaining,
      note: label,
    });

    return { ok: true, balance: remaining, chargeRef };
  }

  async chargeForAnalysis(params: {
    uid: string;
    fileId: number;
    label: string;
    attemptUuid?: string;
  }): Promise<CreditResult<{ balance: number; chargeRef: string }>> {
    return this.consumeCreditForAnalysis(params);
  }

  async refundFailedAnalysis(params: {
    uid: string;
    fileId: number;
    chargeRef?: string;
    attemptUuid?: string;
    reasonNote?: string;
    reasonDetail?: string;
  }): Promise<CreditResult<{ balance: number }>> {
    const { uid, fileId } = params;
    const chargeRef = params.chargeRef || `analysis:${fileId}:${params.attemptUuid}`;
    const reasonNote = params.reasonNote || params.reasonDetail || `Refund 1 credit for failed analysis (file #${fileId})`;

    // Pre-flight check: Must have matching consume record
    const matchedConsume = sqliteDb
      .prepare(
        "SELECT id, delta FROM credit_ledger WHERE uid = ? AND reason = 'consume' AND ref = ? AND delta = -1"
      )
      .get(uid, chargeRef);

    if (!matchedConsume) {
      console.warn(`[CreditBank] Refund rejected: no consume record matching ref ${chargeRef} for uid ${uid}`);
      return {
        ok: false,
        code: "persistence_error",
        message: "No matching consumed charge found for this refund",
      };
    }

    // Check if refund already journaled for this chargeRef (using the SAME ref as consume)
    const alreadyRefunded = sqliteDb
      .prepare("SELECT id FROM credit_ledger WHERE uid = ? AND reason = 'refund' AND ref = ?")
      .get(uid, chargeRef);

    if (alreadyRefunded) {
      console.warn(`[CreditBank] Refund rejected: refund already processed for ref ${chargeRef}`);
      return {
        ok: false,
        code: "duplicate_transaction",
        message: "Refund already processed for this analysis attempt",
      };
    }

    const docRef = getFirestore().collection("users").doc(uid);
    let newBalance = 0;

    try {
      newBalance = await getFirestore().runTransaction(async (tx) => {
        const snap = await tx.get(docRef);
        const current = snap.exists ? Number(snap.data()?.credits ?? 0) : 0;
        const nextCredits = current + 1;
        tx.update(docRef, { credits: nextCredits });
        return nextCredits;
      });
    } catch (err: any) {
      console.error("[CreditBank] refundFailedAnalysis transaction error:", err);
      return {
        ok: false,
        code: "persistence_error",
        message: err?.message || "Refund transaction failed",
      };
    }

    // Journal AFTER transaction succeeds with exact same ref: chargeRef and balanceAfter: newBalance
    await this.journalWithRetry({
      uid,
      delta: +1,
      reason: "refund",
      ref: chargeRef,
      balanceAfter: newBalance,
      note: reasonNote,
    });

    console.log(
      `[CreditBank] Restored 1 credit to user ${uid} (ref: ${chargeRef}, new balance: ${newBalance})`
    );
    return { ok: true, balance: newBalance };
  }

  async grantPurchase(params: {
    uid: string;
    orderNo?: string;
    orderId?: string;
    credits?: number;
    creditsToAdd?: number;
    note?: string;
    amountTwd?: number;
  }): Promise<CreditResult<{ balance: number; alreadyGranted?: boolean }>> {
    const { uid } = params;
    const orderRef = params.orderNo || params.orderId || "";
    const credits = params.credits ?? params.creditsToAdd ?? 0;
    const note = params.note || `Purchased ${credits} credits via Order #${orderRef}`;

    if (credits <= 0) {
      return { ok: false, code: "invalid_amount", message: "Credits must be positive" };
    }

    // Check if already journaled (idempotent, pure orderNo/orderId without "order:" prefix)
    const existing = sqliteDb
      .prepare("SELECT id, balanceAfter FROM credit_ledger WHERE reason = 'purchase' AND ref = ?")
      .get(orderRef) as { id: number; balanceAfter: number | null } | undefined;

    if (existing) {
      const balance = existing.balanceAfter ?? (await this.getBalance(uid));
      return { ok: true, balance, alreadyGranted: true };
    }

    const docRef = getFirestore().collection("users").doc(uid);
    let newBalance = 0;

    try {
      newBalance = await getFirestore().runTransaction(async (tx) => {
        const snap = await tx.get(docRef);
        const current = snap.exists ? Number(snap.data()?.credits ?? 0) : 0;
        const target = current + credits;
        tx.set(docRef, { credits: target }, { merge: true });
        return target;
      });
    } catch (err: any) {
      console.error("[CreditBank] grantPurchase transaction error:", err);
      return {
        ok: false,
        code: "persistence_error",
        message: err?.message || "Failed to grant purchase credits",
      };
    }

    // Journal AFTER transaction succeeds with direct orderRef (no "order:" prefix) and balanceAfter: newBalance
    await this.journalWithRetry({
      uid,
      delta: credits,
      reason: "purchase",
      ref: orderRef,
      balanceAfter: newBalance,
      note,
    });

    return { ok: true, balance: newBalance, alreadyGranted: false };
  }

  async adminAdjust(params: {
    uid: string;
    delta: number;
    note?: string | null;
  }): Promise<CreditResult<{ balance: number; adjustRef: string }>> {
    const { uid, delta, note } = params;
    const adjustRef = `admin:${crypto.randomUUID()}`;
    const docRef = getFirestore().collection("users").doc(uid);
    let newBalance = 0;

    try {
      const result = await getFirestore().runTransaction(async (tx) => {
        const snap = await tx.get(docRef);
        const current = snap.exists ? Number(snap.data()?.credits ?? 0) : 0;
        const target = current + delta;
        if (target < 0) return null; // Prevent negative balance
        tx.set(docRef, { credits: target }, { merge: true });
        return target;
      });

      if (result === null) {
        return {
          ok: false,
          code: "would_go_negative",
          message: "Adjustment would result in negative credit balance",
        };
      }
      newBalance = result;
    } catch (err: any) {
      console.error("[CreditBank] adminAdjust transaction error:", err);
      return {
        ok: false,
        code: "persistence_error",
        message: err?.message || "Failed to adjust credits",
      };
    }

    await this.journalWithRetry({
      uid,
      delta,
      reason: "admin_adjust",
      ref: adjustRef,
      balanceAfter: newBalance,
      note: note ?? "Admin adjustment",
    });

    return { ok: true, balance: newBalance, adjustRef };
  }

  async clawBackToExpected(params: {
    uid: string;
    observed: number;
    expected: number;
    anomalyId: number;
    at?: string;
  }): Promise<boolean> {
    const { uid, observed, expected, anomalyId, at } = params;
    const ref = getFirestore().collection("users").doc(uid);

    try {
      const applied = await getFirestore().runTransaction(async (tx) => {
        const snap = await tx.get(ref);
        const current = snap.exists ? Number(snap.data()?.credits ?? 0) : 0;
        if (current !== observed) return null;
        if (expected >= current) return null;
        if (expected < 0) return null;
        tx.update(ref, { credits: expected });
        return expected;
      });

      if (applied === null) return false;

      await this.journalWithRetry({
        uid,
        delta: expected - observed,
        reason: "reconcile_correction",
        ref: `anomaly:${anomalyId}`,
        balanceAfter: expected,
        note: "unexplained credits removed by credit audit",
        at,
      });

      return true;
    } catch (err) {
      console.error("[CreditBank] clawBackToExpected transaction error:", err);
      return false;
    }
  }
}

export const CreditBank = new CreditBankService();
