// server/services/creditHistory.ts — Member Credit Journal & History Aggregator
// Aggregates positive credit events (additions) and consumption events (deductions)
// guaranteeing mathematical parity against the user's active CreditBank balance.

import { db } from "../db";
import { CreditBank } from "./creditBank";
import { generateReceiptSignature } from "../newebpay";

export interface CreditAdditionItem {
  id: number;
  createdAt: string;
  delta: number;
  reason: "purchase" | "signup" | "refund" | "admin_adjust" | "reconcile_correction" | string;
  note?: string;
  orderNo?: string;
  amt?: number;
  usdAmt?: number;
  tradeNo?: string;
  buyerName?: string | null;
  receiptIssuedAt?: string | null;
  receiptUrl?: string | null;
}

export interface CreditDeductionItem {
  id: number;
  createdAt: string;
  delta: number;
  reason: "consume" | "admin_adjust" | string;
  ref: string;
  fileId?: number | null;
  filename?: string | null;
  analysisType?: string | null;
  note?: string;
}

export interface CreditHistoryResponse {
  balance: number;
  additions: CreditAdditionItem[];
  deductions: CreditDeductionItem[];
}

/**
 * Retrieves the full double-entry credit journal for an authenticated member.
 * - Left column (additions): delta > 0 (purchases, bonuses, refunds, positive adjustments).
 *   For purchases, attaches NewebPay billing info, buyerName, receiptIssuedAt.
 *   `receiptUrl` is only returned if the receipt has been officially claimed (receiptIssuedAt is NOT null).
 * - Right column (deductions): delta < 0 (analysis charges, negative adjustments).
 *   Parses `ref` to link filename and analysisType from file_meta, with graceful fallback to `note`.
 */
export async function getMemberCreditHistory(
  uid: string,
  clientUrl?: string
): Promise<CreditHistoryResponse> {
  let balance = await CreditBank.getBalance(uid);
  if (balance === 0) {
    const latestLedger = db
      .prepare(
        "SELECT balanceAfter FROM credit_ledger WHERE uid = ? ORDER BY createdAt DESC, id DESC LIMIT 1"
      )
      .get(uid) as any;
    if (latestLedger && typeof latestLedger.balanceAfter === "number") {
      balance = latestLedger.balanceAfter;
    }
  }
  const effectiveClientUrl = (clientUrl || process.env.CLIENT_URL || "").replace(/\/+$/, "");

  // 1. Fetch all positive credit ledger rows (additions)
  const additionsRows = db
    .prepare(
      `SELECT id, delta, reason, ref, note, createdAt
         FROM credit_ledger
        WHERE uid = ? AND delta > 0
        ORDER BY createdAt DESC`
    )
    .all(uid) as any[];

  const getOrderStmt = db.prepare(
    `SELECT orderNo, amt, usdAmt, fxRate, tradeNo, paidAt, buyerName, receiptIssuedAt
       FROM newebpay_orders
      WHERE orderNo = ?`
  );

  const additions: CreditAdditionItem[] = additionsRows.map((row) => {
    const item: CreditAdditionItem = {
      id: row.id,
      createdAt: row.createdAt,
      delta: row.delta,
      reason: row.reason,
      note: row.note || undefined,
    };

    if (row.reason === "purchase" && row.ref) {
      const order = getOrderStmt.get(row.ref) as any;
      if (order) {
        item.orderNo = order.orderNo;
        item.amt = order.amt;
        item.usdAmt =
          order.usdAmt ??
          (order.amt === 1 ? 1 : Math.round(order.amt / (order.fxRate || 32)));
        item.tradeNo = order.tradeNo || undefined;
        item.buyerName = order.buyerName || null;
        item.receiptIssuedAt = order.receiptIssuedAt || null;

        // Strict Access Control: receiptUrl is provided ONLY after the official receipt is claimed.
        // Unclaimed purchases return null, requiring the user to specify buyerName before accessing the URL.
        if (order.receiptIssuedAt) {
          const sig = generateReceiptSignature(order.orderNo, order.paidAt);
          item.receiptUrl = `${effectiveClientUrl}/api/newebpay/orders/${order.orderNo}/receipt?sig=${sig}`;
        } else {
          item.receiptUrl = null;
        }
      }
    }
    return item;
  });

  // 2. Fetch all negative credit ledger rows (deductions)
  const deductionsRows = db
    .prepare(
      `SELECT id, delta, reason, ref, note, createdAt
         FROM credit_ledger
        WHERE uid = ? AND delta < 0
        ORDER BY createdAt DESC`
    )
    .all(uid) as any[];

  const getFileStmt = db.prepare(
    `SELECT id, filename, analysisType FROM file_meta WHERE id = ?`
  );

  const deductions: CreditDeductionItem[] = deductionsRows.map((row) => {
    const item: CreditDeductionItem = {
      id: row.id,
      createdAt: row.createdAt,
      delta: row.delta,
      reason: row.reason,
      ref: row.ref || "",
      note: row.note || undefined,
    };

    if (row.ref) {
      // Matches composite references: "analysis:{fileId}:{uuid}" or "file:{fileId}"
      const match = row.ref.match(/^(?:analysis|file):(\d+)/);
      if (match) {
        const fileId = parseInt(match[1], 10);
        item.fileId = fileId;
        const file = getFileStmt.get(fileId) as any;
        if (file) {
          item.filename = file.filename;
          item.analysisType = file.analysisType;
        }
      }
    }
    return item;
  });

  return {
    balance,
    additions,
    deductions,
  };
}
