# Specification: CMAA Self-Serve Credit Journal & On-Demand Official Receipt System

**Document ID**: `SPEC-CMAA-PAY-002` (Supersedes `SPEC-CMAA-PAY-001`)  
**Status**: APPROVED / IMPLEMENTATION READY  
**Triage Label**: `ready-for-agent`  
**Target Systems**:
- Frontend (`Cloud-Mobile-App-Analysis/frontend`): Navigation, Credit History Modal/View, Guest Uploader
- Backend (`Cloud-Mobile-App-Analysis/server`): Member Credit History API, On-Demand Receipt Claim API, NewebPay Webhook Fulfillment, Official Receipt HTML Renderer

---

## Problem Statement

Users of the Cloud Mobile App Analysis (CMAA) platform face several critical usability, financial, and operational obstacles under the initial payment and receipt workflow:

1. **Inflexible Corporate & Institutional Reimbursement**:
   Academic researchers, university laboratories, and enterprise auditors purchasing analysis credits require official reimbursement receipts (支出證明 / 收據) issued to their specific **Company, Institution, or Department Name** (公司或機關抬頭, e.g. "國立臺灣大學 電機工程學系" or "Acme Cybersecurity Inc."). Under the previous automated workflow, receipts were generated immediately upon payment using only the raw account email, giving users no opportunity to specify their legal expense entity.

2. **Unwanted Email Dependencies & Delivery Failures**:
   The previous model pushed receipt emails via third-party mailer APIs (Resend) immediately upon payment confirmation. This introduced friction: email spam filtering, institutional firewall drops, client-side SVG sanitization issues (Gmail/Outlook stripping vector stamps), and support overhead when users simply wanted an immediate, printable URL for their accounting department.

3. **Visitor Receipt Mismatch & Administrative Burden**:
   Unauthenticated visitors purchasing single-run reports were asked for a receipt email. In practice, visitors frequently enter throwaway or invalid emails, causing mailer errors, while expecting enterprise reimbursement features. Corporate and fiscal compliance requires verifiable accountability, which is only appropriate for registered member accounts.

4. **Zero Credit Transparency**:
   Logged-in members currently see only a static counter (`Credits: 106`) in the top navigation bar. Members have no visibility into how credits were acquired (purchase packages, dates, order numbers, transaction references) or how they were spent (which APK/IPA file was analyzed, analysis type, timestamp).

---

## Solution

The platform re-architects credit tracking and receipt generation into an **on-demand, self-serve, and zero-email** model:

1. **Visitor Receipt Discontinuation & Clear Advisory**:
   - Completely remove receipt email input fields and receipt generation from the visitor/guest flow.
   - Display a clear, prominent English advisory notice on the guest analysis payment interface:  
     > *"Notice: Official reimbursement receipts are available exclusively for registered members. If your institution or company requires an official receipt for expense claims, please register or sign in before purchasing."*

2. **Interactive Credit Audit Journal (Credits History)**:
   - Make the top navigation bar's `Credits: {count}` indicator interactive and clickable.
   - Clicking opens a comprehensive **Credit History View / Modal** displaying account balance, email, and a side-by-side balanced dual-column layout:
     - **Left Column (Credits Added)**: Chronological journal of all positive credit events (`delta > 0`, including purchases, signup bonuses, analysis failure refunds, and positive admin adjustments). For purchases (`reason = 'purchase'`), displays date, credit quantity, currency amount (TWD & USD), order number, payment reference, and receipt claim status.
     - **Right Column (Credits Deducted)**: Chronological journal of all credit consumption events (`delta < 0`, including analysis deductions and negative adjustments). Parses composite references (`analysis:{fileId}:{uuid}` or `file:{fileId}`) to resolve file metadata (`filename`, `analysisType`), falling back to `note` if file metadata is purged.

3. **On-Demand Single-Issue Official Receipt Generation**:
   - In the "Credits Added" table, each eligible paid order provides an on-demand receipt generation action.
   - Users enter their official **Company / Institution Name** (公司/機關抬頭, 2-120 characters) via an intuitive prompt/dialog.
   - **Strict Once-Only Guard**: Each purchase record can generate a receipt exactly once (`WHERE orderNo = ? AND receiptIssuedAt IS NULL`). Once claimed, the company name and issuance timestamp are permanently locked and immutable.
   - **Airtight Access Control**: In `GET /api/member/credits/history`, `receiptUrl` is only computed and returned when `receiptIssuedAt IS NOT NULL`. Unclaimed orders return `receiptUrl: null`. Because HMAC signatures cannot be forged without the server's private secret, users cannot bypass the claim step.
   - Upon generation, the system immediately presents a direct, browser-viewable HTML receipt link with "View Official Receipt" and "Copy Receipt Link" actions.

4. **Complete Elimination of Payment Email Dispatch**:
   - Delete all automated receipt email sending (`sendReceiptEmailSafe` / Resend) from the payment webhook (`POST /api/newebpay/notify`).
   - Payment webhooks perform only atomic state transition (`pending` -> `paid`) and instant credit allocation (`CreditBank.grantPurchase`), eliminating external email timeout hazards.
   - The Resend email client in `receiptMailer.ts` is preserved as a general email delivery infrastructure for inquiry dispatch and backward compatibility.

---

## User Stories

### Member Credit Transparency & Navigation
1. As a **Member**, I want the `Credits: {count}` badge in the top navigation bar to be visibly clickable with a hover indicator, so that I immediately know I can view my credit details.
2. As a **Member**, I want clicking `Credits: {count}` to open a dedicated Credit History interface without losing my current application session, so that I can inspect my financial activity seamlessly.
3. As a **Member**, I want to see my current verified email address and active credit balance prominently displayed at the top of the Credit History interface, so that I can confirm my account identity.
4. As a **Member**, I want the Credit History interface to be organized into a two-column layout separating "Credits Added" on the left and "Credits Deducted" on the right, so that I can easily distinguish income from expenditure.
5. As a **Member**, I want a clean "Back" or "Close" button on the Credit History interface, so that I can return to the main dashboard anytime.

### Credits Added (Purchases & Additions)
6. As a **Member**, I want to see all my credit additions listed chronologically with the newest transactions at the top, so that I can verify recent payments.
7. As a **Member**, I want each credit addition row to show the transaction timestamp (formatted in local time), the credit amount added (e.g., `+1`, `+5`), and the reason (e.g., `Starter Package`, `Pro Package`, `Signup Bonus`), so that I understand where each credit came from.
8. As a **Member**, I want each purchase row to display the billed NewebPay Merchant Order Number (`orderNo`), the charged TWD amount (`NT$`), and the USD catalog price, so that I can cross-reference my credit card billing statement.
9. As a **Member**, I want to see an empty state message if I have not yet made any credit purchases, so that the screen does not look broken.

### On-Demand Official Receipt Generation
10. As a **Member**, I want an unissued purchase record to display a "Request Official Receipt" button, so that I can claim a receipt when my organization requires it.
11. As a **Member**, I want clicking "Request Official Receipt" to prompt me to enter our official Company or Institution Name (公司/機關抬頭), so that the resulting document meets my university or enterprise reimbursement standards.
12. As a **Member**, I want the company name input to provide a clear placeholder and character limit guidance, so that I do not enter invalid or truncated names.
13. As a **Member**, I want the system to enforce that each purchase order can only generate a receipt once, so that duplicate or conflicting fiscal claims cannot be issued for the same payment.
14. As a **Member**, I want the receipt generation request to succeed instantly and return a direct web receipt URL, so that I do not have to wait for an email to arrive.
15. As a **Member**, I want the UI to immediately update the purchase row after generation to show "Receipt Issued to: [Company Name]" along with a "View Official Receipt ↗" button and a "Copy Link" button, so that I can access or share the link anytime.
16. As a **Member**, I want already issued receipts in my history to permanently retain their "View Official Receipt ↗" link, so that I can re-access or re-print the receipt months later during annual tax or grant audits.

### Web Official Receipt View & Printing
17. As a **Member**, I want clicking "View Official Receipt" to open the formal A4 receipt in a clean browser window, displaying our specified Company Name in the `Received from:` field.
18. As a **Member**, I want the web receipt to feature the official vector SVG seal (`SUPREMA TECHNOLOGIES LTD ★ OFFICIAL SEAL ★` with `VERIFIED & SECURED`), so that the document carries formal institutional authority.
19. As a **Member**, I want the web receipt to display the issuance timestamp, itemized credit package description, NewebPay transaction number (`tradeNo`), and the official reimbursement retention notice.
20. As a **Member**, I want the web receipt page to feature a "Print / Save as PDF" button and clean `@media print` rules, so that I can print or save a perfect A4 PDF with one click.
21. As a **Member**, I want to be able to copy the web receipt URL and send it to our accounting department, so that finance personnel can verify and download the receipt directly without needing my platform password.

### Credits Deducted (Analysis Consumption)
22. As a **Member**, I want the right column to list all credit deductions chronologically, so that I have a complete audit trail of how my credits were utilized.
23. As a **Member**, I want each deduction row to display the deduction timestamp, the application filename (or hash) analyzed, the analysis mode (Static / Dynamic), and the target platform (Android / iOS), so that I know exactly which job consumed each credit.
24. As a **Member**, I want deduction rows to indicate if an analysis failed and resulted in an automatic credit refund, so that I know my credits were safely restored.

### Visitor Policy & Discontinuation of Emails
25. As a **Visitor**, I want to see a clear English advisory notice on the single-report payment screen stating that official reimbursement receipts are reserved for registered members, so that I am informed before making a payment.
26. As a **Visitor**, I want the single-report payment screen to have no receipt email input field, so that the checkout form is simpler and does not collect unnecessary personal data.
27. As a **Visitor**, I want my payment to unlock my single report immediately without sending any receipt emails, so that my download is fast and clean.
28. As a **Platform Administrator**, I want all receipt email sending via external mailer APIs (Resend) to be completely removed from the payment notification webhook, so that network email latency or quota exhaustion never threatens payment fulfillment.
29. As a **Security Auditor**, I want all user-submitted company names to be strictly validated, sanitized, and HTML-entity escaped, so that malicious script payloads cannot execute stored XSS on the receipt page.
30. As a **Security Auditor**, I want access to generate or view receipts to enforce strict ownership verification and HMAC verification tokens, preventing IDOR access across accounts.

---

## Implementation Decisions

### Modules Modified & Created
1. **Frontend Navigation & Credits Component (`UserCredits.tsx`)**:
   - Transform the static text into an interactive, accessible button or badge.
   - Emits an `onClick` event or toggles the Credit History view/modal in the parent container.

2. **Frontend Credit History Component (`CreditHistoryModal.tsx` / `CreditHistoryView.tsx`)**:
   - Dedicated component rendering the two-column audit view.
   - Left Column: Credits Added list with receipt claim action / direct link.
   - Right Column: Credits Deducted list with job details.
   - Inline receipt claim dialog: collects Company Name, calls the claim API, and updates local state to show the link.

3. **Frontend Visitor Checkout (`GuestUploader.tsx`)**:
   - Remove `receiptEmail` state and input field.
   - Insert the standardized English member receipt advisory notice.

4. **Backend Member Credit History Route (`GET /api/member/credits/history`)**:
   - Authenticated via Firebase ID token (`verifyToken`).
   - Queries `credit_ledger` for the authenticated `uid`.
   - **Left Column (`additions`)**: Queries all entries where `delta > 0` ordered by `createdAt DESC` (covering `purchase`, `signup`, `refund`, and positive `admin_adjust`). For `reason = 'purchase'`, performs `LEFT JOIN newebpay_orders ON credit_ledger.ref = newebpay_orders.orderNo`. Computes and attaches `receiptUrl` **only when `receiptIssuedAt IS NOT NULL`**; when `receiptIssuedAt IS NULL`, returns `receiptUrl: null` to prevent bypassing the receipt claim step.
   - **Right Column (`deductions`)**: Queries all entries where `delta < 0` ordered by `createdAt DESC` (covering `consume` and negative adjustments). Parses composite references (`analysis:{fileId}:{uuid}` or `file:{fileId}`) using regex (e.g. `/^(?:analysis|file):(\d+)/`) to extract `fileId`, querying `file_meta` to retrieve `filename` and `analysisType`. If `file_meta` is not found or has been purged by hygiene jobs, falls back to `credit_ledger.note`.
   - Returns structured JSON `{ balance, additions: [...], deductions: [...] }` with mathematical parity guaranteed (`sum(additions.delta) + sum(deductions.delta) == balance`).

5. **Backend On-Demand Receipt Claim Route (`POST /api/orders/:orderNo/receipt/claim` & `/api/newebpay/orders/:orderNo/receipt/claim`)**:
   - Authenticated via `verifyToken`.
   - Mounted on both `/api/orders/:orderNo/receipt/claim` and `/api/newebpay/orders/:orderNo/receipt/claim` to align with the existing 307 alias convention.
   - Validates that `req.user.uid === order.uid`.
   - Validates that `order.status === 'paid'`.
   - Validates `companyName`: string, trimmed length between 2 and 120 characters (`companyName.trim().length >= 2 && companyName.trim().length <= 120`), rejecting blank or whitespace-only inputs.
   - Enforces the once-only rule atomically: `UPDATE newebpay_orders SET buyerName = ?, receiptIssuedAt = CURRENT_TIMESTAMP WHERE orderNo = ? AND receiptIssuedAt IS NULL`. If `changes === 0`, rejects with `409 Conflict`.
   - Sanitizes `buyerName` against XSS payloads via `escapeHtml`.
   - Generates the secure HMAC-SHA256 signature and returns `{ ok: true, receiptUrl, buyerName, receiptIssuedAt }`.

6. **Backend Payment Webhook Decoupling (`POST /api/newebpay/notify`)**:
   - Completely removes automated receipt email sending (`sendReceiptEmailSafe`).
   - Payment webhooks perform only atomic state transition (`pending` -> `paid`) and credit grant via `CreditBank.grantPurchase`.
   - The Resend email client in `receiptMailer.ts` is preserved as a general email delivery infrastructure for inquiry dispatch and backward compatibility.

7. **Backend Official Receipt Web Route (`GET /api/newebpay/orders/:orderNo/receipt`)**:
   - Preserves 200 OK rendering when a valid HMAC signature (`sig`) is provided, ensuring zero regression for existing orders, guest reports, and unit test suites (`http_routes_and_webhook_regression.test.ts`).
   - Title rendering precedence:
     - When `order.buyerName` is present: renders `${escapeHtml(buyerName)} (${escapeHtml(recipientEmail)})` (or `${escapeHtml(buyerName)}` if `recipientEmail` is absent) to provide both formal business expense recognition and account audit traceability.
     - When `order.buyerName` is null (legacy orders / guest orders): gracefully falls back to `${escapeHtml(recipientEmail || "Valued Customer")}`.
   - Injects receipt issuance timestamp (`receiptIssuedAt || paidAt`).
   - Continues serving the high-fidelity A4 layout with inline SVG seal and print controls.

8. **Legacy Route Governance & Deprecation**:
   - `POST /api/newebpay/orders/:orderNo/resend-receipt` is retained and marked `@deprecated` to maintain 100% backward compatibility with existing tests and administrative operations.

### Database Schema Updates (`newebpay_orders`)
The SQLite table `newebpay_orders` receives two additional nullable columns:
- `buyerName` (`TEXT DEFAULT NULL`): The user-specified company/institution name for the receipt.
- `receiptIssuedAt` (`TEXT DEFAULT NULL`): The ISO 8601 timestamp when the receipt was first generated.
- (Note: `receiptSentAt` and `receiptEmail` from the previous spec become deprecated/legacy columns).

### Data Shapes & Contracts

```typescript
// GET /api/member/credits/history response
interface CreditHistoryResponse {
  balance: number;
  additions: Array<{
    id: number;
    createdAt: string;
    delta: number;
    reason: 'purchase' | 'signup' | 'refund' | 'admin_adjust' | 'reconcile_correction' | string;
    note?: string;
    orderNo?: string;
    amt?: number;
    usdAmt?: number;
    tradeNo?: string;
    buyerName?: string | null;
    receiptIssuedAt?: string | null;
    receiptUrl?: string | null;
  }>;
  deductions: Array<{
    id: number;
    createdAt: string;
    delta: number;
    reason: 'consume' | 'admin_adjust' | string;
    ref: string;
    fileId?: number | null;
    filename?: string | null;
    analysisType?: string | null;
    note?: string;
  }>;
}

// POST /api/orders/:orderNo/receipt/claim request & response
interface ClaimReceiptRequest {
  companyName: string;
}

interface ClaimReceiptResponse {
  ok: boolean;
  receiptUrl: string;
  buyerName: string;
  receiptIssuedAt: string;
}
```

---

## Testing Decisions

### Good Test Principles
- Tests must strictly evaluate observable external behavior via public HTTP routes and published TypeScript interfaces.
- Tests must never inspect internal private helpers or assert tautological mocks.
- Every state transition (once-only lock, atomic update, XSS neutralization) must be verified through real assertions.

### Modules Under Test
1. **Receipt Claim & Idempotency Suite**:
   - Verify claiming a receipt for a paid order succeeds and returns valid `receiptUrl`, `buyerName`, and `receiptIssuedAt`.
   - Verify claiming a second time on the same order fails with `409 Conflict`.
   - Verify claiming with empty, whitespace-only, or < 2 char company name fails with `400 Bad Request`.
   - Verify claiming a receipt for another user's order fails with `403 Forbidden` (IDOR defense).
   - Verify claiming a receipt for an unpaid order fails with `400 Bad Request`.
   - Verify company names with `<script>alert(1)</script>` or HTML formatting are safely escaped on the web receipt.
   - Verify `GET /api/member/credits/history` returns `receiptUrl: null` when `receiptIssuedAt IS NULL`.
   - Verify `GET /api/newebpay/orders/:orderNo/receipt?sig=...` renders `${buyerName} (${recipientEmail})` when claimed, and gracefully falls back to `${recipientEmail || "Valued Customer"}` when unclaimed or for guest orders without breaking 200 OK.

2. **Member Credit History Suite**:
   - Verify `GET /api/member/credits/history` returns all additions (`delta > 0`, including `signup`, `purchase`, `refund`, and positive `admin_adjust`).
   - Verify `GET /api/member/credits/history` returns all deductions (`delta < 0`, including `consume` and negative adjustments).
   - Verify composite reference strings (`analysis:{fileId}:{uuid}` or `file:{fileId}`) parse `fileId` correctly to populate `filename` and `analysisType` from `file_meta`, falling back to `note` when file metadata is absent.
   - Verify unauthenticated requests return `401 Unauthorized`.

3. **Webhook Email Removal & Regression Verification**:
   - Verify that simulated NewebPay notifications unlock jobs or grant credits without invoking any email transport or requiring `RESEND_API_KEY`.
   - Verify that the notification returns HTTP 200 reliably within minimal latency.
   - Verify `npm run test:unit` regression suite (`http_routes_and_webhook_regression.test.ts`, `receipt_mailer.test.ts`, etc.) passes with 100% success.

4. **Visitor Advisory Notice Verification**:
   - Verify frontend guest checkout contains the English advisory notice and contains zero receipt email fields.

### Prior Art
- `server/tests/receipt_mailer.test.ts` (SVG seal and HTML layout verification).
- `server/tests/http_routes_and_webhook_regression.test.ts` (Webhook handling, timing-safe tokens, 307 route alias).
- `server/tests/creditBank.test.ts` and `server/tests/credit_audit_writes.test.js` (credit ledger transactions).

---

## Out of Scope

1. **PDF Generation via Cloud Lambda for Receipts**: Receipts continue to be rendered as clean, high-fidelity browser HTML with `@media print` A4 formatting for instant client-side Save-as-PDF, rather than triggering backend headless Chrome rendering.
2. **Post-Issuance Company Name Editing**: Editing or changing the company name after the receipt has been issued is strictly out of scope to maintain legal, fiscal, and audit immutability.
3. **Retroactive Visitor Account Linking**: Claiming receipts for past visitor purchases by retroactively creating a member account is out of scope. Visitors are warned prior to purchase that member status is required.
4. **Automated Invoicing / VAT Tax Numbers (統一編號發票)**: The system provides formal proof of electronic purchase receipts (收據) with 0% VAT notation. Taiwan Government Uniform Invoice (GUI / 電子發票平台) B2B integration is out of scope.

---

## Further Notes

- **Migration Safety**: Existing `newebpay_orders` rows will have `buyerName = NULL` and `receiptIssuedAt = NULL`. All previously paid member orders will immediately be eligible for the self-serve receipt generation flow.
- **URL Immutability**: Web receipt URLs generated via `generateReceiptSignature` remain backward-compatible and accessible for both existing and newly claimed receipts.
- **English Language Requirement**: As specified, all visitor advisory messages, receipt field labels, and guidance messages must be provided in English.
