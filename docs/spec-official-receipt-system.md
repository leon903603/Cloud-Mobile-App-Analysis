# Specification: CMAA Official Electronic Receipt System & Automated Fulfillment

**Document ID**: `SPEC-CMAA-PAY-001`  
**Author**: CMAA Cloud Platform Engineering Team  
**Status**: APPROVED / IMPLEMENTATION READY  
**Created**: 2026-10-27  
**Updated**: 2026-10-28 (Incorporating Email Sanitizer Fallback, Webhook Idempotency, XSS Escaping & Probe Safety Guards)  
**Target System**: CMAA Cloud Backend (`Cloud-Mobile-App-Analysis/server`), NewebPay Gateway Adapter, Resend Email Delivery Engine  

---

## Problem Statement

Academic researchers, university research laboratories, and enterprise security auditors purchasing **Credits** or single-run **Reports** on the Cloud Mobile App Analysis (CMAA) platform require formal, legally and fiscally compliant proof of purchase ("OFFICIAL RECEIPT") to execute reimbursement and expense accounting claims.

In production deployment, the platform faces five critical operational, fiscal, and security challenges:
1. **Absence of Official Reimbursement Proof**: The standard NewebPay payment notification email serves only as a generic transaction slip without itemized service descriptions, tax-exempt notations, institutional authority seals, or standard reimbursement retention clauses.
2. **Email Client SVG Sanitization Stripping (Gmail & Outlook Limitations)**: While modern web browsers render inline `<svg>` and `<textPath>` elements with crisp mathematical precision, major email clients (particularly Gmail Web and desktop Outlook) actively strip `<svg>` tags from incoming HTML emails for security reasons. Consequently, recipients reading the receipt directly in their email client may see a stripped or empty seal region.
3. **Webhook Retry Storms and Duplicate Email Hazards**: If transient network congestion delays the HTTP 200 response to NewebPay, the gateway will retry the notification webhook (`POST /api/newebpay/notify`). Without strict idempotent gating around email dispatch, users receive duplicate receipt emails for a single transaction.
4. **Template XSS & Injection Vulnerabilities**: Because receipt emails dynamically interpolate external user inputs (particularly unauthenticated **Visitor** emails entered in checkout forms), unescaped string interpolation could permit malicious HTML or script injection that breaks layout rendering or introduces email security risks.
5. **Configuration Drift of Test Payment Probes**: To allow development verification without charging $40.00 USD, a low-denomination test mode (NT$ 1.00) is required. However, if a test probe switch is inadvertently left enabled in production, external users could exploit it to purchase credits at near-zero cost.

---

## Solution

The platform implements an automated, non-blocking, and defensively hardened **Official Electronic Receipt (官方電子購買收據)** system integrated into the NewebPay Webhook fulfillment pipeline (`POST /api/newebpay/notify`) and backed by Cloudflare DNS, Resend REST API, and a dedicated browser-viewable receipt route:

1. **Dual-Channel High-Fidelity Receipt Experience**:
   - **Email Body**: Delivers a clean, styled HTML receipt with full transaction details, fiscal metadata, and an action button: **`View & Print Official Receipt (A4 / PDF)`**.
   - **Dedicated Web Receipt Route (`GET /api/orders/:orderNo/receipt`)**: Hosts the pristine, unstripped receipt directly on the platform domain. When users click through from their email, modern browsers render the full vector SVG seal (`CLOUD MOBILE APP ANALYSIS ★ OFFICIAL SEAL ★` with `isLab VERIFIED & SECURED`) and execute `@media print` rules for flawless A4 printing via `Ctrl+P`.
   - **Security Authorization on Web Route**: Access to the web receipt route requires either authenticated Member ownership or a cryptographic order verification token (`token` query param or Visitor Secret Key match) to prevent unauthorized enumeration of purchase records (IDOR defense).

2. **Strict Webhook Idempotency and Deduplication Gate**:
   - Receipt email dispatch is placed strictly inside the atomic database state transition gate:
     ```
     UPDATE newebpay_orders SET status='paid' WHERE orderNo=? AND status='pending'
     ```
   - Only when `updated.changes === 1` is `sendReceiptEmailSafe` triggered. Subsequent retried webhooks for an already-paid order acknowledge HTTP 200 to the payment gateway immediately without re-triggering email dispatch.

3. **Mandatory HTML Entity Escaping (XSS & Injection Defense)**:
   - All dynamic strings sourced from external input or database storage (including `recipientEmail`, `orderNo`, `packageName`, and `tradeNo`) pass through a deterministic `escapeHtml` sanitizer before template interpolation, neutralizing `<`, `>`, `&`, `"`, and `'`.

4. **Zero-Dependency Resend REST Adapter with Graceful Degradation**:
   - Leverages native Node.js 18+ global `fetch` to communicate directly with `https://api.resend.com/emails`, introducing zero additional npm dependencies.
   - Wrapped in `sendReceiptEmailSafe` to guarantee that email network errors or missing API keys never throw unhandled exceptions or roll back core credit allocation.

5. **1 TWD / 1 USD Payment Probe with Multi-Layer Startup Guards**:
   - Controlled by `TEST_PAYMENT_PROBE=true`. When active, prices the `Starter Package` at `NT$ 1.00 / $1.00 USD`.
   - **Startup Security Alarm**: During server boot, if `TEST_PAYMENT_PROBE === "true"`, the system prints a high-visibility security warning banner in server logs.
   - **Production Isolation**: Higher-tier packages (Pro, Power, Enterprise) and visitor standard flows remain strictly protected at catalog prices even if the probe is enabled.

---

## User Stories

1. As a **Member**, I want to receive an official electronic receipt in my email automatically upon payment completion, so that I have immediate proof of purchase for university or company expense reimbursement.
2. As a **Member**, I want my receipt email to include a "View & Print Official Receipt" button that opens the receipt on the CMAA platform, so that I can view and print the unstripped SVG official seal even if my email client (e.g. Gmail) blocks inline SVG tags.
3. As a **Member**, I want the receipt to display my verified account email in the `Received from` field, so that the expense claim proves I am the authorized purchaser.
4. As a **Member**, I want the receipt to clearly display the package name and credit quantity (e.g., `Starter Package: 1 Analysis Credit` or `Pro Package: 5 Analysis Credits`), so that my institution's finance office can verify the exact purchased service.
5. As a **Member**, I want the receipt to state both the USD catalog price and the actual TWD charged through the credit card gateway, so that foreign currency accounting and credit card statements reconcile cleanly.
6. As a **Member**, I want the receipt to state `Included VAT/GST: 0.0%`, so that accounting departments understand the tax classification of the digital security assessment service.
7. As a **Member**, I want the receipt to include the NewebPay gateway transaction reference (`tradeNo`), so that the payment can be cross-referenced against my monthly credit card statement.
8. As a **Member**, I want the receipt to state `Company: Suprema Technologies LTD` and `Service: Application Security Assessment Chance`, so that the document identifies the official registered corporate merchant and accurately reflects both single-chance and bulk-credit purchases without misleading "One" prefixes.
9. As a **Member**, I want the receipt to include the reimbursement clause `Please retain this receipt for your records and reimbursement purposes.`, so that university auditing boards accept the document.
10. As a **Member**, I want the web receipt page to print cleanly onto standard A4 paper without clipped margins or web buttons when using `Ctrl+P`, so that I can submit physical hard copies to accounting.
11. As a **Visitor**, I want to specify a receipt email address during single-report checkout, so that I receive an official receipt without having a registered platform account.
12. As a **Visitor**, I want my receipt to specify `Guest Single Analysis Report: 1 Analysis Credit`, so that the document accurately reflects my one-off report purchase.
13. As a **Visitor**, I want my report to unlock immediately upon NewebPay payment confirmation regardless of whether the receipt email service is temporarily slow or unreachable, so that my workflow is not blocked.
14. As a **Platform Administrator**, I want official receipts to embed an official SVG verification seal with `CLOUD MOBILE APP ANALYSIS ★ OFFICIAL SEAL ★` and `isLab VERIFIED & SECURED`, so that receipts maintain institutional authority without requiring a manual wet signature.
15. As a **Platform Administrator**, I want receipt email dispatch to be completely non-blocking, so that external email gateway outages never cause NewebPay Webhooks to timeout or fail.
16. As a **Platform Administrator**, I want webhook retries from NewebPay to be handled idempotently, so that customers are never spammed with duplicate receipt emails if the gateway resends a notification.
17. As a **Security Auditor**, I want all user-supplied fields in receipt templates to be strictly HTML-entity-escaped, so that injection payloads in email addresses cannot execute XSS or corrupt receipt formatting.
18. As a **Security Auditor**, I want access to the web receipt route (`/api/orders/:orderNo/receipt`) to be protected against IDOR enumeration, so that unauthorized third parties cannot scrape other users' payment receipts.
19. As a **DevOps Engineer**, I want the server to log a prominent security warning on startup whenever `TEST_PAYMENT_PROBE` is enabled, so that staging probe configurations are never left active in production by accident.
20. As a **Platform Administrator**, I want an optional `TEST_PAYMENT_PROBE=true` switch that charges NT$ 1 for the Starter package, so that we can execute real end-to-end credit card transactions and receipt audits without paying $40 USD per test run.

---

## Implementation Decisions

### 1. Integration Seam & Webhook Idempotency
The receipt system attaches to the highest available operational seam: the **NewebPay Webhook Notification endpoint (`POST /api/newebpay/notify`)**.

To prevent duplicate emails on webhook retries, `sendReceiptEmailSafe` is triggered exclusively when the atomic database row transition succeeds (`updated.changes === 1`):

```
[ NewebPay MPG Gateway ] 
         │ (POST Webhook)
         ▼
[ POST /api/newebpay/notify ] 
         │
         ├── Verify TradeSha & Amount ──► (Mismatch? Return 400)
         │
         ├── Atomic UPDATE: status='paid' WHERE orderNo=? AND status='pending'
         │        │
         │        ├── changes === 0 (Already Paid / Duplicate Webhook)
         │        │        └──► Log & Return HTTP 200 "ok" (No duplicate email!)
         │        │
         │        └── changes === 1 (First Confirmation)
         │                 ├──► CreditBank.grantPurchase() OR GuestJob.update()
         │                 └──► (Async Non-blocking) sendReceiptEmailSafe(orderData)
         │                                                    │
         │                                                    ▼
         │                                         [ Resend REST API ] ──► [ Inbox ]
         │
         └── Return HTTP 200 "ok"
```

### 2. Dual-Channel Receipt Architecture & Web View Route
To circumvent Gmail and desktop Outlook stripping inline `<svg>` and `<textPath>` elements:
- In the email body, a prominent action banner is rendered:  
  `[ View & Print Official Receipt (A4 / PDF) ]` linking to `https://cmaa.solitesterror.com/api/orders/:orderNo/receipt?sig=:hash`.
- When viewed in a browser via this route:
  - Full vector `<svg>` seal renders with 100% fidelity.
  - One-click print button triggers `window.print()`.
  - `@media print` eliminates shadows, headers, and buttons for clean A4 printing.
- Access to the route is protected by a HMAC-SHA256 signature (`sig = sha256(orderNo + paidAt + secret)`), preventing IDOR enumeration by attackers guessing order numbers.

### 3. HTML Sanitization Guard (`escapeHtml`)
All dynamic fields interpolated into HTML templates must pass through an entity escaper:
```typescript
function escapeHtml(str: string): string {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
```

### 4. Probe Safety & Server Startup Guardrail
In server initialization (`index.ts` / `newebpay.ts`), the system audits the probe configuration:
```typescript
if (process.env.TEST_PAYMENT_PROBE === "true") {
  console.warn("====================================================================");
  console.warn(" [SECURITY WARNING] TEST_PAYMENT_PROBE IS ENABLED!");
  console.warn(" Starter Package credit price is overridden to NT$ 1.00 / US$ 1.00.");
  console.warn(" ENSURE THIS FLAG IS DISABLED IN REAL PRODUCTION DEPLOYMENTS.");
  console.warn("====================================================================");
}
```

---

## Testing Decisions

### Test Characteristics
Tests must strictly verify observable external behavior and contracts rather than internal implementation details:
- Template rendering tests assert that required fiscal fields, dates, order IDs, VAT notations, and branding strings are present in the output.
- Security tests assert that malicious HTML payloads injected into `recipientEmail` or `orderNo` are sanitized into entities.
- Deduplication tests assert that calling notify on an already-paid order returns HTTP 200 without re-invoking the email dispatcher.
- Probe isolation tests assert that probe pricing applies exclusively to the Starter package while leaving higher tiers intact.

### Target Test Suite (`server/tests/receipt_mailer.test.ts`)
- **Test 1: Official Seal SVG Compliance**: Verifies SVG element validity, brand text, and security verification taglines.
- **Test 2: Standard Member Receipt HTML**: Validates all fiscal headers, `Received from`, `Application Security Assessment Chance`, fees, and disclaimers.
- **Test 3: XSS & HTML Entity Escaping**: Injects `"><script>alert(1)</script>` into `recipientEmail` and asserts it is safely escaped to `&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;`.
- **Test 4: Test Probe Fee Rendering**: Validates formatted `$1.00 USD (NT$ 1.00)` output when `TEST_PAYMENT_PROBE=true`.
- **Test 5: Visitor Report Receipt**: Validates single analysis report labeling.
- **Test 6: Graceful Degradation**: Validates mock mode execution when `RESEND_API_KEY` is omitted, and graceful input rejection for invalid emails.
- **Regression Suite**: Tested alongside all 17 pre-existing platform test suites via `npm run test:unit`.

---

## Out of Scope

1. **Government Electronic Invoices (台灣統一發票 / GUI)**:
   This specification governs the academic and international **OFFICIAL RECEIPT (官方電子購買收據)**. Integration with Ministry of Finance B2C E-Invoice Turnkey systems or third-party invoice carriers (e.g., ezPay, Ecpay) is out of scope.
2. **Analysis Engine Internals**:
   Static decompilation rules (`android-static`), dynamic Frida hooks (`android-detection-system`), and statutory security audit report styling (`pdf-generator`) are frozen baselines and remain untouched.
3. **Frontend Payment UI Overhaul**:
   The existing `BuyCredits` and `GuestCheckout` frontend form contracts remain unchanged; recipient emails are derived automatically from authenticated sessions or existing receipt email inputs.

---

## Further Notes

- **Worktree Isolation**: All developments and tests are conducted in an isolated Git worktree (`feat/receipt-system`) under `ops/worktree_spawn.ps1` to prevent SQLite WAL locks (`SQLITE_BUSY`) and port collisions.
- **Presentation Previews**: Sample HTML receipt files have been generated at `C:\Users\leon9\Desktop\sample_official_receipt.html` and `sample_official_receipt_probe.html` for faculty review.
