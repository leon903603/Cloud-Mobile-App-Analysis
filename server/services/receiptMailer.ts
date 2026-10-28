// server/services/receiptMailer.ts — Official Electronic Receipt generator & Resend mailer
// Generates official academic & enterprise reimbursement receipts for Suprema Technologies LTD.

export interface ReceiptEmailPayload {
  orderNo: string;
  recipientEmail: string;
  credits: number;
  amt: number; // TWD charged
  usdAmt?: number; // USD list price
  orderType: "credits" | "guest_report" | string;
  tradeNo?: string;
  paidAt?: string;
  packageName?: string;
  webReceiptUrl?: string; // Optional direct web receipt link for email clients that strip inline SVG
  isWeb?: boolean; // True when rendered on the web receipt endpoint, false for email
  buyerName?: string; // User-specified company or institution name for reimbursement
  receiptIssuedAt?: string; // ISO timestamp when official receipt was issued
}

/**
 * Escapes unsafe characters for HTML entity interpolation (XSS defense).
 */
export function escapeHtml(str: unknown): string {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/**
 * High-resolution official circular electronic verification seal (SVG format).
 * Features outer ring text, center emblem, and 'VERIFIED & SECURED' badge.
 */
export function generateOfficialSealSvg(): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 170 170" width="145" height="145" style="display: block;">
  <defs>
    <!-- Top arc path for 'CLOUD MOBILE APP ANALYSIS' -->
    <path id="sealTopArc" d="M 22,85 A 63,63 0 1,1 148,85" fill="none" />
    <!-- Bottom arc path for '★ OFFICIAL SEAL ★' -->
    <path id="sealBottomArc" d="M 148,85 A 63,63 0 0,1 22,85" fill="none" />
  </defs>

  <!-- Outer double concentric ring -->
  <circle cx="85" cy="85" r="80" fill="none" stroke="#0f2b48" stroke-width="2.5" />
  <circle cx="85" cy="85" r="75" fill="none" stroke="#0f2b48" stroke-width="1" stroke-dasharray="3.5 2" />

  <!-- Outer circular text -->
  <text font-family="Georgia, 'Times New Roman', serif" font-size="8.6" font-weight="bold" fill="#0f2b48" letter-spacing="1.4px">
    <textPath href="#sealTopArc" startOffset="50%" text-anchor="middle">SUPREMA TECHNOLOGIES LTD</textPath>
  </text>
  <text font-family="Georgia, 'Times New Roman', serif" font-size="9.5" font-weight="bold" fill="#0f2b48" letter-spacing="2px">
    <textPath href="#sealBottomArc" startOffset="50%" text-anchor="middle">&#9733; OFFICIAL SEAL &#9733;</textPath>
  </text>

  <!-- Inner boundary circle -->
  <circle cx="85" cy="85" r="52" fill="none" stroke="#0f2b48" stroke-width="1.8" />
  <circle cx="85" cy="85" r="49" fill="none" stroke="#0f2b48" stroke-width="0.75" />

  <!-- Central Crest & Emblems -->
  <!-- Top star -->
  <polygon points="85,42 87.5,48.5 94,49 89,53.5 90.5,60 85,56.5 79.5,60 81,53.5 76,49 82.5,48.5" fill="#0f2b48" />

  <!-- Suprema Core Brand -->
  <text x="85" y="79" text-anchor="middle" font-family="Georgia, 'Times New Roman', serif" font-size="14.5" font-weight="bold" fill="#0f2b48" letter-spacing="1.5px">SUPREMA</text>

  <!-- Decorative Separator Line with diamond -->
  <line x1="56" y1="87" x2="114" y2="87" stroke="#0f2b48" stroke-width="1.2" />
  <polygon points="85,85 87,87 85,89 83,87" fill="#0f2b48" />

  <!-- Verified Subtitle -->
  <text x="85" y="100" text-anchor="middle" font-family="'Helvetica Neue', Helvetica, Arial, sans-serif" font-size="6.8" font-weight="bold" fill="#0f2b48" letter-spacing="1.2px">VERIFIED &amp; SECURED</text>

  <!-- Bottom decorative 3 dots -->
  <circle cx="77" cy="111" r="1.5" fill="#0f2b48" />
  <circle cx="85" cy="111" r="2.2" fill="#0f2b48" />
  <circle cx="93" cy="111" r="1.5" fill="#0f2b48" />
</svg>`;
}



/**
 * Resolves item description based on order type, credits, and package.
 */
function resolveItemDescription(payload: ReceiptEmailPayload): string {
  if (payload.orderType === "guest_report") {
    return `Single Security Analysis Report (Order: ${payload.orderNo})`;
  }
  const credits = payload.credits;
  let pkgName = payload.packageName;
  if (!pkgName) {
    if (credits === 1) pkgName = "Starter Package";
    else if (credits === 5) pkgName = "Pro Package";
    else if (credits === 10) pkgName = "Power Package";
    else if (credits === 25) pkgName = "Enterprise Package";
    else pkgName = "Custom Package";
  }
  const countLabel = credits === 1 ? "1 Security Analysis" : `${credits} Security Analyses`;
  return `${pkgName}: ${countLabel} (Order: ${payload.orderNo})`;
}

/**
 * Format currency display string (e.g. '$40.00 USD (NT$ 1,280)' or '$1.00 USD (NT$ 1.00)').
 */
function formatFeeDisplay(usd: number, twd: number): string {
  const isProbe = twd === 1 && usd === 1;
  if (isProbe) {
    return `$1.00 USD (NT$ 1.00)`;
  }
  return `$${usd.toFixed(2)} USD (NT$ ${twd.toLocaleString()})`;
}

/**
 * Formats ISO date to official full date format: "October 27, 2026"
 */
function formatOfficialDate(dateIso?: string): string {
  const date = dateIso ? new Date(dateIso) : new Date();
  const safeDate = isNaN(date.getTime()) ? new Date() : date;
  return safeDate.toLocaleDateString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
    timeZone: "Asia/Taipei",
  });
}

/**
 * Generates the complete HTML for the Official Receipt email.
 * Includes @media print styles for seamless A4 PDF printing.
 */
export function generateReceiptHtml(payload: ReceiptEmailPayload): string {
  const sealSvg = payload.isWeb ? generateOfficialSealSvg() : "";
  const rawItemDesc = resolveItemDescription(payload);
  const dateToFormat = payload.receiptIssuedAt || payload.paidAt;
  const formattedDate = formatOfficialDate(dateToFormat);
  const usdAmt = payload.usdAmt ?? (payload.amt === 1 ? 1 : Math.round(payload.amt / 32));
  const feeDisplay = formatFeeDisplay(usdAmt, payload.amt);

  // XSS Defense: sanitize dynamic user-controllable inputs
  const safeRecipientEmail = escapeHtml(payload.recipientEmail);
  const safeBuyerName = payload.buyerName ? escapeHtml(payload.buyerName.trim()) : "";
  let receivedFromDisplay = "Valued Customer";
  if (safeBuyerName) {
    receivedFromDisplay = safeRecipientEmail
      ? `${safeBuyerName} (${safeRecipientEmail})`
      : safeBuyerName;
  } else if (safeRecipientEmail) {
    receivedFromDisplay = safeRecipientEmail;
  }

  const safeOrderNo = escapeHtml(payload.orderNo);
  const safeItemDesc = escapeHtml(rawItemDesc);
  const safeTradeNo = escapeHtml(payload.tradeNo);
  const safeDate = escapeHtml(formattedDate);
  const safeFeeDisplay = escapeHtml(feeDisplay);
  const safeWebReceiptUrl = payload.webReceiptUrl ? escapeHtml(payload.webReceiptUrl) : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OFFICIAL RECEIPT - ${safeOrderNo}</title>
  <style>
    /* Reset and Typography */
    body {
      margin: 0;
      padding: 24px;
      background-color: #f3f4f6;
      font-family: Georgia, 'Times New Roman', Times, serif;
      color: #1a1a1a;
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
    }

    .receipt-wrapper {
      max-width: 760px;
      margin: 0 auto;
      background: #ffffff;
      padding: 48px 56px;
      border: 1px solid #d1d5db;
      box-shadow: 0 4px 14px rgba(0, 0, 0, 0.06);
      box-sizing: border-box;
    }

    /* Print & Web Action Bar (Hidden on print) */
    .print-actions {
      max-width: 760px;
      margin: 0 auto 16px auto;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .web-view-notice {
      font-size: 13px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      color: #4b5563;
    }
    .web-view-notice a {
      color: #0f2b48;
      font-weight: 600;
      text-decoration: underline;
    }
    .print-btn {
      background-color: #0f2b48;
      color: #ffffff;
      border: none;
      padding: 10px 22px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 14px;
      font-weight: 600;
      border-radius: 6px;
      cursor: pointer;
      box-shadow: 0 2px 4px rgba(0,0,0,0.15);
      transition: background-color 0.15s ease;
    }
    .print-btn:hover {
      background-color: #1a426e;
    }

    /* Header */
    .receipt-title {
      text-align: center;
      font-size: 26px;
      font-weight: bold;
      letter-spacing: 3px;
      text-transform: uppercase;
      padding-bottom: 14px;
      border-bottom: 2px solid #111827;
      margin: 0 0 28px 0;
      color: #111827;
    }

    /* Meta Info Grid */
    .meta-table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 24px;
    }
    .meta-table td {
      vertical-align: top;
      padding: 4px 0;
    }
    .meta-label {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: #4b5563;
      margin-bottom: 2px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    .meta-value {
      font-size: 15px;
      font-weight: bold;
      color: #111827;
      word-break: break-all;
    }

    /* Service Scope Banner */
    .service-banner {
      background-color: #f8fafc;
      border-left: 4px solid #0f2b48;
      padding: 12px 18px;
      margin: 20px 0 28px 0;
      font-size: 14px;
      line-height: 1.6;
    }
    .service-banner span {
      font-weight: bold;
      color: #0f2b48;
    }

    /* Itemized Table */
    .items-table {
      width: 100%;
      border-collapse: collapse;
      margin: 20px 0 24px 0;
    }
    .items-table th {
      border-top: 1.5px solid #111827;
      border-bottom: 1.5px solid #111827;
      padding: 10px 8px;
      font-size: 12px;
      font-weight: bold;
      text-transform: uppercase;
      letter-spacing: 0.6px;
      text-align: left;
      background-color: #fafafa;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    .items-table td {
      padding: 14px 8px;
      font-size: 13.5px;
      border-bottom: 1px solid #e5e7eb;
      vertical-align: middle;
    }
    .col-item { width: 32%; font-weight: bold; }
    .col-desc { width: 38%; color: #374151; font-size: 13px; }
    .col-fee { width: 18%; text-align: right; }
    .col-vat { width: 12%; text-align: right; color: #4b5563; }

    .total-row td {
      border-top: 2px solid #111827;
      border-bottom: 2px solid #111827;
      font-weight: bold;
      padding: 14px 8px;
      font-size: 15px;
    }

    /* Payment Method */
    .payment-method {
      font-size: 13.5px;
      color: #374151;
      margin-bottom: 24px;
      line-height: 1.6;
    }
    .payment-method strong {
      color: #111827;
    }

    /* Notes Box */
    .notes-box {
      background-color: #fafafa;
      border: 1px solid #e5e7eb;
      border-radius: 4px;
      padding: 14px 18px;
      margin-bottom: 28px;
      font-size: 12px;
      color: #374151;
      line-height: 1.6;
    }
    .notes-title {
      font-weight: bold;
      font-size: 12.5px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 6px;
      color: #111827;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    .notes-list {
      margin: 0;
      padding-left: 16px;
    }
    .notes-list li {
      margin-bottom: 4px;
    }

    /* Contact & Official Seal Footer */
    .footer-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 20px;
    }
    .footer-table td {
      vertical-align: middle;
      padding: 0;
    }
    .contact-title {
      font-weight: bold;
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.6px;
      margin-bottom: 4px;
      color: #111827;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    .contact-info {
      font-size: 13px;
      color: #374151;
      line-height: 1.6;
    }
    .contact-info a {
      color: #0f2b48;
      text-decoration: none;
    }
    .seal-col {
      width: 160px;
      text-align: right;
    }
    .copy-email-btn {
      display: inline-block;
      margin-left: 6px;
      padding: 1px 7px;
      font-size: 11px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f1f5f9;
      color: #334155;
      border: 1px solid #cbd5e1;
      border-radius: 4px;
      cursor: pointer;
      vertical-align: middle;
      transition: all 0.15s ease;
    }
    .copy-email-btn:hover {
      background: #e2e8f0;
      color: #0f2b48;
    }

    /* A4 Print Layout */
    @media print {
      body {
        margin: 0 !important;
        padding: 0 !important;
        background: #ffffff !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }
      .no-print {
        display: none !important;
      }
      .receipt-wrapper {
        border: none !important;
        box-shadow: none !important;
        padding: 0 !important;
        max-width: 100% !important;
        width: 100% !important;
      }
      @page {
        size: A4 portrait;
        margin: 18mm 20mm;
      }
    }
  </style>
</head>
<body>
  <!-- Print Action Bar (Browser only) -->
  ${
    payload.isWeb
      ? `<div class="print-actions no-print">
          <div class="web-view-notice">Official Electronic Receipt</div>
          <button class="print-btn" onclick="window.print()">🖨 Print Official Receipt (PDF / A4)</button>
        </div>`
      : ""
  }

  <div class="receipt-wrapper">
    <!-- Header -->
    <div class="receipt-title">OFFICIAL RECEIPT</div>

    <!-- Metadata Table -->
    <table class="meta-table">
      <tr>
        <td style="width: 58%;">
          <div class="meta-label">Received from:</div>
          <div class="meta-value">${receivedFromDisplay}</div>
        </td>
        <td style="width: 42%; text-align: right;">
          <div class="meta-label">Receipt No.:</div>
          <div class="meta-value" style="font-family: monospace; font-size: 14.5px;">${safeOrderNo}</div>
          <div style="margin-top: 6px;">
            <span class="meta-label" style="display: inline;">Date: </span>
            <span class="meta-value" style="font-weight: normal; font-size: 13.5px;">${safeDate}</span>
          </div>
        </td>
      </tr>
    </table>

    <!-- Service Scope -->
    <div class="service-banner">
      <div>Company: <span>Suprema Technologies LTD</span></div>
      <div>Service: <span>Application Security Analysis Services</span></div>
    </div>

    <!-- Itemized Breakdown Table -->
    <table class="items-table">
      <thead>
        <tr>
          <th class="col-item">Item</th>
          <th class="col-desc">Description</th>
          <th class="col-fee">Fee (incl. VAT/GST)</th>
          <th class="col-vat">Included VAT/GST</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td class="col-item">App Security Analysis Plan</td>
          <td class="col-desc">${safeItemDesc}</td>
          <td class="col-fee">${safeFeeDisplay}</td>
          <td class="col-vat">0.0%</td>
        </tr>
        <tr class="total-row">
          <td colspan="2" style="text-align: right;">Total Amount</td>
          <td class="col-fee">${safeFeeDisplay}</td>
          <td class="col-vat"></td>
        </tr>
      </tbody>
    </table>

    <!-- Payment Method -->
    <div class="payment-method">
      <div><strong>Payment Method:</strong> Credit Card (NewebPay Payment Gateway)</div>
      ${safeTradeNo ? `<div><strong>Gateway Transaction No.:</strong> <span style="font-family: monospace;">${safeTradeNo}</span></div>` : ""}
    </div>

    <!-- Notes & Reimbursement Terms -->
    <div class="notes-box">
      <div class="notes-title">Notes</div>
      <ul class="notes-list">
        <li>This receipt confirms payment for Application Security Analysis services on the Cloud Mobile App Analysis (CMAA) platform.</li>
        <li>Service quotas and entitlements are non-transferable. Refunds and service usage are subject to the platform service terms.</li>
        <li><strong>Please retain this receipt for your records and reimbursement purposes.</strong></li>
      </ul>
    </div>

    <!-- Contact & Official Seal / Web Receipt Link -->
    ${
      payload.isWeb
        ? `<table class="footer-table">
            <tr>
              <td style="vertical-align: top;">
                <div class="contact-title">Contact</div>
                <div class="contact-info">
                  <strong>Suprema Technologies LTD</strong><br>
                  Email: <span>suprematechnologiesltd@solitesterror.com</span>
                  <button type="button" class="copy-email-btn no-print" onclick="copyReceiptEmail(this)" title="Copy email address">Copy</button><br>
                  Website: <a href="https://cmaa.solitesterror.com" target="_blank">https://cmaa.solitesterror.com</a>
                </div>
              </td>
              <td class="seal-col">
                ${sealSvg}
              </td>
            </tr>
          </table>`
        : `<div style="margin-top: 28px; padding-top: 18px; border-top: 1px solid #e5e7eb;">
            <div class="contact-title" style="margin-bottom: 4px; font-weight: bold;">Contact</div>
            <div class="contact-info" style="font-size: 13px; color: #4b5563; line-height: 1.5;">
              <strong>Suprema Technologies LTD</strong><br>
              Email: <span>suprematechnologiesltd@solitesterror.com</span><br>
              Website: <a href="https://cmaa.solitesterror.com" target="_blank" style="color: #0f2b48;">https://cmaa.solitesterror.com</a>
            </div>
            ${
              safeWebReceiptUrl
                ? `<div style="margin-top: 20px; padding: 14px 18px; background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; text-align: center;">
                    <div style="font-size: 13px; color: #334155; margin-bottom: 8px;">Need an official stamped receipt for university or enterprise accounting?</div>
                    <a href="${safeWebReceiptUrl}" target="_blank" style="display: inline-block; background-color: #0f2b48; color: #ffffff; padding: 9px 20px; border-radius: 5px; font-weight: 600; font-size: 13.5px; text-decoration: none;">View &amp; Print Official Receipt (A4 / PDF) ↗</a>
                  </div>`
                : ""
            }
          </div>`
    }
  </div>

  ${
    payload.isWeb
      ? `<script>
    function copyReceiptEmail(btn) {
      var email = "suprematechnologiesltd@solitesterror.com";
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(email).then(function() {
          var orig = btn.innerText;
          btn.innerText = "Copied!";
          btn.style.borderColor = "#10b981";
          btn.style.color = "#059669";
          setTimeout(function() {
            btn.innerText = orig;
            btn.style.borderColor = "";
            btn.style.color = "";
          }, 2000);
        }).catch(function() {
          window.prompt("Contact email:", email);
        });
      } else {
        window.prompt("Contact email:", email);
      }
    }
  </script>`
      : ""
  }
</body>
</html>`;
}

/**
 * Sends receipt email safely via Resend REST API without throwing errors or blocking callers.
 * Provides graceful degradation when RESEND_API_KEY is not configured.
 */
export async function sendReceiptEmailSafe(payload: ReceiptEmailPayload): Promise<{
  success: boolean;
  skipped?: boolean;
  reason?: string;
  id?: string;
  error?: string;
}> {
  const apiKey = process.env.RESEND_API_KEY;
  const emailFrom =
    process.env.EMAIL_FROM ||
    "SupremaTechnologiesLTD <suprematechnologiesltd@mail.solitesterror.com>";

  if (!payload.recipientEmail || !payload.recipientEmail.includes("@")) {
    console.warn(
      `[receiptMailer] Skipped: Invalid or missing recipient email for order ${payload.orderNo}`
    );
    return {
      success: false,
      skipped: true,
      reason: "missing_or_invalid_recipient",
    };
  }

  // Graceful degradation when Resend API Key is not configured (e.g. local dev / testing)
  if (!apiKey) {
    console.log(
      `[receiptMailer] [Mock Log] RESEND_API_KEY not configured. Mock sending receipt for order ${payload.orderNo} to ${payload.recipientEmail}`
    );
    return {
      success: true,
      skipped: true,
      reason: "mock_mode_no_api_key",
    };
  }

  try {
    const html = generateReceiptHtml(payload);
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: emailFrom,
        to: [payload.recipientEmail.trim()],
        subject: `Official Receipt:  Suprema Technologies LTD[${payload.orderNo}]`,
        html,
      }),
      signal: AbortSignal.timeout(8000),
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => "");
      console.error(
        `[receiptMailer] Resend API error (${response.status}): ${errText}`
      );
      return {
        success: false,
        error: `Resend HTTP ${response.status}: ${errText}`,
      };
    }

    const data = (await response.json().catch(() => ({}))) as { id?: string };
    console.log(
      `[receiptMailer] Receipt successfully sent to ${payload.recipientEmail} (Resend ID: ${
        data.id ?? "unknown"
      })`
    );
    return { success: true, id: data.id };
  } catch (err: any) {
    console.error(
      `[receiptMailer] Network/system exception sending receipt for order ${payload.orderNo}:`,
      err
    );
    return { success: false, error: err?.message || String(err) };
  }
}
