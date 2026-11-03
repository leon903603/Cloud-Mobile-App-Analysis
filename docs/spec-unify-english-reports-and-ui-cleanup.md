# Specification: Unify Single English Report and Global UI Localization Cleanup

## Problem Statement

Currently, the Cloud Mobile App Analysis (CMAA) platform provides dual bilingual report download buttons (Traditional Chinese and English) across member and guest interfaces. In addition:
1. Analysis pipelines trigger dual PDF generation (rendering Traditional Chinese first, followed by English), causing redundant AWS Lambda execution costs, doubled CPU/memory load, and extra S3 storage.
2. Several frontend components (UploadHistory, GuestUploader, BuyCredits, Product, CreditHistoryModal, PackedApkNotice) contain hardcoded Traditional Chinese text in alert dialogs, labels, disclaimer banners, and button copies.
3. Multiple frontend timestamps (`CreditHistoryModal.tsx`, `GuestUploader.tsx`, `UploadHistory.tsx`) rely on browser-locale defaults (`undefined`), which produces Chinese prefixes/suffixes ("上午 / 下午") on Chinese-configured browsers.
4. For iOS Dynamic Analysis, the Mac execution environment currently only generates Traditional Chinese reports (`pdfs["zh-TW"]`), pending future English support by the iOS specialist. A naive removal of Chinese PDF support would cause iOS dynamic analysis downloads to fail with 404 errors.
5. In `ArtifactVault.storeCompletedReport`, English PDF rendering failure was previously non-fatal (`console.warn`), whereas Chinese PDF rendering was strict and triggered analysis failure refunds.

The platform needs a streamlined, production-safe, and cost-efficient configuration that standardizes on a single English security report, purges residual Chinese UI text, and provides graceful fallback for iOS and legacy reports, adhering strictly to the Principle of Minimum Change (最低改動原則) and zero regression.

---

## Solution

1. **Frontend Button & Text Consolidation**:
   - Replace dual download buttons in `UploadHistory` and `GuestUploader` with single, unambiguous English buttons: `Download Static Report (PDF)`, `Download Dynamic Report (PDF)`, and `Download PDF Report`.
   - Update `handleReportGeneration` and `handleDownload` to default to `lang: "en"`.
   - Standardize all date/time renderings across `CreditHistoryModal.tsx`, `GuestUploader.tsx`, and `UploadHistory.tsx` to explicit `"en-US"` formatting.
   - Translate all residual Chinese alert popups, error strings, and disclaimer texts to clear, professional English.
   - Remove redundant Chinese stored-value disclaimers from public commercial pages (`Product.tsx`).

2. **Smart Graceful Fallback for iOS Dynamic & Historical Reports**:
   - In `ArtifactVault.acquireReportDownloadUrl`, implement an automatic fallback: when `targetLang === "en"` is requested but `paths.pdfKeyEn` does not exist (such as current iOS dynamic tasks or older legacy reports), gracefully fall back to `paths.pdfKeyZh` or `paths.legacyPdfKey` instead of throwing 404.
   - In `ArtifactVault.storeCompletedReport`, preserve pregenerated Mac PDFs (writing to `paths.pdfKeyEn` and `paths.pdfKeyZh` when available) so current iOS analysis outputs remain 100% downloadable.

3. **Backend Pipeline Optimization & Strict Error Handling**:
   - For Android static and dynamic analysis, stop generating the redundant Chinese PDF on Lambda, generating only the English PDF (`_en.pdf`).
   - Transfer strict error throwing to English PDF rendering: if Lambda rendering fails in production (`!opts?.allowDummyPdfFallback`), throw an error so the task is marked as errored and credits are refunded.
   - Switch default report language resolution from `"zh-TW"` to `"en"` across `server/index.ts` and `server/guest_routes.ts`.

4. **PDF Generator Lambda Default Standardization**:
   - Update `static_lambda/handler.py` default language fallback to `'en'`.
   - Retain dual-font configurations (SourceHanSansTC) in Lambda environments to prevent ReportLab font crashes when analyzed app packages contain Unicode/CJK characters.

5. **Automated Test Parity**:
   - Update E2E browser and unit test assertions (`server/tests/browser_ec2_e2e.test.ts` and `server/tests/artifactVault.test.ts`) to target the consolidated English buttons and verify default English report generation with iOS fallback.

---

## User Stories

1. As a security analyst, I want a single, clear "Download Static Report (PDF)" button in my upload history, so that I can download my analysis report in one click without language ambiguity.
2. As a security analyst, I want a single, clear "Download Dynamic Report (PDF)" button in my upload history, so that I can retrieve dynamic assessment results immediately.
3. As an international visitor, I want a unified "Download PDF Report" button after unlocking my guest analysis, so that I can easily obtain the assessment report.
4. As an iOS app tester, I want to click the single "Download Dynamic Report (PDF)" button and successfully receive my iOS report (even if currently rendered in Chinese by the Mac runner), so that my analysis workflow is never broken with 404 errors.
5. As a guest user, I want system notifications, expiry alerts, and card timestamps to display in English, so that I can understand file lifecycle messages without language barriers.
6. As a registered member, I want error popups and login prompts in upload history to display in English, so that my workflow remains consistent with the rest of the application.
7. As a member reviewing my Credit Journal, I want all timestamps to display in a standardized English date format (without Chinese prefixes like "上午" or "下午"), so that financial audit logs are internationally readable.
8. As a finance officer claiming an official reimbursement receipt, I want the form label to read "Company / Institution Name", so that the interface matches standard international invoice forms.
9. As a corporate customer, I want to enter my legally registered company name (in any language) into the receipt claim form, so that tax reimbursement records remain accurate.
10. As a customer who experienced a PDF generation error, I want the system to fail strictly and refund my credits automatically, so that my balance is never lost on failed renders.
11. As a prospective customer visiting the Product page, I want clean, English-only payment and legal notices, so that terms of service and pricing explanations are coherent.
12. As a purchasing customer on BuyCredits, I want payment gateway references displayed cleanly as "NewebPay", so that checkout explanations are concise.
13. As a security auditor, I want packer warnings on PackedApkNotice to reference "360 Qihoo / Jiagu", so that detection explanations follow standard industry naming conventions.
14. As a cloud platform operator, I want Android analysis pipelines to render only one PDF per task, so that AWS Lambda invocation counts and S3 storage costs are reduced by 50%.
15. As an API client consuming `/generate-report` without specifying a language, I want the endpoint to default to English, so that I receive standard English reports.
16. As a developer running regression tests, I want E2E tests to pass cleanly against the updated English buttons and fallback paths, so that CI/CD deployments remain green.

---

## Implementation Decisions

### 1. Module Boundaries and Minimum Change Discipline
- **No Engine Architecture Changes**: Do not modify static analysis rules, dynamic exploration scripts, or PDF typesetting algorithms.
- **Seam Selection**: Apply changes strictly at the presentation, API coordination, and artifact storage layers.

### 2. Frontend Components (`frontend/src/`)
- **UploadHistory Component**:
  - Replace dual buttons (Chinese/English) for both static and dynamic analysis with single buttons:
    - Static: `Download Static Report (PDF)`
    - Dynamic: `Download Dynamic Report (PDF)`
  - Modify `handleReportGeneration` default parameter signature to `lang: "zh-TW" | "en" = "en"`.
  - Replace Chinese error strings in `throw new Error(...)` and `alert(...)` with standard English phrasing.
  - Fix timestamp display (Line 482): pass `"en-US"` to `toLocaleDateString("en-US")`.
- **GuestUploader Component**:
  - Replace dual download buttons with single `Download PDF Report` button calling `handleDownload("en")`.
  - Update notice copy to remove the word "bilingual" (e.g., "...download the full security assessment PDF report").
  - Translate file expiry alerts from Chinese to English.
  - Fix timestamp display (Line 1338): update `{new Date(activeJob.uploadTime).toLocaleString("en-US")}`.
- **CreditHistoryModal Component**:
  - Update `formatTimestamp` helper from `d.toLocaleString(undefined, ...)` to `d.toLocaleString("en-US", { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false })`.
  - Clean field label to `Company / Institution Name:` (removing `(公司抬頭 / 組織名稱)`).
- **PackedApkNotice & Marketing Pages**:
  - Update `PackedApkNotice.tsx`: replace `(360 加固, Bangcle, ...)` with `(360 Qihoo / Jiagu, Bangcle, ...)`.
  - Update `Product.tsx` & `BuyCredits.tsx`: change `NewebPay (藍新金流)` to `NewebPay`.
  - Remove Chinese-only stored-value warning block in `Product.tsx` (redundant with existing English legal terms).

### 3. Backend Services & Dispatch (`server/`)
- **ArtifactVault (`server/services/artifactVault.ts`)**:
  - In `storeCompletedReport`:
    - Eliminate redundant Chinese PDF Lambda generation (saving 1 Lambda invocation and extra S3 writes per task). If a pre-generated PDF buffer is supplied by the runner, store it cleanly; otherwise render only the English PDF (`_en.pdf`) via Lambda.
    - In English PDF rendering: apply strict error handling (if `!enRes.ok` and `!opts?.allowDummyPdfFallback`, `throw new Error(...)` so failed tasks properly trigger automatic credit refunds).
  - In `acquireReportDownloadUrl`:
    - Default `targetLang` to `"en"`.
    - **Universal One-Line Fallback**: Prioritize `paths.pdfKeyEn`; if not found on S3 (and not rendered on-demand), universally fall back to any existing `paths.pdfKeyZh` or `paths.legacyPdfKey` (`effectiveKey = (await objectExists(paths.pdfKeyZh)) ? paths.pdfKeyZh : (await objectExists(paths.legacyPdfKey)) ? paths.legacyPdfKey : ""`). No iOS-specific custom branching is needed.
- **Member & Guest HTTP Routes (`server/index.ts`, `server/guest_routes.ts`)**:
  - In `POST /generate-report`: default `targetLang` and `lang` parameter to `"en"`.
  - In `GET /guest/report/:token`: default `reqLang` query parameter to `"en"`.
- **Job Dispatcher (`server/dispatch.ts`)**:
  - In `analyzeAndroidDynamic` and `runGuestDynamicJob`: pass the English PDF already generated by the dynamic EC2 sandbox (`result.pdfBase64`) directly into `ArtifactVault.storeCompletedReport` as `pregeneratedEnPdfBase64: result.pdfBase64`. This saves the English PDF directly to S3 on the fast path and avoids invoking the PDF Lambda altogether for Android dynamic analysis.

### 4. PDF Generator Lambda (`pdf-generator/`)
- **Static PDF Lambda (`static_lambda/handler.py`)**:
  - Change default language fallback from `'zh-TW'` to `'en'`.
- **CJK Font Preservation**:
  - Retain `SourceHanSansTC-Regular.ttf` and `SourceHanSansTC-Bold.ttf` in both static and dynamic Lambda packages to ensure safe rendering when application metadata, package names, or strings contain Unicode/Chinese characters.

---

## Testing Decisions

### What Makes a Good Test
- Tests must assert **external system behavior** through public contracts and HTTP/browser interfaces rather than inspecting internal variable state.
- Assert that API responses and UI elements provide the correct English content, status codes, and media types.

### Testing Seams & Scope
- **Seam 1: Member Report Generation Endpoint (`POST /generate-report`)**:
  - Test invocation with `{ hash, type }` (no `lang` provided).
  - Verify that the presigned download URL points to an English PDF (`_en.pdf`).
  - Verify that requesting a report with only a legacy/Chinese PDF gracefully falls back to that PDF without returning 404.
- **Seam 2: Guest Report Download Endpoint (`GET /guest/report/:token`)**:
  - Test request without `?lang=` query parameter.
  - Verify response resolves to English PDF by default.
- **Seam 3: Storage Vault Pipeline (`ArtifactVault.storeCompletedReport`)**:
  - Verify that calling `storeCompletedReport` for Android executes only one Lambda rendering job (for English).
  - Verify strict error throwing when Lambda rendering fails in production.
  - Verify iOS dynamic analysis stores the available Mac PDF cleanly.
- **Seam 4: Browser E2E Interaction (`server/tests/browser_ec2_e2e.test.ts`)**:
  - Update selector from `button:has-text('下載中文報告')` to `button:has-text('Download PDF Report')`.
  - Verify click initiates binary download with 200/302 response.
- **Seam 5: Client Date Formatting Unit Check**:
  - Verify that timestamp helpers produce pure English alphanumeric timestamps (`en-US`) without Chinese "上午 / 下午".

---

## Out of Scope

1. **iOS Dynamic Analysis English Rendering Implementation**:
   - The Mac runner's internals (`AutoDetect`) and English layout generation for iOS dynamic reports belong to the iOS specialist team member and will be implemented in a future phase.
2. **PDF Generator Internal Layout Redesign**:
   - Restyling or altering table layouts, margins, or ReportLab canvas in `pdf-generator/static_lambda/report.py` and `dynamic_lambda/report.py`.
3. **Database Schema Breaking Migrations**:
   - Dropping or modifying columns in `file_meta`, `newebpay_orders`, or `credit_ledger`.
4. **Purging Historical S3 Objects**:
   - Existing Chinese PDF objects already generated in S3 buckets will remain intact and accessible to prevent customer link breakage.

---

## Further Notes

- **Zero-Risk Transition for iOS**: Because the backend implements smart fallback, the frontend can be completely unified into a single "Download Report (PDF)" button today. The user will always get a report (English for Android/Static, and the current Chinese report for iOS Dynamic until the teammate adds iOS English support). When the teammate adds English support later, it will seamlessly take precedence without needing any further frontend or API changes.
- **Cost and Efficiency Benefit**: By eliminating the pre-generation of Chinese PDFs on Android tasks, each analysis saves 1 full AWS Lambda execution (typically 3–8 seconds of compute time), reduces CPU/memory peaks on workers, and halves S3 PDF storage volume per analysis.
