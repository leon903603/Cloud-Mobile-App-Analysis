// server/tests/artifactVault.test.ts
import assert from "assert";
import { ArtifactVault, ArtifactScope, decodePregeneratedPdf, isIosDynamicScope } from "../services/artifactVault";

console.log("==================================================");
console.log(" Running ArtifactVault Deep Module Unit Tests");
console.log("==================================================");

async function runTests() {
  // Test 1: Unified Dual-Language Path Resolution & Legacy Compatibility
  const memberScope: ArtifactScope = {
    role: "member",
    uid: "test-user-1",
    hash: "abcde12345",
    analysisType: "static",
    filename: "sample-app.apk",
  };

  const memberPaths = ArtifactVault.resolveBasePaths(memberScope);
  assert.strictEqual(memberPaths.uploadKey, "uploads/test-user-1/abcde12345/sample-app.apk");
  assert.strictEqual(memberPaths.reportJsonKey, "reports/test-user-1/abcde12345/static.json");
  assert.strictEqual(memberPaths.pdfKeyZh, "reports/test-user-1/abcde12345/static_zh.pdf");
  assert.strictEqual(memberPaths.pdfKeyEn, "reports/test-user-1/abcde12345/static_en.pdf");
  assert.strictEqual(memberPaths.legacyPdfKey, "reports/test-user-1/abcde12345/static.pdf");
  console.log("✓ Test 1: Member base paths resolution verified (standard _zh.pdf, _en.pdf, and legacy .pdf)");

  const guestScope: ArtifactScope = {
    role: "guest",
    jobId: "guest-job-99",
    analysisType: "dynamic",
    filename: "guest-app.apk",
    fileType: "apk",
  };

  const guestPaths = ArtifactVault.resolveBasePaths(guestScope);
  assert.strictEqual(guestPaths.uploadKey, "guest/uploads/guest-job-99.apk");
  assert.strictEqual(guestPaths.reportJsonKey, "guest/reports/guest-job-99.json");
  assert.strictEqual(guestPaths.pdfKeyZh, "guest/reports/guest-job-99_zh.pdf");
  assert.strictEqual(guestPaths.pdfKeyEn, "guest/reports/guest-job-99_en.pdf");
  assert.strictEqual(guestPaths.legacyPdfKey, "guest/reports/guest-job-99.pdf");
  console.log("✓ Test 2: Guest base paths resolution verified");

  // Test 3: Quota Safety Guard - Quota MUST NOT be consumed if report files are missing
  let quotaConsumed = false;
  const mockQuotaCallback = () => {
    quotaConsumed = true;
    return true;
  };

  const missingScope: ArtifactScope = {
    role: "member",
    uid: "non-existent-user",
    hash: "non-existent-hash",
    analysisType: "static",
    filename: "ghost.apk",
  };

  const downloadResult = await ArtifactVault.acquireReportDownloadUrl({
    scope: missingScope,
    lang: "zh-TW",
    consumeDownloadQuota: mockQuotaCallback,
  });

  assert.strictEqual(downloadResult.ok, false, "Download must fail when report is missing");
  assert.strictEqual(quotaConsumed, false, "Quota callback must NOT be invoked when file is missing");
  console.log("✓ Test 3: Quota safety guard verified (no quota deducted on missing report)");

  // Test 4: Version-aware purge keys enumeration
  // When includeBinary is false (other analysis shares the binary), uploadKey must be excluded
  const purgeNoBinary = await ArtifactVault.purgeArtifacts(memberScope, { includeBinary: false });
  assert(!purgeNoBinary.purgedKeys.includes(memberPaths.uploadKey), "uploadKey must be excluded when includeBinary=false");
  assert(purgeNoBinary.purgedKeys.includes(memberPaths.reportJsonKey), "reportJsonKey must be purged");
  assert(purgeNoBinary.purgedKeys.includes(memberPaths.pdfKeyZh), "pdfKeyZh must be purged");
  assert(purgeNoBinary.purgedKeys.includes(memberPaths.pdfKeyEn), "pdfKeyEn must be purged");
  assert(purgeNoBinary.purgedKeys.includes(memberPaths.legacyPdfKey), "legacyPdfKey must be purged");

  // When includeBinary is true, uploadKey must be included
  const purgeWithBinary = await ArtifactVault.purgeArtifacts(memberScope, { includeBinary: true });
  assert(purgeWithBinary.purgedKeys.includes(memberPaths.uploadKey), "uploadKey must be included when includeBinary=true");
  console.log("✓ Test 4: Version-aware purge keys enumeration and binary protection verified");

  // Test 5: Magic bytes validation & automatic temp file cleanup
  const invalidTempPath = "./test-invalid-file.apk";
  await require("fs").promises.writeFile(invalidTempPath, Buffer.from([0x00, 0x11, 0x22, 0x33]));
  let rejected = false;
  try {
    await ArtifactVault.ingestUploadedBinary(memberScope, invalidTempPath);
  } catch (err: any) {
    rejected = true;
    assert.strictEqual(err.code, "invalid_file_format");
  }
  assert.strictEqual(rejected, true, "ingestUploadedBinary must reject invalid magic bytes");
  const invalidExists = require("fs").existsSync(invalidTempPath);
  assert.strictEqual(invalidExists, false, "Invalid temp file must be unlinked after rejection");

  console.log("✓ Test 5: Magic bytes validation & automatic temp cleanup verified");

  // Test 6: Defensive Report Object Normalization (double-serialized JSON unpacking)
  const { normalizeReportObject } = await import("../dispatch");

  // Single serialized
  const single = JSON.stringify({ summary: { high: 1 } });
  const normSingle = normalizeReportObject(single);
  assert.strictEqual(normSingle.summary.high, 1, "Single-serialized JSON string must unpack correctly");

  // Double serialized
  const double = JSON.stringify(JSON.stringify({ summary: { high: 1 } }));
  const normDouble = normalizeReportObject(double);
  assert.strictEqual(normDouble.summary.high, 1, "Double-serialized JSON string must unpack correctly");

  // Plain object
  const plain = { summary: { high: 2 } };
  assert.strictEqual(normalizeReportObject(plain).summary.high, 2, "Plain object must pass through intact");

  // Invalid formats must throw
  assert.throws(() => normalizeReportObject("not-a-json"), /Invalid report data structure/);
  assert.throws(() => normalizeReportObject([1, 2, 3]), /Invalid report data structure/);

  console.log("✓ Test 6: Defensive Report Object Normalization (double-serialized JSON unpacking) verified");

  // Test 7: Pre-generated PDFs from an analysis host (iOS on the Mac) are validated
  {
    const pdf = Buffer.concat([Buffer.from("%PDF-1.4\n"), Buffer.alloc(2048, 0x30)]);
    const ok = decodePregeneratedPdf(pdf.toString("base64"), "en");
    assert(ok && ok.equals(pdf), "valid PDF must decode byte-for-byte");
    assert.strictEqual(decodePregeneratedPdf(Buffer.from("<html>x</html>").toString("base64"), "en"), null);
    assert.strictEqual(decodePregeneratedPdf(undefined, "zh-TW"), null);
    const huge = Buffer.concat([Buffer.from("%PDF-"), Buffer.alloc(10 * 1024 * 1024)]);
    assert.strictEqual(decodePregeneratedPdf(huge.toString("base64"), "zh-TW"), null, "oversized PDF is dropped");
    console.log("✓ Test 7: Pre-generated PDF validation (magic bytes, size cap) verified");
  }

  // Test 8: iOS dynamic never falls back to the (Android-only) PDF Lambda
  {
    const iosDynamic: ArtifactScope = {
      role: "member", uid: "u-ios", hash: "h-ios", analysisType: "dynamic", filename: "DVIA-v2.ipa",
    };
    assert.strictEqual(isIosDynamicScope(iosDynamic), true);
    assert.strictEqual(isIosDynamicScope({ ...iosDynamic, filename: "app.apk" }), false);
    assert.strictEqual(isIosDynamicScope({ ...iosDynamic, analysisType: "static" }), false);
    assert.strictEqual(
      isIosDynamicScope({ role: "guest", jobId: "g1", analysisType: "dynamic", filename: "x", fileType: "ipa" }),
      true
    );

    let quotaUsed = false;
    const en = await ArtifactVault.acquireReportDownloadUrl({
      scope: iosDynamic,
      lang: "en",
      consumeDownloadQuota: () => (quotaUsed = true),
    });
    assert.strictEqual(en.ok, false);
    assert.strictEqual(!en.ok && en.code, "pdf_not_available", "English iOS dynamic PDF reports not available");
    assert.strictEqual(quotaUsed, false, "no quota spent on an unavailable PDF");
    console.log("✓ Test 8: iOS dynamic scope detection and no-Lambda English fallback verified");
  }

  console.log("==================================================");
  console.log(" All ArtifactVault Module Unit Tests Passed (8/8) ✅");
  console.log("==================================================");
}

runTests().catch((err) => {
  console.error("ArtifactVault unit tests failed:", err);
  process.exit(1);
});
