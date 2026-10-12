// server/tests/download_whitelist.test.ts
import assert from "assert";
import { isAllowedReportKey } from "../s3";

console.log("==================================================");
console.log(" Running Download Path Whitelist Guard Unit Tests");
console.log("==================================================");

// 1. Valid Member Report Paths
const validMemberPaths = [
  "reports/user123/a1b2c3d4e5f678901234567890abcdef/static.pdf",
  "reports/user_abc/a1b2c3d4e5f678901234567890abcdef/dynamic.pdf",
  "reports/test-user/1234567890abcdef1234567890abcdef/static_zh-TW.pdf",
  "reports/test-user/1234567890abcdef1234567890abcdef/dynamic_en.pdf",
];

for (const p of validMemberPaths) {
  assert.strictEqual(isAllowedReportKey(p), true, `Should accept valid member report key: ${p}`);
}
console.log("✓ Test 1: Valid member PDF keys accepted");

// 2. Valid Guest Report Paths
const validGuestPaths = [
  "guest/reports/job-123.pdf",
  "guest/reports/cmaa-guest-789_zh.pdf",
  "guest/reports/guest_job_999_en.pdf",
];

for (const p of validGuestPaths) {
  assert.strictEqual(isAllowedReportKey(p), true, `Should accept valid guest report key: ${p}`);
}
console.log("✓ Test 2: Valid guest PDF keys accepted");

// 3. Illegal / Exfiltration Paths (Must be rejected!)
const illegalPaths = [
  "uploads/user123/malicious.apk",
  "guest/uploads/job-123.apk",
  "reports/user123/hash/static.json",
  "credentials.json",
  ".env",
  "../../etc/passwd",
  "reports/user123/hash/../../secret.pdf",
  "guest/reports/job-123.exe",
  "",
  null as any,
  undefined as any,
];

for (const p of illegalPaths) {
  assert.strictEqual(isAllowedReportKey(p), false, `Should reject unauthorized key: ${p}`);
}
console.log("✓ Test 3: Unauthorized keys, binaries, source files, and traversal attempts strictly rejected");

console.log("All Download Whitelist Guard tests passed! ✅");
