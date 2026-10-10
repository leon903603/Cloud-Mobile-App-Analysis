import assert from "assert";
import {
  isJobExpired,
  getAssociatedStorageKeys,
} from "../services/storageHygiene";

console.log("==================================================");
console.log(" Running Storage Hygiene Service Unit Tests");
console.log("==================================================");

const BASE_NOW = 1700000000000;

// Anti-Tautological Decoupling: Use independent domain literals rather than
// importing the production constants being tested.
const INDEPENDENT_UNPAID_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const INDEPENDENT_PAID_TTL_MS = 48 * 60 * 60 * 1000;   // 48 hours

// Test 1: Unpaid job boundary checks (24h TTL)
{
  const justBeforeTtl = new Date(BASE_NOW - INDEPENDENT_UNPAID_TTL_MS + 60 * 1000).toISOString(); // 23h 59m ago
  const justAfterTtl = new Date(BASE_NOW - INDEPENDENT_UNPAID_TTL_MS - 60 * 1000).toISOString();  // 24h 01m ago

  assert.strictEqual(
    isJobExpired({ createdAt: justBeforeTtl, isPaid: 0 }, BASE_NOW),
    false,
    "Unpaid job at 23h59m must NOT be expired"
  );

  assert.strictEqual(
    isJobExpired({ createdAt: justAfterTtl, isPaid: 0 }, BASE_NOW),
    true,
    "Unpaid job at 24h01m MUST be expired"
  );
  console.log("✓ Test 1: Unpaid job 24h boundary passed (23h59m vs 24h01m)");
}

// Test 2: Paid job boundary checks (48h TTL)
{
  const justBeforeTtl = new Date(BASE_NOW - INDEPENDENT_PAID_TTL_MS + 60 * 1000).toISOString(); // 47h 59m ago
  const justAfterTtl = new Date(BASE_NOW - INDEPENDENT_PAID_TTL_MS - 60 * 1000).toISOString();  // 48h 01m ago

  assert.strictEqual(
    isJobExpired({ createdAt: justBeforeTtl, isPaid: 1 }, BASE_NOW),
    false,
    "Paid job at 47h59m must NOT be expired"
  );

  assert.strictEqual(
    isJobExpired({ createdAt: justAfterTtl, isPaid: 1 }, BASE_NOW),
    true,
    "Paid job at 48h01m MUST be expired"
  );
  console.log("✓ Test 2: Paid job 48h boundary passed (47h59m vs 48h01m)");
}

// Test 3: Malformed or missing timestamp safeguards
{
  assert.strictEqual(
    isJobExpired({ createdAt: "", isPaid: 0 }, BASE_NOW),
    false,
    "Empty timestamp must not trigger expiry"
  );
  assert.strictEqual(
    isJobExpired({ createdAt: "invalid-date", isPaid: 0 }, BASE_NOW),
    false,
    "Invalid date string must not trigger expiry"
  );
  console.log("✓ Test 3: Invalid/empty timestamp safeguards passed");
}

// Test 4: Associated storage keys enumeration
{
  const keys = getAssociatedStorageKeys({
    jobId: "test-job-123",
    uploadPath: "custom/uploads/test.apk",
    reportPath: "custom/reports/test.pdf",
  });

  const expectedSubstrings = [
    "custom/uploads/test.apk",
    "custom/reports/test.pdf",
    "guest/uploads/test-job-123.apk",
    "guest/uploads/test-job-123.ipa",
    "guest/reports/test-job-123.pdf",
    "guest/reports/test-job-123_zh.pdf",
    "guest/reports/test-job-123_en.pdf",
    "guest/reports/test-job-123.json",
  ];

  for (const expected of expectedSubstrings) {
    assert(
      keys.includes(expected),
      `Expected storage keys to include '${expected}'`
    );
  }
  assert.strictEqual(keys.length, 8, "Expected exactly 8 distinct storage keys");
  console.log("✓ Test 4: Complete storage keys enumeration verified");
}

console.log("==================================================");
console.log(" All Storage Hygiene Unit Tests Passed (4/4) ✅");
console.log("==================================================");
