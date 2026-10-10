import assert from "assert";
import { db } from "../db";
import { FileMeta } from "../models/FileMeta";

console.log("==================================================");
console.log(" Running Member Download Quota Unit Tests");
console.log("==================================================");

// Setup test user and file_meta row
const TEST_UID = "test-user-member-quota";
const TEST_HASH = "mock-member-hash-quota-12345";

db.prepare("INSERT OR IGNORE INTO users (id, email) VALUES (?, ?)").run(
  TEST_UID,
  "quota@example.com"
);

db.prepare(
  "DELETE FROM file_meta WHERE user = ? AND hash = ?"
).run(TEST_UID, TEST_HASH);

const fileRow = FileMeta.create({
  user: TEST_UID,
  filename: "quota-test.apk",
  analysisType: "static",
  filePath: `uploads/${TEST_UID}/${TEST_HASH}/quota-test.apk`,
  reportPath: `reports/${TEST_UID}/${TEST_HASH}/static.json`,
  hash: TEST_HASH,
});

assert(fileRow, "Failed to create test file_meta row");

// Verify default is 5
const initialRow = FileMeta.findById(fileRow.id);
assert.strictEqual(
  initialRow?.downloadsRemaining,
  5,
  `Expected initial downloadsRemaining to be 5, got ${initialRow?.downloadsRemaining}`
);
console.log("✓ Test 1: Initial default downloadsRemaining is 5");

// Decrement from 5 to 4
let ok = FileMeta.decrementDownloadsRemaining(fileRow.id);
assert.strictEqual(ok, true, "First decrement should succeed");
let row = FileMeta.findById(fileRow.id);
assert.strictEqual(row?.downloadsRemaining, 4);
console.log("✓ Test 2: Decrement from 5 to 4 succeeded");

// Force remaining to 1
db.prepare("UPDATE file_meta SET downloadsRemaining = 1 WHERE id = ?").run(fileRow.id);
ok = FileMeta.decrementDownloadsRemaining(fileRow.id);
assert.strictEqual(ok, true, "Decrement from 1 to 0 should succeed");
row = FileMeta.findById(fileRow.id);
assert.strictEqual(row?.downloadsRemaining, 0);
console.log("✓ Test 3: Decrement from 1 to 0 succeeded");

// Decrement at 0 must fail
ok = FileMeta.decrementDownloadsRemaining(fileRow.id);
assert.strictEqual(ok, false, "Decrement at 0 must return false");
row = FileMeta.findById(fileRow.id);
assert.strictEqual(row?.downloadsRemaining, 0);
console.log("✓ Test 4: Decrement at 0 blocked and quota stayed at 0");

// Concurrency test: Reset to 1, fire 10 simultaneous decrements
db.prepare("UPDATE file_meta SET downloadsRemaining = 1 WHERE id = ?").run(fileRow.id);
const results = Array.from({ length: 10 }, () =>
  FileMeta.decrementDownloadsRemaining(fileRow.id)
);
const successes = results.filter((r) => r === true).length;
const rejections = results.filter((r) => r === false).length;

assert.strictEqual(successes, 1, "Exactly 1 concurrent decrement must succeed");
assert.strictEqual(rejections, 9, "Remaining 9 concurrent requests must be rejected");
row = FileMeta.findById(fileRow.id);
assert.strictEqual(row?.downloadsRemaining, 0, "Final quota must be 0");
console.log("✓ Test 5: Concurrency test passed (10 parallel requests -> 1 success, 9 rejections)");

// Cleanup
db.prepare("DELETE FROM file_meta WHERE id = ?").run(fileRow.id);
db.prepare("DELETE FROM users WHERE id = ?").run(TEST_UID);

console.log("==================================================");
console.log(" All Member Download Quota Tests Passed (5/5) ✅");
console.log("==================================================");
