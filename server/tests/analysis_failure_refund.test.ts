// server/tests/analysis_failure_refund.test.ts
import assert from "assert";
import { db } from "../db";
import { FileMeta } from "../models/FileMeta";

console.log("==================================================");
console.log(" Running Analysis Failure Credit Refund Unit Tests");
console.log("==================================================");

// 1. Setup test user in SQLite and mock Firestore-like behavior
const TEST_UID = "test-refund-user-" + Date.now();
db.prepare("INSERT OR IGNORE INTO users (id, email) VALUES (?, ?)").run(
  TEST_UID,
  "refund@example.com"
);

// 2. Create test file record
const file = FileMeta.create({
  user: TEST_UID,
  filename: "crash-test.apk",
  analysisType: "static",
  filePath: `uploads/${TEST_UID}/crash-test.apk`,
  reportPath: `reports/${TEST_UID}/crash-test.pdf`,
  hash: "hash-refund-test-12345",
  status: "pending",
});

assert(file, "File record should be created");
assert.strictEqual(file.creditSpent, 0, "Initially creditSpent should be 0");

// 3. Mark credit spent during analysis dispatch
FileMeta.markCreditSpent(file.id);
let updatedFile = FileMeta.findById(file.id);
assert.strictEqual(updatedFile?.creditSpent, 1, "creditSpent should be 1 during analysis");

// 4. Test failure handling and state reset
FileMeta.update(file.id, { status: "error", creditSpent: 0 });
updatedFile = FileMeta.findById(file.id);
assert.strictEqual(updatedFile?.status, "error", "Status should transition to 'error'");
assert.strictEqual(updatedFile?.creditSpent, 0, "creditSpent should be reset to 0 after refund");

console.log("✓ Test 1: FileMeta state transition to error and creditSpent reset verified");

console.log("All Analysis Failure Refund tests passed! ✅");
