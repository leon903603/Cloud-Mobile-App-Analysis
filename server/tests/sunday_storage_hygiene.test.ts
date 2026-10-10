// server/tests/sunday_storage_hygiene.test.ts
import assert from "assert";
import crypto from "crypto";
import { db } from "../db";
import { GuestJob } from "../models/GuestJob";
import { FileMeta } from "../models/FileMeta";
import { purgeSundayEpochReset, isJobExpired } from "../services/storageHygiene";

console.log("==================================================");
console.log(" Running Sunday Epoch Storage Purge Unit Tests");
console.log("==================================================");

async function runTests() {
  const timestampNow = Date.now();
  const pastCutoff = new Date(timestampNow - 10000).toISOString();

  // 1. Create a guest job before cutoff
  const guestJobId = "test-sunday-guest-" + Date.now();
  GuestJob.create({
    jobId: guestJobId,
    analysisType: "static",
    fileHash: "hash-sunday-test",
    filename: "sunday-guest.apk",
    status: "done",
    secretKey: crypto.randomBytes(16).toString("hex"),
  });
  db.prepare("UPDATE guest_jobs SET createdAt = ? WHERE jobId = ?").run(pastCutoff, guestJobId);

  // 2. Create a member file_meta record before cutoff
  db.prepare("INSERT OR IGNORE INTO users (id, email) VALUES (?, ?)").run(
    "test-user-sunday",
    "sunday@example.com"
  );

  const memberFile = FileMeta.create({
    user: "test-user-sunday",
    filename: "member-sunday.apk",
    analysisType: "static",
    filePath: "uploads/member-sunday.apk",
    reportPath: "reports/member-sunday.pdf",
    hash: "hash-member-sunday",
    status: "done",
  });
  db.prepare("UPDATE file_meta SET uploadTime = ? WHERE id = ?").run(pastCutoff, memberFile.id);

  // 3. Run purgeSundayEpochReset with cutoffMs = timestampNow
  const result = await purgeSundayEpochReset(timestampNow);
  assert(result.guestPurged >= 1, "At least 1 guest job should be purged");
  assert(result.memberFilesPurged >= 1, "At least 1 member file should be purged");

  // 4. Assert guest job state transitioned to 'expired'
  const updatedGuest = GuestJob.findByJobId(guestJobId);
  assert(updatedGuest, "Guest job must still exist in DB");
  assert.strictEqual(updatedGuest.status, "expired", "Guest job status must transition to 'expired'");
  assert.strictEqual(updatedGuest.uploadPath, null, "uploadPath must be cleared");
  assert.strictEqual(updatedGuest.reportPath, null, "reportPath must be cleared");
  console.log("✓ Test 1: Guest job properly transitioned to 'expired' and paths cleared");

  // 5. Assert member file_meta was deleted
  const updatedMember = FileMeta.findById(memberFile.id);
  assert.strictEqual(updatedMember, undefined, "Member file_meta row must be removed");
  console.log("✓ Test 2: Member file_meta row successfully pruned");

  console.log("All Sunday Storage Hygiene tests passed!");
}

runTests().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
