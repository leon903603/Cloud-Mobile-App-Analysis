import assert from "assert";
import { S3Client, GetBucketLifecycleConfigurationCommand } from "@aws-sdk/client-s3";

async function verifyLifecycle() {
  console.log("======================================================================");
  console.log(" 🛡️ AWS S3 Bucket Lifecycle Configuration Verification");
  console.log("======================================================================");

  const region = process.env.AWS_REGION || "ap-southeast-2";
  const bucket = process.env.S3_BUCKET || "cmaa-s3-islab-sydney";

  const client = new S3Client({ region });
  const res = await client.send(
    new GetBucketLifecycleConfigurationCommand({ Bucket: bucket })
  );

  assert(res.Rules && res.Rules.length >= 3, "Expected at least 3 lifecycle rules");

  const abortRule = res.Rules.find((r) => r.ID === "AbortIncompleteMultipartUploadsAfter1Day");
  assert(abortRule, "AbortIncompleteMultipartUploadsAfter1Day rule must exist");
  assert.strictEqual(abortRule.Status, "Enabled");
  assert.strictEqual(abortRule.AbortIncompleteMultipartUpload?.DaysAfterInitiation, 1);
  console.log("✓ Rule 1: AbortIncompleteMultipartUploadsAfter1Day verified (1 day)");

  const expireNoncurrentRule = res.Rules.find((r) => r.ID === "ExpireNoncurrentHistoricalVersionsAfter2Days");
  assert(expireNoncurrentRule, "ExpireNoncurrentHistoricalVersionsAfter2Days rule must exist");
  assert.strictEqual(expireNoncurrentRule.Status, "Enabled");
  assert.strictEqual(expireNoncurrentRule.NoncurrentVersionExpiration?.NoncurrentDays, 2);
  console.log("✓ Rule 2: ExpireNoncurrentHistoricalVersionsAfter2Days verified (2 days, live files safe)");

  const guestSafetyRule = res.Rules.find((r) => r.ID === "GuestLifecycleSafetyNet7Days");
  assert(guestSafetyRule, "GuestLifecycleSafetyNet7Days rule must exist");
  assert.strictEqual(guestSafetyRule.Status, "Enabled");
  assert.strictEqual(guestSafetyRule.Expiration?.Days, 7);
  console.log("✓ Rule 3: GuestLifecycleSafetyNet7Days verified (7 days safety net)");

  const legacyDangerousRule = res.Rules.find((r) => r.ID === "delete-old-uploads");
  assert(!legacyDangerousRule, "Legacy delete-old-uploads rule must NOT exist (protects member assets)");
  console.log("✓ Rule 4: Legacy 30-day live file deletion rule successfully eliminated");

  console.log("======================================================================");
  console.log(" 🎉 All S3 Bucket Lifecycle Rules Validated Successfully!");
  console.log("======================================================================");
}

verifyLifecycle().catch((err) => {
  console.error("Lifecycle verification failed:", err);
  process.exit(1);
});
