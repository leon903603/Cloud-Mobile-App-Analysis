import dotenv from "dotenv";
dotenv.config();

if (!process.env.AWS_REGION) process.env.AWS_REGION = "ap-southeast-2";
if (!process.env.S3_BUCKET) process.env.S3_BUCKET = "cmaa-s3-islab-sydney";

import assert from "node:assert/strict";
import { describe, it, before } from "node:test";

describe("Ephemeral 60s Presigned Download Token Enforcement", () => {
  let getPresignedDownloadUrl: any;

  before(async () => {
    const s3Module = await import("../s3");
    getPresignedDownloadUrl = s3Module.getPresignedDownloadUrl;
  });
  it("defaults to 60 seconds expiration", async () => {
    const testKey = "guest/test-uuid/report.pdf";
    const testFilename = "test-report.pdf";

    const urlString = await getPresignedDownloadUrl(testKey, testFilename);
    const parsed = new URL(urlString);

    // In AWS SigV4 query strings, expiration is denoted by X-Amz-Expires
    const expiresParam = parsed.searchParams.get("X-Amz-Expires");
    assert.strictEqual(
      expiresParam,
      "60",
      `Expected X-Amz-Expires to be 60, got ${expiresParam}`
    );

    // Also assert that response content disposition is set
    const contentDisposition = parsed.searchParams.get("response-content-disposition");
    assert.ok(
      contentDisposition?.includes("test-report.pdf"),
      `Expected filename in response-content-disposition, got ${contentDisposition}`
    );
  });

  it("respects explicit 60s parameter", async () => {
    const testKey = "guest/test-uuid/report.pdf";
    const urlString = await getPresignedDownloadUrl(testKey, undefined, 60);
    const parsed = new URL(urlString);
    const expiresParam = parsed.searchParams.get("X-Amz-Expires");
    assert.strictEqual(expiresParam, "60");
  });
});
