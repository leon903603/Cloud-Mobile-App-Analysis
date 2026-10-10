import dotenv from "dotenv";
dotenv.config();

import assert from "assert";
import {
  S3Client,
  PutObjectCommand,
  ListObjectVersionsCommand,
} from "@aws-sdk/client-s3";

async function runLiveS3Test() {
  console.log("======================================================================");
  console.log(" 🌐 AWS S3 即時雲端全版本物理抹除 (Live Cloud Purge) 實測");
  console.log("======================================================================");

  const region = process.env.AWS_REGION || "ap-southeast-2";
  const bucket = process.env.S3_BUCKET || "cmaa-s3-islab-sydney";
  const testKey = "test-live-hygiene/probe-audit.txt";

  const client = new S3Client({ region });
  const { purgeObjectAllVersions } = await import("../s3");

  console.log(`[步驟 1] 目標儲存桶: ${bucket} (區域: ${region})`);
  console.log(`[步驟 2] 連續上傳兩次同名檔案至 S3 (${testKey}) 模擬產生多個計費版本...`);

  // 上傳版本 1
  await client.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: testKey,
      Body: "Version 1: initial binary payload",
    })
  );

  // 上傳版本 2 (覆蓋)
  await client.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: testKey,
      Body: "Version 2: overwritten newer binary payload",
    })
  );

  // 查詢 S3 版本
  console.log("[步驟 3] 透過 AWS S3 API 查詢當前物件版本清單...");
  const versionsBefore = await client.send(
    new ListObjectVersionsCommand({
      Bucket: bucket,
      Prefix: testKey,
    })
  );

  const vCount = versionsBefore.Versions?.length || 0;
  console.log(`  -> 偵測到 S3 上存在 ${vCount} 個歷史版本 VersionId:`);
  for (const v of versionsBefore.Versions || []) {
    console.log(`     * VersionId: ${v.VersionId} (IsLatest: ${v.IsLatest}, Size: ${v.Size} bytes)`);
  }
  assert(vCount >= 2, `預期至少有 2 個版本，但實際只有 ${vCount} 個`);

  // 呼叫 purgeObjectAllVersions 進行物理抹除
  console.log("\n[步驟 4] 呼叫後端 purgeObjectAllVersions 執行連根拔除 (物理抹除)...");
  await purgeObjectAllVersions(testKey);

  // 再次查詢 S3 確認是否真正連根拔除
  console.log("\n[步驟 5] 再次透過 AWS S3 API 查詢該 Key 狀態...");
  const versionsAfter = await client.send(
    new ListObjectVersionsCommand({
      Bucket: bucket,
      Prefix: testKey,
    })
  );

  const remainingVersions = versionsAfter.Versions?.filter((v) => v.Key === testKey) || [];
  const remainingMarkers = versionsAfter.DeleteMarkers?.filter((dm) => dm.Key === testKey) || [];

  console.log(`  -> 剩餘 Versions 數量: ${remainingVersions.length}`);
  console.log(`  -> 剩餘 DeleteMarkers 數量: ${remainingMarkers.length}`);

  assert.strictEqual(remainingVersions.length, 0, "Versions 必須徹底歸零！");
  assert.strictEqual(remainingMarkers.length, 0, "DeleteMarkers 必須徹底歸零（杜絕殭屍標記）！");

  console.log("======================================================================");
  console.log(" 🎉 真實 AWS S3 雲端物理全版本抹除 100% 成功！無任何殘留與殭屍費用！");
  console.log("======================================================================");
}

runLiveS3Test().catch((err) => {
  console.error("❌ 真實 AWS S3 測試失敗:", err);
  process.exit(1);
});
