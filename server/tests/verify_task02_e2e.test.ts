import assert from "assert";
import fs from "fs";
import path from "path";
import { db } from "../db";
import { GuestJob } from "../models/GuestJob";
import { purgeExpiredGuestJobs } from "../services/storageHygiene";

console.log("======================================================================");
console.log(" 🧪 工單 02: Storage Hygiene Worker 端到端 (E2E) 整合驗證流程");
console.log("======================================================================");

const LOCAL_STORAGE_DIR = path.join(__dirname, "..", "data", "s3_local");

function ensureLocalFile(relKey: string, content: string = "dummy-binary-payload"): string {
  const fullPath = path.join(LOCAL_STORAGE_DIR, ...relKey.split("/"));
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, content, "utf-8");
  return fullPath;
}

async function runVerification() {
  const now = Date.now();
  const ONE_HOUR = 60 * 60 * 1000;

  // 1. 準備四組不同生命週期的測試任務
  const testJobs = [
    {
      id: "test-job-A-unpaid-25h",
      isPaid: 0,
      createdAt: new Date(now - 25 * ONE_HOUR).toISOString(),
      expectedExpired: true,
      desc: "未付費任務 (已過 25h > 24h TTL) -> 預期過期並被清理",
    },
    {
      id: "test-job-B-unpaid-23h",
      isPaid: 0,
      createdAt: new Date(now - 23 * ONE_HOUR).toISOString(),
      expectedExpired: false,
      desc: "未付費任務 (僅 23h < 24h TTL)  -> 預期保留活躍狀態",
    },
    {
      id: "test-job-C-paid-25h",
      isPaid: 1,
      createdAt: new Date(now - 25 * ONE_HOUR).toISOString(),
      expectedExpired: false,
      desc: "已付費任務 (已過 25h < 48h TTL) -> 預期保留活躍狀態",
    },
    {
      id: "test-job-D-paid-50h",
      isPaid: 1,
      createdAt: new Date(now - 50 * ONE_HOUR).toISOString(),
      expectedExpired: true,
      desc: "已付費任務 (已過 50h > 48h TTL) -> 預期過期並被清理",
    },
  ];

  console.log("\n[步驟 1] 建立測試資料庫紀錄與磁碟實體測試檔案...");
  for (const job of testJobs) {
    // 清理舊殘留
    GuestJob.delete(job.id);

    const uploadKey = `guest/uploads/${job.id}.apk`;
    const reportKey = `guest/reports/${job.id}.pdf`;

    const uploadFile = ensureLocalFile(uploadKey, `APK binary for ${job.id}`);
    const reportFile = ensureLocalFile(reportKey, `PDF report for ${job.id}`);

    // 直接以原始 SQL 寫入以精確控制 createdAt 與 isPaid
    db.prepare(`
      INSERT INTO guest_jobs (jobId, analysisType, fileHash, filename, status, isPaid, createdAt, expiresAt, uploadPath, reportPath)
      VALUES (?, 'static', 'hash123', 'app.apk', 'done', ?, ?, ?, ?, ?)
    `).run(
      job.id,
      job.isPaid,
      job.createdAt,
      new Date(now + 7 * 24 * ONE_HOUR).toISOString(),
      uploadKey,
      reportKey
    );

    console.log(`  + 已建立: ${job.id} (${job.desc})`);
    assert(fs.existsSync(uploadFile), `檔案應存在: ${uploadFile}`);
    assert(fs.existsSync(reportFile), `檔案應存在: ${reportFile}`);
  }

  // 2. 觸發定時清理管線
  console.log("\n[步驟 2] 觸發 Storage Hygiene 定時清理管線 (purgeExpiredGuestJobs)...");
  const result = await purgeExpiredGuestJobs(now);
  console.log(`  -> 掃描活躍任務數: ${result.scanned} 筆，已清理過期任務數: ${result.purged} 筆`);

  // 3. 逐一斷言與驗證結果
  console.log("\n[步驟 3] 驗證各任務之資料庫狀態與檔案物理抹除結果:");
  for (const job of testJobs) {
    const row = GuestJob.findByJobId(job.id);
    assert(row, `資料庫中應能找到 ${job.id}`);

    const uploadPath = path.join(LOCAL_STORAGE_DIR, "guest", "uploads", `${job.id}.apk`);
    const reportPath = path.join(LOCAL_STORAGE_DIR, "guest", "reports", `${job.id}.pdf`);
    const filesExist = fs.existsSync(uploadPath) || fs.existsSync(reportPath);

    if (job.expectedExpired) {
      assert.strictEqual(row.status, "expired", `${job.id} 的 DB status 應變為 'expired'`);
      assert.strictEqual(row.uploadPath, null, `${job.id} 的 uploadPath 應被清空為 null`);
      assert.strictEqual(row.reportPath, null, `${job.id} 的 reportPath 應被清空為 null`);
      assert.strictEqual(filesExist, false, `${job.id} 的實體檔案必須已被物理刪除`);
      console.log(`  ✅ [過期清理成功] ${job.id}: 狀態更新為 expired，所有實體檔案已物理拔除！`);
    } else {
      assert.strictEqual(row.status, "done", `${job.id} 狀態應維持 'done'`);
      assert(row.uploadPath !== null, `${job.id} 的 uploadPath 應被保留`);
      assert(filesExist, `${job.id} 的實體檔案應完好如初`);
      console.log(`  ✅ [狀態安全保留] ${job.id}: 任務尚未超過 TTL，檔案與路徑完整保留！`);
    }
  }

  // 4. 清理測試環境
  console.log("\n[步驟 4] 清理測試環境，還原資料庫與暫存檔案...");
  for (const job of testJobs) {
    GuestJob.delete(job.id);
    const p1 = path.join(LOCAL_STORAGE_DIR, "guest", "uploads", `${job.id}.apk`);
    const p2 = path.join(LOCAL_STORAGE_DIR, "guest", "reports", `${job.id}.pdf`);
    if (fs.existsSync(p1)) fs.unlinkSync(p1);
    if (fs.existsSync(p2)) fs.unlinkSync(p2);
  }

  console.log("\n======================================================================");
  console.log(" 🎉 工單 02 所有生命週期邏輯、物理清除與資料庫狀態轉換 100% 驗證通過！");
  console.log("======================================================================");
}

runVerification().catch((err) => {
  console.error("❌ 驗證失敗:", err);
  process.exit(1);
});
