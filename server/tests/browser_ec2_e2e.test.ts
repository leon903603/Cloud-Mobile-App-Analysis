import { chromium } from "playwright";
import assert from "assert";

console.log("==================================================");
console.log(" Running Remote EC2 Playwright Browser E2E Test");
console.log(" Flow: Preview Job -> NewebPay Checkout Form Verify -> PDF Download");
console.log("==================================================");

async function runBrowserE2E() {
  const browser = await chromium.launch({
    headless: true,
  });

  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    viewport: { width: 1280, height: 800 },
  });

  const page = await context.newPage();

  page.on("pageerror", (err) => {
    console.error("[Uncaught Browser Page Error]:", err.message);
  });

  try {
    // ─────────────────────────────────────────────────────────────
    // Phase 1: Unpaid Completed Report (Score Preview + NewebPay Gateway)
    // ─────────────────────────────────────────────────────────────
    const unpaidJob = {
      jobId: "e2e-unpaid-job",
      secretKey: "secret-unpaid-key",
      filename: "unpaid-sample.apk",
      analysisType: "static",
      status: "done",
      createdAt: new Date().toISOString(),
      isPaid: false,
      priceUsd: 40,
      priceTwd: 1280,
      summaryPreview: { high: 1, medium: 2, low: 3, score: 85 },
    };

    console.log("1. Navigating to CMAA platform (/app)...");
    await page.goto("https://cmaa.solitesterror.com/app", {
      waitUntil: "domcontentloaded",
      timeout: 30000,
    });

    // Populate localStorage with unpaid test job
    await page.evaluate((job) => {
      localStorage.setItem("cmaa_guest_jobs_history", JSON.stringify([job]));
      localStorage.setItem("cmaa_guest_job", JSON.stringify(job));
    }, unpaidJob);

    // Reload page to let GuestUploader load the job
    await page.goto("https://cmaa.solitesterror.com/app?guest_job=e2e-unpaid-job", {
      waitUntil: "domcontentloaded",
      timeout: 30000,
    });

    await page.waitForTimeout(2000);

    // 2. Verify Completed Preview UI (Score, High, Medium, Low)
    console.log("2. Verifying Completed Preview UI...");
    const scoreElement = page.locator("text=85/100").first();
    await scoreElement.waitFor({ state: "visible", timeout: 10000 });
    console.log("✓ Security Score '85/100' rendered in preview!");

    // Button label: "Pay $40(one credit) to Unlock PDF"
    const unlockButton = page.locator("button:has-text('Unlock PDF')").first();
    await unlockButton.waitFor({ state: "visible", timeout: 5000 });
    console.log("✓ 'Pay to Unlock PDF' button is visible:", await unlockButton.textContent());

    // 3. Intercept Form Submission to NewebPay Gateway
    console.log("3. Testing NewebPay Checkout Form generation seam...");
    let interceptedPost = false;
    let postUrl = "";
    let postData = "";

    // Route / block actual redirection to external NewebPay
    await page.route("**/MPG/**", (route) => {
      interceptedPost = true;
      postUrl = route.request().url();
      postData = route.request().postData() || "";
      console.log("✓ Successfully intercepted real form POST to NewebPay gateway!");
      console.log("  Target URL:", postUrl);
      console.log("  Form POST Payload keys:", postData.split("&").map((k) => k.split("=")[0]));
      route.abort();
    });

    // Click unlock button
    await unlockButton.click();

    // Wait for the form POST interception
    await page.waitForTimeout(3000);

    assert.ok(interceptedPost, "Browser must create and submit the hidden NewebPay form");
    assert.ok(postData.includes("MerchantID="), "Payload must contain MerchantID");
    assert.ok(postData.includes("TradeInfo="), "Payload must contain TradeInfo");
    assert.ok(postData.includes("TradeSha="), "Payload must contain TradeSha");
    assert.ok(postData.includes("Version="), "Payload must contain Version");

    console.log("==================================================");
    console.log("✓ NewebPay Real Form Submission Seam Verified!");
    console.log("==================================================");

    // ─────────────────────────────────────────────────────────────
    // Phase 2: Paid Completed Report (Download PDF Buttons)
    // ─────────────────────────────────────────────────────────────
    console.log("4. Verifying Report Download Seam for Paid Job...");
    const context2 = await browser.newContext({
      ignoreHTTPSErrors: true,
      viewport: { width: 1280, height: 800 },
    });
    const page2 = await context2.newPage();

    const paidJob = {
      jobId: "e2e-browser-test-job",
      secretKey: "secret1234567890abcdef",
      filename: "test-app.apk",
      analysisType: "static",
      status: "done",
      createdAt: new Date().toISOString(),
      isPaid: true,
      downloadToken: "paid-test-token-123456",
      summaryPreview: { high: 1, medium: 2, low: 3, score: 85 },
    };

    await page2.goto("https://cmaa.solitesterror.com/app", {
      waitUntil: "domcontentloaded",
      timeout: 30000,
    });

    await page2.evaluate((job) => {
      localStorage.setItem("cmaa_guest_jobs_history", JSON.stringify([job]));
      localStorage.setItem("cmaa_guest_job", JSON.stringify(job));
    }, paidJob);

    await page2.goto("https://cmaa.solitesterror.com/app?guest_job=e2e-browser-test-job&payment=success&token=paid-test-token-123456", {
      waitUntil: "domcontentloaded",
      timeout: 30000,
    });
    await page2.waitForTimeout(2000);

    const downloadZhBtn = page2.locator("button:has-text('下載中文報告')").first();
    const downloadEnBtn = page2.locator("button:has-text('Download English')").first();
    await downloadZhBtn.waitFor({ state: "visible", timeout: 10000 });
    await downloadEnBtn.waitFor({ state: "visible", timeout: 10000 });
    console.log("✓ Both Chinese and English PDF download buttons rendered!");

    // 5. Test PDF stream download response from server (handles 302 redirect to S3 presigned URL)
    console.log("5. Testing actual PDF binary stream download...");
    const [downloadResponse] = await Promise.all([
      page2.waitForResponse((res) => res.url().includes("/guest/report/") || res.url().includes("s3.amazonaws.com"), { timeout: 10000 }),
      downloadZhBtn.click(),
    ]);

    console.log("  Endpoint Response Status:", downloadResponse.status(), "URL:", downloadResponse.url().slice(0, 80));
    assert.ok(
      downloadResponse.status() === 200 || downloadResponse.status() === 302,
      `PDF download endpoint returned status: ${downloadResponse.status()}`
    );

    // If redirected to S3, follow to download actual bytes
    let pdfBuffer: Buffer;
    if (downloadResponse.status() === 302) {
      const redirectLocation = downloadResponse.headers()["location"];
      console.log("  302 Presigned S3 Location received:", redirectLocation.slice(0, 100));
      const s3Res = await fetch(redirectLocation);
      assert.strictEqual(s3Res.status, 200, "S3 Presigned URL must return 200 OK");
      pdfBuffer = Buffer.from(await s3Res.arrayBuffer());
    } else {
      pdfBuffer = Buffer.from(await downloadResponse.body());
    }

    console.log("  Received PDF size:", pdfBuffer.length, "bytes");
    assert.ok(pdfBuffer.length > 1000, "PDF must not be empty");
    assert.strictEqual(pdfBuffer.slice(0, 4).toString(), "%PDF", "PDF must start with %PDF magic header");
    console.log("✓ Genuine PDF magic header (%PDF) verified from download stream!");

    console.log("==================================================");
    console.log("✓ ALL Remote Browser E2E Tests Successfully Passed!");
    console.log("==================================================");
    await context2.close();
  } finally {
    await browser.close();
  }
}

runBrowserE2E().catch((err) => {
  console.error("Browser E2E test failed:", err);
  process.exit(1);
});
