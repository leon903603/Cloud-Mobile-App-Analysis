import assert from "assert";
import {
  createSandboxAdapter,
  SandboxExecutionError,
  DynamicJobRequest,
} from "../services/sandboxAdapter";

console.log("==================================================");
console.log(" Running SandboxAdapter Deep Module Unit Tests");
console.log("==================================================");

async function runTests() {
  // ── Test 1: FIFO Mutex & Last-One-Out Zero-Idle Shutdown ─────────────────
  console.log("Testing Test 1: FIFO Mutex & Last-One-Out Zero-Idle Shutdown...");
  {
    const callLog: string[] = [];
    let job1Finished = false;

    const mockAdapter = createSandboxAdapter({
      instanceId: "i-test-12345",
      timeoutMs: 5000,
      ec2Send: async (cmd: any) => {
        const cmdName = cmd.constructor.name;
        callLog.push(`ec2:${cmdName}`);
        return {};
      },
      waitUntilRunning: async () => {
        callLog.push("ec2:waitUntilRunning");
      },
      probeFn: async () => {
        callLog.push("sandbox:probe");
        return true;
      },
      downloadToTempFn: async () => {
        callLog.push("s3:download");
        return "fake-temp-path.apk";
      },
      createReadStreamFn: () => Buffer.from("mock"),
      fetchFn: (async (url: string, opts: any) => {
        callLog.push(`fetch:${url}`);
        if (url.includes("/analyze_dynamic")) {
          // If this is job 1, artificially delay to ensure job 2 is queued
          if (!job1Finished) {
            await new Promise((r) => setTimeout(r, 80));
            job1Finished = true;
          }
          return {
            ok: true,
            status: 200,
            json: async () => ({
              report: { status: "success", score: 85 },
              pdf_base64: "dGVzdC1wZGY=",
            }),
          } as any;
        }
        return { ok: true, status: 200, json: async () => ({}) } as any;
      }) as any,
    });

    const job2Phases: string[] = [];

    // Launch Job 1 and Job 2 concurrently
    const p1 = mockAdapter.runDynamicAnalysis({
      s3UploadKey: "uploads/user1/hash1/app.apk",
      filename: "app1.apk",
      fileHash: "hash1",
    });

    // Small delay to ensure job 1 has acquired the lock
    await new Promise((r) => setTimeout(r, 10));

    const p2 = mockAdapter.runDynamicAnalysis({
      s3UploadKey: "uploads/user2/hash2/app.apk",
      filename: "app2.apk",
      fileHash: "hash2",
      onPhaseChange: (phase) => {
        job2Phases.push(phase);
      },
    });

    const [res1, res2] = await Promise.all([p1, p2]);

    assert.strictEqual(res1.reportData.status, "success");
    assert.strictEqual(res2.reportData.status, "success");

    // Job 2 must have experienced "queued" phase because Job 1 held the mutex
    assert(
      job2Phases.includes("queued"),
      "Job 2 should have transitioned through 'queued' phase while waiting for Job 1"
    );

    // Verify "Last-One-Out" StopInstances behavior:
    // Job 1 must NOT have stopped the instance when finishing because Job 2 was pending.
    // StopInstancesCommand should only appear at the very end after both jobs are complete.
    const stopCommands = callLog.filter((c) => c === "ec2:StopInstancesCommand");
    assert.strictEqual(
      stopCommands.length,
      1,
      "StopInstancesCommand should be called exactly once (when queue becomes empty)"
    );

    // The single StopInstancesCommand must be the last EC2 action
    const lastEc2Index = callLog.lastIndexOf("ec2:StopInstancesCommand");
    assert.strictEqual(
      lastEc2Index,
      callLog.length - 1,
      "StopInstancesCommand must execute as the final cleanup step"
    );

    console.log("✓ Test 1: FIFO Mutex, warm handover, and Last-One-Out shutdown verified");
  }

  // ── Test 2: Error Classification (SandboxExecutionError) ─────────────────
  console.log("Testing Test 2: Error Classification (Capacity, Startup, Timeout)...");
  {
    // A: Capacity Error
    let startAttempts = 0;
    const capacityAdapter = createSandboxAdapter({
      instanceId: "i-capacity-test",
      startRetryDelayMs: 10,
      stopRetryDelayMs: 5,
      ec2Send: async (cmd: any) => {
        if (cmd.constructor.name === "StartInstancesCommand") {
          startAttempts++;
          const err = new Error("InsufficientInstanceCapacity: We do not have sufficient capacity");
          err.name = "InsufficientInstanceCapacity";
          throw err;
        }
        return {};
      },
      probeFn: async () => true,
      downloadToTempFn: async () => "tmp.apk",
    });

    try {
      await capacityAdapter.runDynamicAnalysis({
        s3UploadKey: "uploads/test/capacity.apk",
        filename: "capacity.apk",
        fileHash: "hash-cap",
      });
      assert.fail("Should have thrown capacity error");
    } catch (err: any) {
      assert(err instanceof SandboxExecutionError, "Error must be instance of SandboxExecutionError");
      assert.strictEqual(err.kind, "capacity", "Error kind should be 'capacity'");
    }

    // B: Startup Probe Failed Error
    const probeFailAdapter = createSandboxAdapter({
      instanceId: "i-probe-fail",
      ec2Send: async () => ({}),
      waitUntilRunning: async () => {},
      probeFn: async () => false, // probe returns false (timed out)
    });

    try {
      await probeFailAdapter.runDynamicAnalysis({
        s3UploadKey: "uploads/test/probe.apk",
        filename: "probe.apk",
        fileHash: "hash-probe",
      });
      assert.fail("Should have thrown startup_failed error");
    } catch (err: any) {
      assert(err instanceof SandboxExecutionError, "Error must be instance of SandboxExecutionError");
      assert.strictEqual(err.kind, "startup_failed", "Error kind should be 'startup_failed'");
    }

    // C: Timeout Error
    const timeoutAdapter = createSandboxAdapter({
      instanceId: "i-timeout-test",
      timeoutMs: 50, // fast timeout for test
      ec2Send: async () => ({}),
      waitUntilRunning: async () => {},
      probeFn: async () => true,
      downloadToTempFn: async () => "tmp.apk",
      createReadStreamFn: () => Buffer.from("mock"),
      fetchFn: (async () => {
        // Hang indefinitely until aborted
        await new Promise((r) => setTimeout(r, 500));
        return { ok: true, json: async () => ({}) } as any;
      }) as any,
    });

    try {
      await timeoutAdapter.runDynamicAnalysis({
        s3UploadKey: "uploads/test/timeout.apk",
        filename: "timeout.apk",
        fileHash: "hash-timeout",
      });
      assert.fail("Should have timed out");
    } catch (err: any) {
      assert(err instanceof SandboxExecutionError, "Error must be instance of SandboxExecutionError");
      assert.strictEqual(err.kind, "timeout", "Error kind should be 'timeout'");
    }

    console.log("✓ Test 2: Error classification for capacity, startup_failed, and timeout verified");
  }

  // ── Test 3: Guest Simulation Fallback ────────────────────────────────────
  console.log("Testing Test 3: Guest Simulation Fallback...");
  {
    const fallbackAdapter = createSandboxAdapter({
      instanceId: "i-fallback",
      stopRetryDelayMs: 5,
      ec2Send: async () => {
        throw new Error("AWS Credentials Unavailable");
      },
    });

    const dynamicRes = await fallbackAdapter.runDynamicAnalysis({
      s3UploadKey: "guest/uploads/job-123.apk",
      filename: "guest-test.apk",
      fileHash: "hash-guest",
      allowSimulationFallback: true,
    });

    assert.strictEqual(dynamicRes.simulated, true, "Dynamic result should indicate simulated=true");
    assert.strictEqual(dynamicRes.reportData.status, "success");
    assert.strictEqual(dynamicRes.pdfBase64, null);

    const staticRes = await fallbackAdapter.runStaticAnalysis({
      platform: "android",
      s3UploadKey: "guest/uploads/job-123.apk",
      filename: "guest-test.apk",
      fileHash: "hash-guest",
      allowSimulationFallback: true,
    });

    assert.strictEqual(staticRes.simulated, true, "Static result should indicate simulated=true");
    assert.strictEqual(staticRes.reportData.status, "success");

    console.log("✓ Test 3: Guest simulation fallbacks for dynamic and static engines verified");
  }

  // ── Test 4: Static Analysis Job Submission & Polling ────────────────────
  console.log("Testing Test 4: Static Analysis Polling...");
  {
    let pollCount = 0;
    const staticAdapter = createSandboxAdapter({
      staticApiAndroid: "http://static-engine:5001",
      pollIntervalMs: 10,
      fetchFn: (async (url: string, opts: any) => {
        if (url.endsWith("/analyze_apk")) {
          return {
            ok: true,
            status: 202,
            json: async () => ({ job_id: "job-static-abc" }),
          } as any;
        }
        if (url.includes("/status/job-static-abc")) {
          pollCount++;
          if (pollCount < 2) {
            return {
              ok: true,
              json: async () => ({ status: "running" }),
            } as any;
          }
          return {
            ok: true,
            json: async () => ({
              status: "success",
              result: { findings: [], score: 90 },
            }),
          } as any;
        }
        return { ok: false, status: 404 } as any;
      }) as any,
    });

    let reportedTaskId = "";
    const result = await staticAdapter.runStaticAnalysis({
      platform: "android",
      s3UploadKey: "uploads/user/app.apk",
      filename: "app.apk",
      fileHash: "hash-static",
      onTaskQueued: (taskId) => {
        reportedTaskId = taskId;
      },
    });

    assert.strictEqual(reportedTaskId, "job-static-abc");
    assert.strictEqual(result.simulated, false);
    assert.strictEqual(result.reportData.score, 90);

    console.log("✓ Test 4: Static analysis dispatch and poll resolution verified");
  }

  // ── Test 5: Static Analysis Timeout / Network Hang Handling ─────────────
  console.log("Testing Test 5: Static Analysis Timeout / Network Hang Handling...");
  {
    const timeoutAdapter = createSandboxAdapter({
      staticApiAndroid: "http://static-engine:5001",
      timeoutMs: 30, // 30ms fast timeout
      fetchFn: (async (url: string, opts: any) => {
        // If timeout option is provided and small, simulate fetch abort/timeout
        if (opts?.timeout && opts.timeout <= 50) {
          const err = new Error("network timeout at: http://static-engine:5001/analyze_apk");
          (err as any).name = "FetchError";
          (err as any).type = "request-timeout";
          throw err;
        }
        return { ok: true, json: async () => ({}) } as any;
      }) as any,
    });

    let failed = false;
    try {
      await timeoutAdapter.runStaticAnalysis({
        platform: "android",
        s3UploadKey: "uploads/user/timeout.apk",
        filename: "timeout.apk",
        fileHash: "hash-timeout",
        allowSimulationFallback: false,
      });
    } catch (err: any) {
      failed = true;
      assert(err.message.includes("timeout"), "Error should reflect network timeout");
    }
    assert.strictEqual(failed, true, "Static analysis must throw when network times out");
    console.log("✓ Test 5: Static analysis submission timeout properly caught and handled");
  }

  // ── Test 6: Async Dynamic Polling Flow ─────────────────────────
  console.log("Testing Test 6: Async Dynamic Polling Flow (?async=true & /job_status)...");
  {
    let pollCount = 0;
    const asyncAdapter = createSandboxAdapter({
      instanceId: "i-async-test",
      pollIntervalMs: 10,
      ec2Send: async () => ({}),
      waitUntilRunning: async () => ({}),
      probeFn: async () => true,
      downloadToTempFn: async () => "fake-async.apk",
      createReadStreamFn: () => Buffer.from("mock"),
      fetchFn: (async (url: string) => {
        if (url.includes("/analyze_dynamic?async=true")) {
          return {
            ok: true,
            status: 202,
            json: async () => ({ job_id: "job-async-123", status: "queued" }),
          } as any;
        }
        if (url.includes("/job_status/job-async-123")) {
          pollCount++;
          if (pollCount < 3) {
            return {
              ok: true,
              status: 200,
              json: async () => ({ status: "processing", job_id: "job-async-123" }),
            } as any;
          }
          return {
            ok: true,
            status: 200,
            json: async () => ({
              status: "done",
              report: { status: "success", score: 92 },
              pdf_base64: "YXN5bmMtcGRm",
            }),
          } as any;
        }
        return { ok: true, status: 200, json: async () => ({}) } as any;
      }) as any,
    });

    const result = await asyncAdapter.runDynamicAnalysis({
      s3UploadKey: "uploads/async/app.apk",
      filename: "async_app.apk",
      fileHash: "hash-async",
    });

    assert.strictEqual(result.reportData.status, "success");
    assert.strictEqual(result.reportData.score, 92);
    assert.strictEqual(result.pdfBase64, "YXN5bmMtcGRm");
    assert(pollCount >= 3, `Expected at least 3 polls, got ${pollCount}`);
    console.log("✓ Test 6: Async Dynamic Polling (?async=true & /job_status) passed successfully");
  }

  // ── Test 7: 404 Circuit Breaker Fast-Fail ─────────────────────
  console.log("Testing Test 7: 404 Circuit Breaker Fast-Fail...");
  {
    let pollAttempts = 0;
    const circuitBreakerAdapter = createSandboxAdapter({
      instanceId: "i-404-test",
      pollIntervalMs: 5,
      ec2Send: async () => ({}),
      waitUntilRunning: async () => ({}),
      probeFn: async () => true,
      downloadToTempFn: async () => "fake-404.apk",
      createReadStreamFn: () => Buffer.from("mock"),
      fetchFn: (async (url: string) => {
        if (url.includes("/analyze_dynamic?async=true")) {
          return {
            ok: true,
            status: 202,
            json: async () => ({ job_id: "job-lost-404", status: "queued" }),
          } as any;
        }
        if (url.includes("/job_status/job-lost-404")) {
          pollAttempts++;
          return {
            ok: false,
            status: 404,
            json: async () => ({ error: "Not found" }),
          } as any;
        }
        return { ok: true, status: 200, json: async () => ({}) } as any;
      }) as any,
    });

    let threwExpectedError = false;
    try {
      await circuitBreakerAdapter.runDynamicAnalysis({
        s3UploadKey: "uploads/404/app.apk",
        filename: "lost_app.apk",
        fileHash: "hash-404",
      });
    } catch (err: any) {
      if (err instanceof SandboxExecutionError && err.kind === "analysis_failed" && err.message.includes("404")) {
        threwExpectedError = true;
      }
    }

    assert.strictEqual(threwExpectedError, true, "Adapter must throw analysis_failed after 3 consecutive 404s");
    assert.strictEqual(pollAttempts, 3, "Polling must stop immediately at exactly 3 consecutive 404s");
    console.log("✓ Test 7: 404 circuit breaker successfully failed fast after 3 consecutive 404s");
  }

  // ── Test 8: iOS Wrapper Token + Presigned Input ─────────────────────────
  console.log("Testing Test 8: iOS wrapper token header and presigned input...");
  {
    const seen: { url: string; headers: any; body?: any }[] = [];
    const iosFetch = (async (url: string, opts: any) => {
      seen.push({ url, headers: opts?.headers || {}, body: opts?.body ? JSON.parse(opts.body) : undefined });
      if (url.endsWith("/analyze_ipa")) {
        return { ok: true, status: 202, json: async () => ({ job_id: "job-ios-1" }) } as any;
      }
      return {
        ok: true,
        json: async () => ({ status: "success", result: { rules: 38 }, pdfs: { "zh-TW": "WkgtUERG", en: "RU4tUERG" } }),
      } as any;
    }) as any;

    const presignAdapter = createSandboxAdapter({
      staticApiIos: "http://100.64.0.9:8000",
      staticTokenIos: "tok-123",
      staticS3ModeIos: "presign",
      pollIntervalMs: 10,
      presignInputUrlFn: async (key, ttl) => `https://s3.example/${key}?ttl=${ttl}`,
      fetchFn: iosFetch,
    });
    const res = await presignAdapter.runStaticAnalysis({
      platform: "ios",
      s3UploadKey: "uploads/u1/" + "a".repeat(64) + "/app.ipa",
      filename: "app.ipa",
      fileHash: "a".repeat(64),
    });
    assert.strictEqual(res.reportData.rules, 38);
    assert.strictEqual(seen[0].body.key, undefined, "presign mode must not send the raw S3 key");
    assert.strictEqual(seen[0].body.download_url, "https://s3.example/uploads/u1/" + "a".repeat(64) + "/app.ipa?ttl=1800");
    assert.strictEqual(seen[0].headers["X-Static-Token"], "tok-123", "submit must carry the token");
    assert.strictEqual(seen[1].headers["X-Static-Token"], "tok-123", "status poll must carry the token");
    assert.deepStrictEqual(seen[0].body.pdf_langs, ["zh-TW", "en"], "iOS asks the wrapper for both PDFs");
    assert.deepStrictEqual(res.pdfs, { "zh-TW": "WkgtUERG", en: "RU4tUERG" }, "wrapper PDFs are passed through");

    // Default mode: unchanged request shape, and Android never gets the iOS token.
    seen.length = 0;
    const directAdapter = createSandboxAdapter({
      staticApiIos: "http://100.64.0.9:8000",
      staticApiAndroid: "http://static-engine:5001",
      staticTokenIos: "tok-123",
      staticS3ModeIos: "direct",
      pollIntervalMs: 10,
      fetchFn: (async (url: string, opts: any) => {
        if (!url.endsWith("/analyze_apk")) return iosFetch(url, opts);
        seen.push({ url, headers: opts?.headers || {}, body: JSON.parse(opts.body) });
        return { ok: true, status: 202, json: async () => ({ job_id: "a1" }) } as any;
      }) as any,
    });
    await directAdapter.runStaticAnalysis({
      platform: "ios", s3UploadKey: "uploads/u1/h/app.ipa", filename: "app.ipa", fileHash: "h",
    });
    assert.strictEqual(seen[0].body.key, "uploads/u1/h/app.ipa");
    assert.strictEqual(seen[0].body.download_url, undefined);
    seen.length = 0;
    await directAdapter.runStaticAnalysis({
      platform: "android", s3UploadKey: "uploads/u1/h/app.apk", filename: "app.apk", fileHash: "h",
    });
    assert.strictEqual(seen[0].headers["X-Static-Token"], undefined, "Android must not receive the iOS token");
    assert.strictEqual(seen[0].body.pdf_langs, undefined, "Android keeps using the PDF Lambda");

    const { isAllowedAnalysisInputKey } = await import("../s3");
    assert.strictEqual(isAllowedAnalysisInputKey("uploads/u1/" + "a".repeat(64) + "/兆豐 銀行.ipa"), true);
    assert.strictEqual(isAllowedAnalysisInputKey("guest/uploads/job_1.ipa"), true);
    assert.strictEqual(isAllowedAnalysisInputKey("reports/u1/" + "a".repeat(64) + "/static.pdf"), false);
    assert.strictEqual(isAllowedAnalysisInputKey("uploads/u1/" + "a".repeat(64) + "/app.apk"), false);
    assert.strictEqual(isAllowedAnalysisInputKey("uploads/u1/../x/" + "a".repeat(64) + ".ipa"), false);
    console.log("✓ Test 8: iOS presigned input + token verified; direct mode and Android unchanged");
  }

  console.log("==================================================");
  console.log(" All SandboxAdapter Unit Tests Passed (8/8) ✅");
  console.log("==================================================");
}

runTests().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
