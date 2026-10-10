import assert from "assert";
import { verifyTurnstileToken } from "../turnstile";

console.log("==================================================");
console.log(" Running Turnstile Verification Unit Tests");
console.log("==================================================");

async function runTests() {
  const originalSecret = process.env.TURNSTILE_SECRET_KEY;
  const originalFetch = global.fetch;

  try {
    // Test 1: Graceful bypass when TURNSTILE_SECRET_KEY is empty/unset
    delete process.env.TURNSTILE_SECRET_KEY;
    const bypassResult = await verifyTurnstileToken(null);
    assert.strictEqual(bypassResult.ok, true, "Bypass must return ok: true when secret is unset");
    console.log("✓ Test 1: Graceful offline/dev bypass verified");

    // Enable secret key for remaining tests
    process.env.TURNSTILE_SECRET_KEY = "1x0000000000000000000000000000000AA";

    // Test 2: Missing or empty token returns 400-level code
    const missingResult = await verifyTurnstileToken("");
    assert.strictEqual(missingResult.ok, false);
    assert.strictEqual(missingResult.code, "missing_token");
    console.log("✓ Test 2: Missing token error code verified (missing_token -> 400)");

    // Test 3: Successful token verification
    global.fetch = async () =>
      ({
        ok: true,
        json: async () => ({ success: true }),
      } as any);

    const successResult = await verifyTurnstileToken("valid-token", "1.2.3.4");
    assert.strictEqual(successResult.ok, true);
    console.log("✓ Test 3: Successful token verification verified");

    // Test 4: Failed token verification
    global.fetch = async () =>
      ({
        ok: true,
        json: async () => ({ success: false, "error-codes": ["invalid-input-response"] }),
      } as any);

    const failResult = await verifyTurnstileToken("invalid-token", "1.2.3.4");
    assert.strictEqual(failResult.ok, false);
    assert.strictEqual(failResult.code, "invalid_token");
    console.log("✓ Test 4: Failed token verification verified (invalid_token -> 403)");

    // Test 5: Network timeout handling
    global.fetch = async () => {
      const err = new Error("The operation was aborted due to timeout");
      err.name = "TimeoutError";
      throw err;
    };

    const timeoutResult = await verifyTurnstileToken("any-token");
    assert.strictEqual(timeoutResult.ok, false);
    assert.strictEqual(timeoutResult.code, "timeout");
    console.log("✓ Test 5: Network timeout handling verified (timeout code mapped)");
  } finally {
    process.env.TURNSTILE_SECRET_KEY = originalSecret;
    global.fetch = originalFetch;
  }

  console.log("==================================================");
  console.log(" All Turnstile Unit Tests Passed (5/5) ✅");
  console.log("==================================================");
}

runTests().catch((err) => {
  console.error("Turnstile unit tests failed:", err);
  process.exit(1);
});
