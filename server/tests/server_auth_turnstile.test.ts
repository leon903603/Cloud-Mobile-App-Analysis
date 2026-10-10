// server/tests/server_auth_turnstile.test.ts
import assert from "assert";
import { verifyTurnstileToken } from "../turnstile";

console.log("==================================================");
console.log(" Running Server Auth Turnstile Guard Unit Tests");
console.log("==================================================");

async function runTests() {
  const originalSecret = process.env.TURNSTILE_SECRET_KEY;

  try {
    // 1. When TURNSTILE_SECRET_KEY is configured
    process.env.TURNSTILE_SECRET_KEY = "dummy-secret-key-for-test";

    // Test missing token
    const missingRes = await verifyTurnstileToken(undefined);
    assert.strictEqual(missingRes.ok, false, "Missing token must fail");
    assert.strictEqual(missingRes.code, "missing_token");

    const emptyRes = await verifyTurnstileToken("   ");
    assert.strictEqual(emptyRes.ok, false, "Empty token must fail");
    assert.strictEqual(emptyRes.code, "missing_token");
    console.log("✓ Test 1: Missing and empty Turnstile tokens rejected properly");

    // Test bypass when TURNSTILE_SECRET_KEY is not set (graceful dev environment)
    delete process.env.TURNSTILE_SECRET_KEY;
    const devRes = await verifyTurnstileToken(undefined);
    assert.strictEqual(devRes.ok, true, "Unset TURNSTILE_SECRET_KEY must bypass gracefully for dev");
    console.log("✓ Test 2: Unset TURNSTILE_SECRET_KEY gracefully bypasses");

    // 2. Validate simulation of auth endpoint logic
    process.env.TURNSTILE_SECRET_KEY = "test-secret";
    const authEndpointSimulator = async (body: { email?: string; password?: string; turnstileToken?: string }) => {
      const { email, turnstileToken } = body;
      if (!email) return { status: 400, error: "Email is required." };
      const turnstileRes = await verifyTurnstileToken(turnstileToken);
      if (!turnstileRes.ok) {
        const status = turnstileRes.code === "missing_token" ? 400 : 403;
        return { status, error: turnstileRes.reason };
      }
      return { status: 200, ok: true };
    };

    const resNoToken = await authEndpointSimulator({ email: "user@example.com" });
    assert.strictEqual(resNoToken.status, 400, "Auth endpoint must return 400 when turnstileToken is missing");

    const resNoEmail = await authEndpointSimulator({ turnstileToken: "valid" });
    assert.strictEqual(resNoEmail.status, 400, "Auth endpoint must return 400 when email is missing");

    console.log("✓ Test 3: Auth endpoint input validation and Turnstile gating verified");

    console.log("All Server Auth Turnstile tests passed!");
  } finally {
    process.env.TURNSTILE_SECRET_KEY = originalSecret;
  }
}

runTests().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
