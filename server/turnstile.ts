// server/turnstile.ts — Cloudflare Turnstile token validation helper.
// Provides graceful degradation: if TURNSTILE_SECRET_KEY is empty/unset,
// verification is bypassed so development and unconfigured deployments never break.

export async function verifyTurnstileToken(
  token: string | undefined | null,
  remoteIp?: string
): Promise<{ ok: boolean; reason?: string; code?: "missing_token" | "invalid_token" | "timeout" | "service_error" }> {
  const secretKey = process.env.TURNSTILE_SECRET_KEY?.trim();

  // If not configured, bypass gracefully
  if (!secretKey) {
    return { ok: true };
  }

  if (!token || typeof token !== "string" || !token.trim()) {
    return {
      ok: false,
      code: "missing_token",
      reason: "Human verification token is required. Please complete the verification challenge.",
    };
  }

  try {
    const formData = new URLSearchParams();
    formData.append("secret", secretKey);
    formData.append("response", token.trim());
    if (remoteIp) {
      formData.append("remoteip", remoteIp);
    }

    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: formData,
      signal: AbortSignal.timeout(5000),
    });

    if (!res.ok) {
      console.warn(`[Turnstile] Verification HTTP error: ${res.status}`);
      return { ok: false, code: "service_error", reason: `Verification service returned HTTP status ${res.status}.` };
    }

    const outcome = (await res.json()) as {
      success: boolean;
      "error-codes"?: string[];
      challenge_ts?: string;
      hostname?: string;
    };

    if (!outcome.success) {
      console.warn("[Turnstile] Verification failed:", outcome["error-codes"]);
      return {
        ok: false,
        code: "invalid_token",
        reason: "Human verification failed or expired. Please retry the verification challenge.",
      };
    }

    return { ok: true };
  } catch (err: any) {
    const isTimeout = err?.name === "TimeoutError" || err?.name === "AbortError";
    console.error("[Turnstile] Error during token verification:", isTimeout ? "Request timed out" : err);
    return {
      ok: false,
      code: isTimeout ? "timeout" : "service_error",
      reason: isTimeout
        ? "Human verification timed out. Please retry the verification challenge."
        : "Unable to verify human challenge due to a network error.",
    };
  }
}
