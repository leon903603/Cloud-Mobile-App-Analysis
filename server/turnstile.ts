// server/turnstile.ts — Cloudflare Turnstile token validation helper.
// Provides graceful degradation: if TURNSTILE_SECRET_KEY is empty/unset,
// verification is bypassed so development and unconfigured deployments never break.

export async function verifyTurnstileToken(
  token: string | undefined | null,
  remoteIp?: string
): Promise<{ ok: boolean; reason?: string }> {
  const secretKey = process.env.TURNSTILE_SECRET_KEY?.trim();

  // If not configured, bypass gracefully
  if (!secretKey) {
    return { ok: true };
  }

  if (!token || typeof token !== "string" || !token.trim()) {
    return {
      ok: false,
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
    });

    if (!res.ok) {
      console.warn(`[Turnstile] Verification HTTP error: ${res.status}`);
      return { ok: false, reason: `Verification service returned HTTP status ${res.status}.` };
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
        reason: "Human verification failed or expired. Please retry the verification challenge.",
      };
    }

    return { ok: true };
  } catch (err: any) {
    console.error("[Turnstile] Network error during token verification:", err);
    return { ok: false, reason: "Unable to verify human challenge due to a network error." };
  }
}
