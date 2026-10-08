import React, { useEffect, useRef, useState } from "react";

interface TurnstileWidgetProps {
  onVerify: (token: string) => void;
  onExpire?: () => void;
  siteKey?: string;
  theme?: "light" | "dark" | "auto";
}

export const TurnstileWidget: React.FC<TurnstileWidgetProps> = ({
  onVerify,
  onExpire,
  siteKey,
  theme = "auto",
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const widgetId = useRef<string | null>(null);
  const [effectiveKey, setEffectiveKey] = useState<string>(
    siteKey || import.meta.env.VITE_TURNSTILE_SITE_KEY || ""
  );

  useEffect(() => {
    if (effectiveKey) return;
    fetch(`${import.meta.env.VITE_BACKEND_URL}/api/config`)
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data?.turnstileSiteKey) {
          setEffectiveKey(data.turnstileSiteKey);
        }
      })
      .catch(() => {});
  }, [effectiveKey]);

  useEffect(() => {
    if (!effectiveKey) return;
    if (document.getElementById("cf-turnstile-script")) return;

    const script = document.createElement("script");
    script.id = "cf-turnstile-script";
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    script.async = true;
    script.defer = true;
    document.head.appendChild(script);
  }, [effectiveKey]);

  useEffect(() => {
    if (!effectiveKey) return;

    let timer: NodeJS.Timeout;
    const tryRender = () => {
      const turnstile = (window as any).turnstile;
      if (turnstile && containerRef.current) {
        if (widgetId.current !== null) {
          try {
            turnstile.remove(widgetId.current);
          } catch {}
          widgetId.current = null;
        }
        try {
          widgetId.current = turnstile.render(containerRef.current, {
            sitekey: effectiveKey,
            theme,
            callback: (token: string) => onVerify(token),
            "expired-callback": () => onExpire?.(),
            "error-callback": () => onExpire?.(),
          });
        } catch (e) {
          console.warn("Turnstile render error:", e);
        }
      } else {
        timer = setTimeout(tryRender, 200);
      }
    };

    tryRender();

    return () => {
      if (timer) clearTimeout(timer);
      const turnstile = (window as any).turnstile;
      if (turnstile && widgetId.current !== null) {
        try {
          turnstile.remove(widgetId.current);
        } catch {}
        widgetId.current = null;
      }
    };
  }, [effectiveKey, theme]);

  if (!effectiveKey) return null;

  return (
    <div className="flex justify-center my-3">
      <div ref={containerRef} />
    </div>
  );
};

export default TurnstileWidget;
