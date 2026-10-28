import * as React from "react";
import { Copy, Check } from "lucide-react";

export interface CopyableEmailLinkProps {
  email?: string;
  subject?: string;
  label?: React.ReactNode;
  children?: React.ReactNode;
  className?: string;
  showIcon?: boolean;
  copiedFeedback?: string;
}

export const DEFAULT_CONTACT_EMAIL = "suprematechnologiesltd@solitesterror.com";

/**
 * Robust clipboard copy utility with automatic fallback to document.execCommand
 * for restricted/non-HTTPS or iframe browser environments.
 */
export async function copyTextToClipboard(text: string): Promise<boolean> {
  if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Fall through to legacy execCommand fallback
    }
  }

  if (typeof document !== "undefined") {
    try {
      const textArea = document.createElement("textarea");
      textArea.value = text;
      textArea.style.position = "fixed";
      textArea.style.left = "-9999px";
      textArea.style.top = "-9999px";
      textArea.setAttribute("readonly", "");
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      const success = document.execCommand("copy");
      document.body.removeChild(textArea);
      return success;
    } catch {
      return false;
    }
  }

  return false;
}

/**
 * CopyableEmailLink (SPEC-CMAA-UX-002 Lightweight Edition)
 *
 * Replaces raw <a href="mailto:..."> links across the CMAA platform with a resilient
 * one-click copy trigger that writes the email to the user's clipboard and provides
 * instant inline visual confirmation without opening unresponsive desktop email apps.
 */
export function CopyableEmailLink({
  email = DEFAULT_CONTACT_EMAIL,
  subject,
  label,
  children,
  className = "",
  showIcon = true,
  copiedFeedback = "Copied!",
}: CopyableEmailLinkProps) {
  const [copied, setCopied] = React.useState(false);
  const timeoutRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);

  React.useEffect(() => {
    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
    };
  }, []);

  const handleClick = async (e: React.MouseEvent<HTMLAnchorElement>) => {
    // Intercept default mailto navigation to eliminate focus stealing and dead-clicks
    e.preventDefault();
    const ok = await copyTextToClipboard(email);
    if (ok) {
      setCopied(true);
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
      timeoutRef.current = setTimeout(() => {
        setCopied(false);
      }, 2000);
    }
  };

  const mailtoHref = subject
    ? `mailto:${email}?subject=${encodeURIComponent(subject)}`
    : `mailto:${email}`;

  const content = children || label || email;

  return (
    <a
      href={mailtoHref}
      onClick={handleClick}
      role="button"
      tabIndex={0}
      title={copied ? "Copied to clipboard!" : `Click to copy ${email}`}
      aria-label={copied ? "Email copied to clipboard" : `Copy email address ${email}`}
      className={`inline-flex items-center gap-1.5 cursor-pointer select-none transition-colors duration-150 ${className}`}
    >
      <span>{content}</span>
      {showIcon && (
        <span className="inline-flex items-center shrink-0">
          {copied ? (
            <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-300 dark:border-emerald-800 px-1.5 py-0.5 rounded shadow-xs animate-in fade-in duration-150">
              <Check className="h-3 w-3 stroke-[2.5]" />
              <span>{copiedFeedback}</span>
            </span>
          ) : (
            <Copy className="h-3.5 w-3.5 text-muted-foreground/70 hover:text-foreground transition-colors" />
          )}
        </span>
      )}
    </a>
  );
}

export default CopyableEmailLink;
