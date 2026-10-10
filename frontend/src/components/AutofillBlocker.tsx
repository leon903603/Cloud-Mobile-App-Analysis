import React from "react";

/**
 * Off-screen dummy inputs that absorb aggressive browser password-manager
 * auto-fill passes (e.g. 1Password, Bitwarden, Chrome Autofill) before they
 * reach the dynamic sandbox test account credentials fields.
 */
export const AutofillBlocker: React.FC = () => {
  return (
    <div
      style={{
        position: "absolute",
        top: -9999,
        left: -9999,
        width: 1,
        height: 1,
        overflow: "hidden",
      }}
      aria-hidden="true"
    >
      <input
        type="text"
        name="chrome_dummy_username"
        tabIndex={-1}
        autoComplete="off"
        data-lpignore="true"
        data-1p-ignore="true"
      />
      <input
        type="password"
        name="chrome_dummy_password"
        tabIndex={-1}
        autoComplete="off"
        data-lpignore="true"
        data-1p-ignore="true"
      />
    </div>
  );
};
