import assert from "assert";
import fs from "fs";
import path from "path";
import {
  DEFAULT_CONTACT_EMAIL,
  copyTextToClipboard,
} from "../../frontend/src/utils/contactEmail";

console.log("==================================================");
console.log(" Running Contact Email Resilience Unit Tests (UX-002)");
console.log("==================================================");

async function runTests() {
  // Test 1: Verify invariant contact email
  assert.strictEqual(
    DEFAULT_CONTACT_EMAIL,
    "suprematechnologiesltd@solitesterror.com",
    "Default contact email must match the corporate support address"
  );
  console.log("✓ Test 1: Corporate support email invariant verified");

  const originalNavigatorDesc = Object.getOwnPropertyDescriptor(globalThis, "navigator");

  const setMockNavigator = (nav: any) => {
    Object.defineProperty(globalThis, "navigator", {
      value: nav,
      configurable: true,
      writable: true,
    });
  };

  const restoreNavigator = () => {
    if (originalNavigatorDesc) {
      Object.defineProperty(globalThis, "navigator", originalNavigatorDesc);
    } else {
      delete (globalThis as any).navigator;
    }
  };

  try {
    // Test 2: Clipboard API primary path (navigator.clipboard.writeText)
    let writtenText = "";
    const mockNavigator = {
      clipboard: {
        writeText: async (text: string) => {
          writtenText = text;
        },
      },
    };

    setMockNavigator(mockNavigator);
    const result1 = await copyTextToClipboard("test@example.com");
    assert.strictEqual(result1, true, "copyTextToClipboard should return true on success");
    assert.strictEqual(writtenText, "test@example.com", "Written text should match target email");
    console.log("✓ Test 2: Modern navigator.clipboard.writeText execution verified");

    // Test 3: Fallback path when navigator.clipboard throws (execCommand fallback)
    setMockNavigator({
      clipboard: {
        writeText: async () => {
          throw new Error("NotAllowedError: Permission denied in test context");
        },
      },
    });

    let execCommandCalled = false;
    let appendedElement: any = null;
    const mockDocument = {
      createElement: (tag: string) => ({
        value: "",
        style: {},
        setAttribute: () => {},
        focus: () => {},
        select: () => {},
      }),
      body: {
        appendChild: (el: any) => {
          appendedElement = el;
        },
        removeChild: (el: any) => {
          if (appendedElement === el) appendedElement = null;
        },
      },
      execCommand: (command: string) => {
        if (command === "copy") {
          execCommandCalled = true;
          return true;
        }
        return false;
      },
    };

    (global as any).document = mockDocument;
    const result2 = await copyTextToClipboard("fallback@example.com");
    assert.strictEqual(result2, true, "Fallback should return true on execCommand success");
    assert.strictEqual(execCommandCalled, true, "execCommand('copy') must be invoked on fallback");
    console.log("✓ Test 3: execCommand('copy') resilience fallback verified");

    // Clean up global mocks
    delete (global as any).document;

    // Test 4: Graceful handling in headless non-DOM environment
    setMockNavigator({});
    const result3 = await copyTextToClipboard("headless@example.com");
    assert.strictEqual(result3, false, "Should return false gracefully when no DOM/clipboard exists");
    console.log("✓ Test 4: Headless / SSR non-crashing graceful degradation verified");
  } finally {
    restoreNavigator();
    delete (global as any).document;
  }

  // Test 5: Verify all frontend entrypoints have eliminated raw unshielded mailto links
  const frontendSrc = path.resolve(__dirname, "../../frontend/src");
  const targetFiles = [
    "components/DynamicConfirmModal.tsx",
    "components/FileUploader.tsx",
    "components/GuestUploader.tsx",
    "pages/Product.tsx",
    "App.tsx",
  ];

  for (const relPath of targetFiles) {
    const fullPath = path.join(frontendSrc, relPath);
    const content = fs.readFileSync(fullPath, "utf-8");

    // Must import CopyableEmailLink
    assert(
      content.includes("CopyableEmailLink"),
      `File ${relPath} must import and use CopyableEmailLink`
    );

    // Must not contain raw `<a href="mailto:...`
    const rawMailtoRegex = /<a[^>]*href=["']mailto:/i;
    assert(
      !rawMailtoRegex.test(content),
      `File ${relPath} must not contain raw unshielded <a href="mailto:...">`
    );
  }
  console.log("✓ Test 5: All 5 frontend contact touchpoints migrated to CopyableEmailLink");

  console.log("==================================================");
  console.log(" All Contact Email Resilience Tests Passed (5/5) ✅");
  console.log("==================================================");
}

runTests().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
