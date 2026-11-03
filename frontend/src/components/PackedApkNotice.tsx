import React from "react";
import { PackageOpen } from "lucide-react";

// Shared expectation-setting notice for Android static analysis.
//
// A packed ("hardened") APK ships its real DEX encrypted and only reconstructs it
// in memory at runtime, so androguard sees the unpacking stub and little else.
// The report is then thin through no fault of the scan, which customers read as a
// broken analysis unless we say so up front — hence the same wording on the
// uploaders, the history entry and the public product page.
const PackedApkNotice: React.FC<{ className?: string }> = ({ className = "" }) => (
  <div
    className={`flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2.5 ${className}`}
  >
    <PackageOpen className="mt-0.5 h-4 w-4 shrink-0 text-amber-600 dark:text-amber-500" />
    <p className="text-sm text-foreground">
      <span className="font-medium">Packed APKs produce fewer findings.</span> If an Android
      app is hardened with a packer or protector (360 Qihoo / Jiagu, Bangcle, Tencent Legu,
      DexProtector and similar), its real code is stored encrypted and only restored in
      memory while the app runs. Static analysis can only read the unpacking stub, so the
      report will be much shorter than it would be for an unprotected APK — that is a
      property of the app, not a failed scan.{" "}
      <span className="font-medium">Dynamic analysis</span> is the better fit for those apps.
    </p>
  </div>
);

export default PackedApkNotice;
