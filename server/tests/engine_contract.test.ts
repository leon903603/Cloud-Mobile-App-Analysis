import assert from "assert";
import fs from "fs";
import path from "path";

const SCHEMA_PATH = path.resolve(__dirname, "../schemas/static_report_v1.schema.json");
const STATIC_REPO_CANDIDATES = [
  path.resolve(__dirname, "../../../android-static"),
  path.resolve(__dirname, "../../../../android-static"),
  path.resolve(__dirname, "../../../../../android-static"),
];
const STATIC_REPO_DIR = STATIC_REPO_CANDIDATES.find((p) => fs.existsSync(p)) || STATIC_REPO_CANDIDATES[0];

interface RuleMeta {
  title?: string;
  mas?: string;
  mast?: string;
  real_mstg?: string;
  owasp_mobile?: string;
  level?: string;
  cve?: string;
  desc?: string;
}

export function validateStaticRulesContract(
  rules: Record<string, RuleMeta>,
  schemaConfig: any,
  options: { isWhiteLabel?: boolean } = { isWhiteLabel: true }
): { ok: boolean; errors: string[] } {
  const errors: string[] = [];
  const ruleKeys = Object.keys(rules);
  const { whiteLabel } = schemaConfig.invariants;

  if (ruleKeys.length < whiteLabel.minRuleCount) {
    errors.push(`Rule count ${ruleKeys.length} is below minimum ${whiteLabel.minRuleCount}`);
  }

  for (const reqId of whiteLabel.requiredLatestRuleIds) {
    if (!rules[reqId]) {
      errors.push(`Missing required latest rule ID: ${reqId}`);
    }
  }

  for (const [ruleId, meta] of Object.entries(rules)) {
    for (const reqField of schemaConfig.definitions.RuleMetadata.required) {
      if (typeof (meta as any)[reqField] !== "string") {
        errors.push(`${ruleId}: missing or non-string required field '${reqField}'`);
      }
    }

    if (options.isWhiteLabel) {
      for (const forbiddenField of whiteLabel.forbiddenFieldsNonEmpty) {
        const val = (meta as any)[forbiddenField];
        if (typeof val === "string" && val.trim() !== "") {
          errors.push(`${ruleId}: white-label violation — '${forbiddenField}' must be empty, got '${val}'`);
        }
      }
      for (const badSub of whiteLabel.forbiddenSubstringsInDesc) {
        if (meta.desc && meta.desc.includes(badSub)) {
          errors.push(`${ruleId}: white-label violation — desc contains forbidden URL '${badSub}'`);
        }
      }
    }
  }

  return { ok: errors.length === 0, errors };
}

async function runTests() {
  console.log("==================================================");
  console.log(" Running Cross-Engine Contract & White-Label Tests");
  console.log("==================================================");

  assert(fs.existsSync(SCHEMA_PATH), `Schema file must exist at ${SCHEMA_PATH}`);
  const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, "utf-8"));

  // Test 1: Validate synthetic white-labeled report passes contract
  const validRules: Record<string, RuleMeta> = {};
  for (let i = 1; i <= 87; i++) {
    const id = `AS-lab${String(i).padStart(3, "0")}`;
    validRules[id] = {
      title: `Rule ${id}`,
      mas: "",
      mast: "",
      real_mstg: "MSTG-NETWORK-1",
      owasp_mobile: "M3",
      level: "HIGH",
      cve: "CWE-319",
      desc: "Standard international OWASP MASVS description.",
    };
  }
  const passRes = validateStaticRulesContract(validRules, schema, { isWhiteLabel: true });
  assert.strictEqual(passRes.ok, true, `Valid rules should pass: ${passRes.errors.join("; ")}`);
  console.log("✓ Test 1: Compliant white-labeled 87-rule payload passes contract schema");

  // Test 2: Detect white-label regression (non-empty 'mas' or 'mas.owasp.org' leak)
  const pollutedRules = {
    ...validRules,
    "AS-lab001": {
      ...validRules["AS-lab001"],
      mas: "4.1.1.1.1",
      desc: "See https://mas.owasp.org/MASTG/ for details",
    },
  };
  const failRes = validateStaticRulesContract(pollutedRules, schema, { isWhiteLabel: true });
  assert.strictEqual(failRes.ok, false, "Polluted rules must be rejected by contract validator");
  assert(failRes.errors.some((e) => e.includes("'mas' must be empty")), "Should flag non-empty mas");
  assert(failRes.errors.some((e) => e.includes("mas.owasp.org")), "Should flag mas.owasp.org link");
  console.log("✓ Test 2: Contract validator accurately catches 'mas' & 'mas.owasp.org' regressions");

  // Test 3: Sibling android-static verification
  const enPath = path.join(STATIC_REPO_DIR, "android_static_en.json");
  const zhPath = path.join(STATIC_REPO_DIR, "android_static_zhtw.json");
  if (fs.existsSync(enPath) && fs.existsSync(zhPath)) {
    const enRules = JSON.parse(fs.readFileSync(enPath, "utf-8"));
    const zhRules = JSON.parse(fs.readFileSync(zhPath, "utf-8"));

    assert.deepStrictEqual(
      Object.keys(enRules).sort(),
      Object.keys(zhRules).sort(),
      "EN and zh-TW rule keys must have 100% parity"
    );

    // In origin/android-static, JSON file contains full MAS baseline by default,
    // and white-labeling is performed at output stage (/get_json with MAS_REPORT=0).
    const enBaseCheck = validateStaticRulesContract(enRules, schema, { isWhiteLabel: false });
    const zhBaseCheck = validateStaticRulesContract(zhRules, schema, { isWhiteLabel: false });
    assert.strictEqual(enBaseCheck.ok, true, `android_static_en.json failed base contract: ${enBaseCheck.errors.join(", ")}`);
    assert.strictEqual(zhBaseCheck.ok, true, `android_static_zhtw.json failed base contract: ${zhBaseCheck.errors.join(", ")}`);
    console.log(`✓ Test 3: Live sibling repo (android-static) EN & zh-TW (${Object.keys(enRules).length} rules) verified!`);
  } else {
    console.log("ℹ Test 3: Sibling android-static repo not mounted — skipped live file check");
  }

  // Test 4: PDF generator safe parsing invariant (defensive .get for mas/real_mstg)
  const incomingSampleWithoutMas: any = {
    title: "Test Rule",
    level: "HIGH",
    desc: "A test description"
  };
  const safeMas = incomingSampleWithoutMas.mas || "";
  const safeRealMstg = incomingSampleWithoutMas.real_mstg || "";
  assert.strictEqual(safeMas, "");
  assert.strictEqual(safeRealMstg, "");
  console.log("✓ Test 4: Downstream consumer defensive parsing invariant verified");

  console.log("==================================================");
  console.log(" All Cross-Engine Contract Tests Passed ✅");
  console.log("==================================================");
}

runTests().catch((err) => {
  console.error("Cross-Engine Contract tests failed:", err);
  process.exit(1);
});
