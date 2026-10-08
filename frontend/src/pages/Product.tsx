// src/pages/Product.tsx — public product introduction & pricing page
// (required disclosure for payment-gateway review: product intro, price, contact info)
import { Link } from "react-router-dom";
import {
  Activity,
  ArrowRight,
  FileSearch,
  Mail,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { Button } from "../components/ui/button";
import PackedApkNotice from "../components/PackedApkNotice";
import ThemeToggle from "../components/ThemeToggle";

const COMPANY = "SUPREMA TECHNOLOGIES LTD";
const CONTACT_EMAIL = "suprematechnologiesltd@solitesterror.com";

const capabilities = [
  {
    icon: FileSearch,
    title: "Static Analysis",
    body: "Reverse engineer IPA and APK files to analyze permissions, embedded secrets, SDK usage, cryptography, and insecure logic.",
  },
  {
    icon: Activity,
    title: "Dynamic Analysis",
    body: "Execute applications in controlled environments and instrument runtime behavior using Frida to observe APIs, data flows, and hidden functionality.",
  },
  {
    icon: ShieldAlert,
    title: "Threat Detection",
    body: "Detect malicious behavior, anti-debug techniques, dynamic code loading, and privacy violations.",
  },
];

const staticWorkflow = [
  { title: "Package Extraction", items: ["IPA / APK unpacking", "Binary & resource extraction"] },
  { title: "Code Inspection", items: ["Permissions", "Secrets", "SDKs"] },
  { title: "Risk Assessment", items: ["Vulnerability identification", "Security findings"] },
];

const dynamicWorkflow = [
  { title: "Controlled Execution", items: ["Emulator / Device", "Isolated environment"] },
  { title: "Frida Instrumentation", items: ["API hooking", "Native & Java hooks"] },
  { title: "Runtime Findings", items: ["Data leakage", "Hidden logic"] },
];

const coverage = [
  {
    title: "MASVS – Architecture & Data",
    items: ["Secure data storage", "Encryption & key handling", "Secure communication"],
  },
  {
    title: "MASVS – Platform Interaction",
    items: ["Permission misuse", "Inter-process communication", "Insecure intents & URL schemes"],
  },
  {
    title: "MSTG – Runtime Analysis",
    items: ["Anti-debug & anti-tampering", "Dynamic code loading", "Runtime API abuse"],
  },
];

function WorkflowRow({ steps }: { steps: { title: string; items: string[] }[] }) {
  return (
    <div className="flex flex-col md:flex-row items-stretch gap-3">
      {steps.map((step, i) => (
        <div key={step.title} className="flex flex-col md:flex-row items-center gap-3 flex-1">
          <div className="w-full h-full rounded-xl border border-border bg-card p-5 text-center">
            <div className="text-xs font-semibold tracking-widest text-primary mb-2">
              STEP {i + 1}
            </div>
            <h3 className="font-semibold text-foreground mb-2">{step.title}</h3>
            <ul className="text-sm text-muted-foreground space-y-1">
              {step.items.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </div>
          {i < steps.length - 1 && (
            <ArrowRight className="shrink-0 text-muted-foreground rotate-90 md:rotate-0" />
          )}
        </div>
      ))}
    </div>
  );
}

function Product() {
  return (
    <div className="min-h-screen w-full bg-gradient-to-br from-slate-100 via-background to-indigo-50 dark:from-[#070b16] dark:via-background dark:to-[#0c1226]">
      <div className="mx-auto max-w-5xl px-6 py-10 flex flex-col gap-16">

        {/* ── Header ─────────────────────────────────────────────────── */}
        <header className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-2 font-semibold text-foreground">
            <ShieldCheck className="text-primary" />
            {COMPANY}
          </div>
          <div className="flex items-center gap-2">
            <ThemeToggle />
            <Button asChild>
              <Link to="/app">Go to Platform</Link>
            </Button>
          </div>
        </header>

        {/* ── Hero ───────────────────────────────────────────────────── */}
        <section className="text-center flex flex-col items-center gap-4">
          <h1 className="text-4xl md:text-5xl font-bold text-foreground">
            Mobile Application Analysis Platform
          </h1>
          <p className="max-w-2xl text-lg text-muted-foreground">
            Advanced static and dynamic analysis for iOS and Android applications.
            We inspect IPA and APK files using reverse engineering and runtime
            instrumentation such as Frida.
          </p>
        </section>

        {/* ── Core capabilities ──────────────────────────────────────── */}
        <section className="flex flex-col gap-6">
          <div className="text-center">
            <h2 className="text-2xl font-bold text-foreground">Core Capabilities</h2>
            <p className="text-muted-foreground mt-1">
              Deep inspection of mobile applications across code, runtime behavior,
              and security posture.
            </p>
          </div>
          <div className="grid gap-4 md:grid-cols-3">
            {capabilities.map(({ icon: Icon, title, body }) => (
              <div key={title} className="rounded-xl border border-border bg-card p-6">
                <Icon className="text-primary mb-3" />
                <h3 className="font-semibold text-foreground mb-2">{title}</h3>
                <p className="text-sm text-muted-foreground">{body}</p>
              </div>
            ))}
          </div>
        </section>

        {/* ── Workflows ──────────────────────────────────────────────── */}
        <section className="flex flex-col gap-6">
          <div className="text-center">
            <h2 className="text-2xl font-bold text-foreground">Static Analysis Workflow</h2>
            <p className="text-muted-foreground mt-1">
              Application packages are analyzed without execution to identify
              structural and configuration risks.
            </p>
          </div>
          <WorkflowRow steps={staticWorkflow} />
          <PackedApkNotice className="mx-auto w-full max-w-3xl" />
        </section>

        <section className="flex flex-col gap-6">
          <div className="text-center">
            <h2 className="text-2xl font-bold text-foreground">Dynamic Analysis Workflow</h2>
            <p className="text-muted-foreground mt-1">
              Runtime analysis reveals behaviors that cannot be observed statically.
            </p>
          </div>
          <WorkflowRow steps={dynamicWorkflow} />
        </section>

        {/* ── OWASP coverage ─────────────────────────────────────────── */}
        <section className="flex flex-col gap-6">
          <div className="text-center">
            <h2 className="text-2xl font-bold text-foreground">
              OWASP MASVS &amp; MSTG Coverage
            </h2>
            <p className="text-muted-foreground mt-1">
              Our analysis aligns with industry-standard mobile security frameworks.
            </p>
          </div>
          <div className="grid gap-4 md:grid-cols-3">
            {coverage.map(({ title, items }) => (
              <div key={title} className="rounded-xl border border-border bg-card p-6">
                <h3 className="font-semibold text-foreground mb-3">{title}</h3>
                <ul className="text-sm text-muted-foreground space-y-2">
                  {items.map((item) => (
                    <li key={item} className="flex items-start gap-2">
                      <ShieldCheck className="h-4 w-4 mt-0.5 shrink-0 text-primary" />
                      {item}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </section>

        {/* ── Pricing ────────────────────────────────────────────────── */}
        <section className="flex flex-col gap-6" id="pricing">
          <div className="text-center">
            <h2 className="text-2xl font-bold text-foreground">Pricing</h2>
            <p className="text-muted-foreground mt-1">
              Simple, transparent, pay-per-use pricing.
            </p>
          </div>
          <div className="mx-auto w-full max-w-sm rounded-xl border border-border bg-card p-8 text-center">
            <h3 className="font-semibold text-foreground">Application Analysis</h3>
            <div className="my-4">
              <span className="text-5xl font-bold text-foreground">US$40</span>
              <span className="text-muted-foreground"> / analysis</span>
              <div className="text-muted-foreground mt-1">
                billed in TWD at the current exchange rate
              </div>
            </div>
            <p className="text-sm text-muted-foreground mb-6">
              One credit runs one analysis of one IPA or APK file and includes a
              downloadable PDF security report. Static and dynamic analysis are
              charged separately, so running both on the same file costs two
              credits. Uploading a file is free — a credit is only spent when you
              start an analysis. Prices are listed in US dollars. Payments are
              processed by NewebPay (藍新金流) and charged in New Taiwan Dollars
              (TWD); the exact TWD amount is shown before you pay.
            </p>
            <Button asChild className="w-full">
              <Link to="/app">Get Started</Link>
            </Button>
          </div>
        </section>

        {/* ── Stored-value disclosure (required merchant disclosure) ──── */}
        <section className="flex flex-col gap-4">
          <div className="text-center">
            <h2 className="text-2xl font-bold text-foreground">Stored Value Disclosure</h2>
          </div>
          <div className="mx-auto w-full max-w-2xl rounded-xl border border-border bg-card p-6 text-sm text-muted-foreground space-y-3">
            <p>
              SUPREMA TECHNOLOGIES LTD does{" "}
              <span className="font-semibold text-foreground">not</span> provide
              stored-value, e-wallet, or top-up services. Every payment on this
              platform is a prepaid fee for a specific service: one credit
              corresponds to exactly one mobile application analysis run (US$40,
              charged in TWD at the exchange rate shown at checkout). Static and
              dynamic analysis are separate services, each costing one credit.
            </p>
            <p>
              Credits have no cash value, are non-transferable, cannot be
              exchanged or refunded for cash, and cannot be used for any purpose
              other than the analysis services described on this page.
            </p>
            <p>
              本網站不提供儲值服務；點數為預付之應用程式分析服務費用，僅可兌換本平台之分析服務，不得轉讓、兌換現金或移作其他用途。
            </p>
          </div>
        </section>

        {/* ── Contact / footer ───────────────────────────────────────── */}
        <footer className="border-t border-border pt-8 pb-4 text-center flex flex-col items-center gap-2">
          <h2 className="text-lg font-semibold text-foreground">Contact Us</h2>
          <a
            href={`mailto:${CONTACT_EMAIL}`}
            className="inline-flex items-center gap-2 text-primary hover:underline"
          >
            <Mail className="h-4 w-4" />
            {CONTACT_EMAIL}
          </a>
          <p className="text-sm text-muted-foreground mt-2">
            © {new Date().getFullYear()} {COMPANY}. All rights reserved.
          </p>
        </footer>

      </div>
    </div>
  );
}

export default Product;
