import path from "path";
import dotenv from "dotenv";
dotenv.config({ path: path.resolve(__dirname, "../../.env") });
dotenv.config({ path: path.resolve(__dirname, "../.env") });
dotenv.config();

import { initializeApp, getApps, cert, ServiceAccount } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore, FieldValue } from "firebase-admin/firestore";
import serviceAccount from "./serviceAccountKey.json";
import { User } from "./models/User";
import express, { Request, Response, NextFunction } from "express";
import multer from "multer";
import fs from "fs";
import os from "os";
import cors from "cors";
import { FileMeta, FileMetaRow } from "./models/FileMeta";
import {
  DynamicCredentials,
  startCredentialSweep,
  validateCredentials,
} from "./models/DynamicCredentials";
import { analyzeIOSStatic, analyzeAndroidStatic, analyzeAndroidDynamic} from "./dispatch";
import guestRoutes from "./guest_routes";
import { GuestJob } from "./models/GuestJob";
import { verifyTurnstileToken } from "./turnstile";
import newebpayRouter from "./newebpay";
import { startFxRefresh } from "./fx";
import { startStorageHygieneSchedule } from "./services/storageHygiene";
import {
  startCreditAudit,
  creditAuditRouter,
} from "./credit_audit";
import { CreditBank } from "./services/creditBank";
import { ArtifactVault } from "./services/artifactVault";

if (getApps().length === 0) {
  initializeApp({
    credential: cert(serviceAccount as ServiceAccount),
  });
}

// Firestore instance for non-credit operations
const db = getFirestore();

interface AuthRequest extends Request {
  user?: { uid: string; email?: string };
}

const verifyToken = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization || "";
  console.log("Incoming Authorization header:", authHeader ? `${authHeader.slice(0,20)}...` : "(none)");
  const token = authHeader.split(" ")[1]; // Bearer <token>

  if (!token) {
    console.log("No token extracted from Authorization header");
    return res.status(401).json({ error: "Missing token" });
  }

  if (process.env.NODE_ENV === "test" && token.startsWith("test-token-")) {
    const uid = token.replace("test-token-", "");
    req.user = { uid, email: `${uid}@example.com` };
    return next();
  }

  try {
    const decoded = await getAuth().verifyIdToken(token);
    console.log("Token verified for uid:", decoded.uid);
    if (!decoded.email_verified) {
      console.log("Rejected: email not verified for uid:", decoded.uid);
      return res.status(403).json({ error: "email_not_verified" });
    }
    req.user = { uid: decoded.uid, email: decoded.email };
    next();
  } catch (err) {
    console.error("Token verification failed:", err);
    res.status(401).json({ error: "Unauthorized" });
  }
};

const app = express();
app.set("trust proxy", true);
// Allow configured client origin and local development origins
const configuredOrigin = process.env.CLIENT_URL;
const allowedOrigins = [
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  "http://localhost:3000",
  "http://localhost",
  "https://core.newebpay.com",
  "https://ccore.newebpay.com",
  "https://core.spgateway.com",
  "https://ccore.spgateway.com",
];
if (configuredOrigin) {
  const normalized = configuredOrigin.trim().replace(/\/+$/, "");
  if (normalized && !allowedOrigins.includes(normalized)) {
    allowedOrigins.push(normalized);
  }
}

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) {
      return callback(null, true);
    }
    const cleanOrigin = origin.trim().replace(/\/+$/, "");
    if (allowedOrigins.includes(cleanOrigin)) {
      callback(null, true);
    } else {
      // Return false so CORS headers are omitted rather than throwing an unhandled Error
      callback(null, false);
    }
  },
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "x-guest-secret",
    "x-download-token",
    "x-turnstile-token",
    "x-admin-token",
  ],
}));
app.options("*", cors());

app.use(express.json());

app.use("/guest", guestRoutes);
// NewebPay posts notify/return as form-urlencoded, hence the extra parser.
app.use("/api/newebpay", express.urlencoded({ extended: false }), newebpayRouter);
// Credit reconciliation console. Static-token auth (ADMIN_API_TOKEN), not Firebase —
// it has to stay usable when Firebase is the thing under suspicion.
app.use("/api/admin/credit-audit", creditAuditRouter);

// Public client config
app.get("/api/config", (_req: Request, res: Response) => {
  res.json({
    turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || process.env.VITE_TURNSTILE_SITE_KEY || "",
  });
});

// Q4-A: Verify Turnstile Token for Member Authentication & Registration
app.post("/api/auth/verify-turnstile", async (req: Request, res: Response) => {
  const { token } = req.body ?? {};
  const clientIp = (req.headers["cf-connecting-ip"] as string) || req.ip;
  const result = await verifyTurnstileToken(token, clientIp);
  if (!result.ok) {
    const status = result.code === "missing_token" ? 400 : 403;
    return res.status(status).json({ ok: false, error: result.reason || "Human verification failed." });
  }
  return res.json({ ok: true });
});

async function verifyFirebasePassword(
  email: string,
  password: string
): Promise<{ ok: boolean; uid?: string; error?: string }> {
  if (process.env.NODE_ENV === "test") {
    if (password === "wrong-password") {
      return { ok: false, error: "INVALID_PASSWORD" };
    }
    try {
      const userRecord = await getAuth().getUserByEmail(email);
      return { ok: true, uid: userRecord.uid };
    } catch {
      return { ok: false, error: "EMAIL_NOT_FOUND" };
    }
  }

  const apiKey = process.env.FIREBASE_WEB_API_KEY || process.env.VITE_FIREBASE_API_KEY;
  if (!apiKey) {
    console.error("[Auth] Cannot verify password: FIREBASE_WEB_API_KEY is not configured on server");
    return { ok: false, error: "Firebase Web API key not configured on server" };
  }

  try {
    const res = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${apiKey}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, returnSecureToken: true }),
      }
    );
    const data = (await res.json()) as any;
    if (!res.ok || data.error) {
      return { ok: false, error: data.error?.message || "Invalid credentials" };
    }
    return { ok: true, uid: data.localId };
  } catch (err: any) {
    return { ok: false, error: err?.message || "Authentication service unavailable" };
  }
}

// ADR-0006: Server-Enforced Turnstile Guarded Authentication
app.post("/api/auth/login", async (req: Request, res: Response) => {
  const { email, password, turnstileToken } = req.body ?? {};
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  const clientIp = (req.headers["cf-connecting-ip"] as string) || req.ip;
  const result = await verifyTurnstileToken(turnstileToken, clientIp);
  if (!result.ok) {
    const status = result.code === "missing_token" ? 400 : 403;
    return res.status(status).json({ error: result.reason || "Human verification failed." });
  }

  const authResult = await verifyFirebasePassword(email, password);
  if (!authResult.ok) {
    return res.status(401).json({ error: "Invalid email or password." });
  }

  try {
    const customToken = await getAuth().createCustomToken(authResult.uid!);
    return res.json({ ok: true, customToken, uid: authResult.uid });
  } catch (err: any) {
    console.error("[Auth Login Error]:", err?.message);
    return res.status(500).json({ error: "Failed to create session token." });
  }
});

app.post("/api/auth/register", async (req: Request, res: Response) => {
  const { email, password, turnstileToken } = req.body ?? {};
  if (!email || !password || password.length < 6) {
    return res.status(400).json({ error: "Valid email and password (min 6 chars) are required." });
  }

  const clientIp = (req.headers["cf-connecting-ip"] as string) || req.ip;
  const result = await verifyTurnstileToken(turnstileToken, clientIp);
  if (!result.ok) {
    const status = result.code === "missing_token" ? 400 : 403;
    return res.status(status).json({ error: result.reason || "Human verification failed." });
  }

  try {
    const userRecord = await getAuth().createUser({
      email,
      password,
    });

    // Seed initial signup credits via CreditBank (guarantees idempotency and ledger journaling)
    await CreditBank.ensureUserSeeded(userRecord.uid, email);

    User.create(userRecord.uid, email);
    const customToken = await getAuth().createCustomToken(userRecord.uid);
    return res.json({ ok: true, customToken, uid: userRecord.uid });
  } catch (err: any) {
    console.error("[Auth Register Error]:", err?.message);
    const message = err?.code === "auth/email-already-exists"
      ? "An account with this email already exists."
      : "Could not create account.";
    return res.status(400).json({ error: message });
  }
});

// Multer buffers the incoming upload to a local temp file; we then stream it to S3
// and delete the temp file. S3 is the durable store — no local uploads/reports dirs.
const upload = multer({
  dest: os.tmpdir(),
  limits: { fileSize: 500 * 1024 * 1024 }, // 500 MB max limit
  defParamCharset: "utf8",
  fileFilter: (_req: any, file: any, cb: any) => {
    const allowed = [".apk", ".ipa"];
    const ext = path.extname(file.originalname).toLowerCase();
    if (!allowed.includes(ext)) {
      return cb(new Error("Invalid file extension: only .apk and .ipa files are allowed."));
    }
    cb(null, true);
  },
} as any);

// Uploading itself is free — the credit is charged when an analysis is run — but
// an empty balance means nothing can ever be done with the file, so it is turned
// away here rather than after multer has buffered the whole binary to disk.
// Ordering matters: this must sit before `upload.single()` in the chain.
const requireCredits = async (req: AuthRequest, res: Response, next: NextFunction) => {
  if (!req.user) return res.status(401).json({ message: "Unauthorized" });
  try {
    if ((await CreditBank.getBalance(req.user.uid)) <= 0) {
      return res.status(402).json({ message: "No credits left", error: "no_credits" });
    }
    next();
  } catch (err) {
    console.error("Credit check error:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// S3 key schemes. These strings are stored in FileMeta.filePath / .reportPath.
const uploadKey = (uid: string, hash: string, filename: string) =>
  `uploads/${uid}/${hash}/${filename}`;
const reportKey = (uid: string, hash: string, analysisType: string) =>
  `reports/${uid}/${hash}/${analysisType}.json`;

const CREDENTIALS_UNAVAILABLE =
  "Credential storage is not configured on this server (DYNAMIC_CRED_KEY)";

/**
 * A dynamic run only ever sees what a signed-out user sees, so the user may hand
 * it a test account to enumerate the app behind the login screen. Both `/upload`
 * and `/check-hash` can carry that account alongside the file they create a row
 * for (`appUsername` / `appPassword`), and both treat it as best effort: the
 * binary is already in S3 and the row already exists, so a credential problem is
 * *reported next to* a successful upload rather than failing one — losing a
 * 500 MB transfer over a mistyped field would be a poor trade, and the account
 * can be set from the history list afterwards.
 *
 * Returns the fields to merge into the response: nothing at all when no account
 * was offered, `credentialsSaved` either way when one was.
 */
function attachCredentials(row: FileMetaRow, body: any): Record<string, unknown> {
  const username = body?.appUsername;
  const password = body?.appPassword;
  // Absent, or present-but-blank (an untouched optional field): nothing offered.
  if (!username && !password) return {};

  if (row.analysisType !== "dynamic")
    return { credentialsSaved: false, credentialsError: "Credentials only apply to dynamic analysis" };

  const invalid = validateCredentials(username, password);
  if (invalid) return { credentialsSaved: false, credentialsError: invalid };

  if (!DynamicCredentials.supported())
    return { credentialsSaved: false, credentialsError: CREDENTIALS_UNAVAILABLE };

  try {
    DynamicCredentials.set(row.id, { username, password });
    return { credentialsSaved: true };
  } catch (err) {
    console.error("Storing dynamic credentials failed:", err);
    return { credentialsSaved: false, credentialsError: "Server error" };
  }
}

// Upload file. Free — a credit is charged per analysis, not per upload.
app.post("/upload", verifyToken, requireCredits, upload.single("file"), async (req: AuthRequest, res: Response) => {
  if (!req.user) return res.status(401).json({ message: "Unauthorized" });

  const file = req.file;
  const { type, hash } = req.body;
  if (!file || !type || !hash) return res.status(400).json({ message: "Missing fields" });

  // Q4: Verify Turnstile Token for member uploads (graceful if secret not set)
  const turnstileToken = (req.headers["x-turnstile-token"] as string) || req.body?.turnstileToken;
  const clientIp = (req.headers["cf-connecting-ip"] as string) || req.ip;
  const turnstileCheck = await verifyTurnstileToken(turnstileToken, clientIp);
  if (!turnstileCheck.ok) {
    if (file.path) await fs.promises.unlink(file.path).catch(() => {});
    const status = turnstileCheck.code === "missing_token" ? 400 : 403;
    return res.status(status).json({ message: turnstileCheck.reason || "Human verification failed" });
  }

  // Find user document
  const user = User.findById(req.user.uid);
  if (!user) {
    if (file.path) await fs.promises.unlink(file.path).catch(() => {});
    return res.status(401).json({ message: "User not found" });
  }

  // Generate unique S3 keys per user + hash and ingest binary via ArtifactVault
  const sanitizedFilename = file.originalname.replace(/\s+/g, "_"); // optional: sanitize spaces
  let filePath: string;
  let reportPath: string;
  try {
    const ingested = await ArtifactVault.ingestUploadedBinary(
      {
        role: "member",
        uid: String(user.id),
        hash,
        analysisType: type,
        filename: sanitizedFilename,
      },
      file.path
    );
    filePath = ingested.uploadKey;
    reportPath = ingested.reportJsonKey;
  } catch (ingestErr: any) {
    if (ingestErr.code === "invalid_file_format" || ingestErr.message?.includes("Invalid file format")) {
      return res.status(400).json({
        error: "invalid_file_format",
        message: ingestErr.message,
      });
    }
    throw ingestErr;
  }
  await ArtifactVault.initializePendingReport({
    role: "member",
    uid: String(user.id),
    hash,
    analysisType: type,
    filename: sanitizedFilename,
  });

  const meta = FileMeta.create({
    user: user.id, // <-- associate file with user
    filename: file.originalname,
    analysisType: type,
    filePath,
    reportPath,
    hash,
    status: "pending",
  });

  // Optional test account for a dynamic run, sent as ordinary multipart fields.
  const credentials = attachCredentials(meta, req.body);

  const remainingCredits = await CreditBank.getBalance(req.user.uid);
  res.json({ message: "File uploaded", meta, remainingCredits, ...credentials });
});

// List uploads for each user
app.get("/uploads", verifyToken, async (req: AuthRequest, res: Response) => {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });

  console.log("User UID from request:", req.user.uid); // Log UID from the request

  const user = User.findById(req.user.uid); // Find the user based on the Firebase UID
  if (!user) {
    console.error("User not found for UID:", req.user.uid); // Log if user is not found
    return res.status(401).json({ error: "User not found" });
  }

  console.log("User found:", user);

  const uploads = FileMeta.find({ user: user.id }); // Already sorted by uploadTime DESC

  // Which dynamic rows carry a test account, and under what name. The username
  // goes back to its owner so they can see which account is stored; the password
  // never leaves this server — it only travels on to the analysis engine.
  const credentials = DynamicCredentials.listFor(
    uploads.filter(u => u.analysisType === "dynamic").map(u => u.id)
  );

  const sanitized = uploads.map(u => ({
    id: String(u.id),
    filename: u.filename,
    hash: u.hash,
    analysisType: u.analysisType,
    filePath: u.filePath,
    status:
      u.status === "analyzing" && u.taskId?.startsWith("substatus:")
        ? u.taskId.replace("substatus:", "")
        : u.status,
    errorMessage:
      u.status === "error" && u.taskId?.startsWith("error:")
        ? u.taskId.replace("error:", "")
        : null,
    // Lets the UI say whether pressing Analyze will cost a credit — a retry of
    // an analysis that was already paid for does not.
    creditSpent: !!u.creditSpent,
    uploadTime: u.uploadTime,
    hasCredentials: credentials.has(u.id),
    // null also when the stored value cannot be decrypted — present, unreadable.
    credentialUsername: credentials.get(u.id)?.username ?? null,
  }));

  res.json(sanitized);
});

// Delete an upload record
app.delete("/uploads/:id", verifyToken, async (req: AuthRequest, res: Response) => {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });

  const user = User.findById(req.user.uid);
  if (!user) return res.status(401).json({ error: "User not found" });

  const upload = FileMeta.findOne({ id: Number(req.params.id), user: user.id } as any);
  if (!upload) return res.status(404).json({ error: "Upload not found" });

  if (upload.status === "analyzing") {
    return res.status(400).json({ error: "Cannot delete an upload while analysis is running" });
  }

  try {
    DynamicCredentials.remove(upload.id);
    FileMeta.delete(upload.id);

    // Physically clean up S3 reports (JSON + PDF across all versions) and uploaded binary if no other analysis shares it
    const otherUploads = FileMeta.find({ user: user.id, hash: upload.hash })
      .filter((r) => r.id !== upload.id);
    await ArtifactVault.purgeArtifacts(
      {
        role: "member",
        uid: user.id,
        hash: upload.hash,
        analysisType: upload.analysisType as any,
        filename: upload.filename,
        existingFilePath: upload.filePath,
        existingReportPath: upload.reportPath,
      },
      { includeBinary: otherUploads.length === 0 }
    );

    res.json({ message: "Upload record deleted successfully" });
  } catch (err) {
    console.error("Failed to delete upload record:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Check for duplicate file
app.post("/check-hash", verifyToken, async (req: AuthRequest, res: Response) => {
  console.log("Received request at /check-hash"); // Add this log for debugging

  if (!req.user) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const { hash, analysisType } = req.body;
  if (!hash || !analysisType) {
    return res.status(400).json({ error: "Missing hash or analysis type field" });
  }

  try {
    const user = User.findById(req.user.uid);
    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }

    console.log("Checking for user ID:", user.id); // Log the user ID being checked
    const file = FileMeta.findOne({ hash, user: user.id });
    if (!file) {
      return res.json({ status: "new" });
    }

    if (file.analysisType === analysisType) {
      return res.json({
        status: "duplicate",
        message: "File with same hash and analysis type already exists",
      });
    } else {
      const reportPath = reportKey(String(user.id), hash, analysisType);
      // Create a new entry in db with different analysis type. Reuses the same
      // uploaded binary (file.filePath) — only the report artifact differs.
      const meta = FileMeta.create({
        user: user.id, // <-- associate file with user
        filename: file.filename,
        analysisType,
        filePath: file.filePath,
        reportPath,
        hash,
        status: "pending",
      });
      await ArtifactVault.initializePendingReport({
        role: "member",
        uid: String(user.id),
        hash,
        analysisType,
        filename: file.filename,
      });

      // This is the other way a dynamic row is born — no /upload call happens on
      // this path, so the test account has to be accepted here too.
      const credentials = attachCredentials(meta, req.body);

      return res.json({
        status: "reuse",
        message: "File with same hash but different analysis type exists",
        ...credentials,
      });
    }

  } catch (err) {
    console.error("Check-hash error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * Managing the test account after the fact — the upload is long done, the user
 * has thought better of the account they gave, or they never gave one because
 * the row came from the `reuse` branch of /check-hash.
 *
 * Resolves the caller's own dynamic row for a hash, or the reason there isn't
 * one to write to. Ownership is not a filter to remember to add here: the lookup
 * is keyed on (user, hash, analysisType), so another account's row is not found
 * rather than found-and-refused.
 */
type DynamicRowLookup = { row: FileMetaRow } | { status: number; error: string };

function findDynamicRow(uid: string, hash: unknown): DynamicRowLookup {
  if (typeof hash !== "string" || !hash) return { status: 400, error: "Missing hash" };

  const user = User.findById(uid);
  if (!user) return { status: 401, error: "User not found" };

  const row = FileMeta.findOne({ user: user.id, hash, analysisType: "dynamic" });
  if (!row) return { status: 404, error: "No dynamic analysis found for this file" };

  // Only a run that hasn't started can still be told who to log in as. A row
  // that is `analyzing` has already handed its account to the engine, and a
  // `done` one cannot be re-run at all.
  if (row.status !== "pending" && row.status !== "error")
    return { status: 409, error: "Analysis is already running or finished" };

  return { row };
}

// Set or replace the account a dynamic run signs in with. Write-only by design:
// there is no route that reads a stored password back out.
app.post("/dynamic-credentials", verifyToken, async (req: AuthRequest, res: Response) => {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });

  const { hash, username, password } = req.body ?? {};
  const invalid = validateCredentials(username, password);
  if (invalid) return res.status(400).json({ error: invalid });

  if (!DynamicCredentials.supported())
    return res.status(503).json({ error: CREDENTIALS_UNAVAILABLE });

  const found = findDynamicRow(req.user.uid, hash);
  if (!("row" in found)) return res.status(found.status).json({ error: found.error });

  try {
    const saved = DynamicCredentials.set(found.row.id, { username, password });
    res.json({ message: "Credentials saved", ...saved });
  } catch (err) {
    console.error("Storing dynamic credentials failed:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Forget the account. Also the fix for a value that outlived its key: the run
// stays possible, it just runs signed out.
app.delete("/dynamic-credentials/:hash", verifyToken, async (req: AuthRequest, res: Response) => {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });

  const found = findDynamicRow(req.user.uid, req.params.hash);
  if (!("row" in found)) return res.status(found.status).json({ error: found.error });

  try {
    DynamicCredentials.remove(found.row.id);
    res.json({ message: "Credentials removed" });
  } catch (err) {
    console.error("Removing dynamic credentials failed:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * The three analyze endpoints, which differ only in which engine they call and
 * what they accept. This is where a credit is spent: one per analysis run, so a
 * single APK analysed both statically and dynamically costs two — they are two
 * separate `file_meta` rows and two separate pieces of work.
 *
 * A row is charged at most once, ever (`creditSpent`). Retrying a failed
 * analysis re-runs it for free, which is why nothing here ever needs to hand a
 * credit *back* — refunds would mean a positive ledger entry, and the audit
 * treats grants it cannot match to outside evidence as critical
 * (see "Credit integrity" in README.md).
 */
function analyzeHandler(opts: {
  analysisType: string;
  extension: string;
  label: string;
  run: (fileId: number) => Promise<unknown>;
}) {
  return async (req: AuthRequest, res: Response) => {
    if (!req.user) return res.status(401).json({ error: "Unauthorized" });

    const { hash } = req.body;
    if (!hash) return res.status(400).json({ error: "Missing hash" });

    // Find the current user
    const user = User.findById(req.user.uid);
    if (!user) return res.status(401).json({ error: "User not found" });

    const upload = FileMeta.findOne({ user: user.id, hash, analysisType: opts.analysisType });
    if (!upload) return res.status(404).json({ error: "Upload not found" });
    if (!upload.filename.endsWith(opts.extension))
      return res.status(400).json({ error: "Not eligible for analysis" });

    // Claim the row *before* charging. The UPDATE only succeeds for one caller,
    // so two Analyze clicks racing each other can't both dispatch and both pay.
    if (!FileMeta.claim(upload.id))
      return res.status(400).json({ error: "File already analyzing or done" });

    let remainingCredits: number;
    let activeChargeRef: string | null = null; // Track if this run actually charged a credit

    try {
      if (upload.creditSpent) {
        // Already paid for — a retry after a failed run costs nothing.
        remainingCredits = await CreditBank.getBalance(req.user.uid);
      } else {
        const charge = await CreditBank.chargeForAnalysis({
          uid: req.user.uid,
          fileId: upload.id,
          label: `${opts.label} ${hash}`,
        });
        if (!charge.ok) {
          FileMeta.release(upload.id);
          return res
            .status(charge.code === "insufficient_credits" ? 402 : 500)
            .json({ error: charge.message });
        }
        activeChargeRef = charge.chargeRef;
        FileMeta.markCreditSpent(upload.id);
        remainingCredits = charge.balance;
      }
    } catch (err) {
      console.error(`${opts.label}: credit charge failed:`, err);
      FileMeta.release(upload.id);
      return res.status(500).json({ error: "Server error" });
    }

    // Dispatch on the row id, not the hash: it is the row this caller has just
    // paid for, and a hash can belong to more than one user's upload.
    opts.run(upload.id)
      .then(() => console.log(`${opts.label} completed`))
      .catch(async (err) => {
        console.error(`${opts.label} error:`, err);
        // Only refund if THIS run actually paid a credit, preventing free-retry infinite minting
        if (activeChargeRef) {
          try {
            const refundRes = await CreditBank.refundFailedAnalysis({
              uid: req.user!.uid,
              fileId: upload.id,
              chargeRef: activeChargeRef,
              reasonNote: `${opts.label} failure refund`,
            });
            FileMeta.update(upload.id, {
              status: "error",
              creditSpent: refundRes.ok ? 0 : 1,
            });
          } catch (refundErr) {
            console.error(
              `Failed to refund credit for failed analysis ${upload.id}:`,
              refundErr
            );
            FileMeta.update(upload.id, { status: "error" });
          }
        } else {
          FileMeta.update(upload.id, { status: "error" });
        }
      });

    res.json({ message: "Analysis triggered", remainingCredits });
  };
}

app.post("/ios-static-analyze", verifyToken, analyzeHandler({
  analysisType: "static",
  extension: ".ipa",
  label: "iOS Static Analysis",
  run: analyzeIOSStatic,
}));

app.post("/android-static-analyze", verifyToken, analyzeHandler({
  analysisType: "static",
  extension: ".apk",
  label: "Android Static Analysis",
  run: analyzeAndroidStatic,
}));

app.post("/android-dynamic-analyze", verifyToken, analyzeHandler({
  analysisType: "dynamic",
  extension: ".apk",
  label: "Android Dynamic Analysis",
  run: analyzeAndroidDynamic,
}));


app.post("/generate-report", verifyToken, async (req: AuthRequest, res: Response) => {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });

  const { hash, type, lang } = req.body;
  if (!hash || !type) return res.status(400).json({ error: "Missing fields" });

  const targetLang = lang === "en" ? "en" : "zh-TW";
  const langSuffix = targetLang === "en" ? "_en" : "_zh";

  // Find the current user
  const user = User.findById(req.user.uid);
  if (!user) return res.status(401).json({ error: "User not found" });

  try {
    const reportMeta = FileMeta.findOne({ hash, analysisType: type, user: user.id });
    if (!reportMeta) return res.status(404).json({ error: "Report not found" });

    const result = await ArtifactVault.acquireReportDownloadUrl({
      scope: {
        role: "member",
        uid: user.id,
        hash,
        analysisType: type as any,
        filename: reportMeta.filename,
        existingFilePath: reportMeta.filePath,
        existingReportPath: reportMeta.reportPath,
      },
      lang: lang === "en" ? "en" : "zh-TW",
      consumeDownloadQuota: () => FileMeta.decrementDownloadsRemaining(reportMeta.id),
    });

    if (!result.ok) {
      if (result.code === "quota_exceeded") {
        return res.status(403).json({ error: result.message });
      }
      if (result.code === "report_json_missing" || result.code === "report_file_missing") {
        return res.status(404).json({ error: result.message });
      }
      return res.status(500).json({ error: result.message });
    }

    return res.json({ url: result.url, expiresIn: result.expiresIn });
  } catch (err: any) {
    console.error("Report generation error:", err);
    res.status(500).json({ error: err?.message || "Failed to generate report" });
  }
});

app.patch("/retry", verifyToken, async (req: AuthRequest, res: Response) => {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });

  const { hash, type } = req.body;
  if (!hash || !type) return res.status(400).json({ error: "Missing fields" });

    // Find the current user
  const user = User.findById(req.user.uid);
  if (!user) return res.status(401).json({ error: "User not found" });

  try {
    const fileDoc = FileMeta.findOne({ hash, analysisType: type, user: user.id });
    if (!fileDoc) return res.status(404).json({ error: "File not found" });

    // Only a failed run can be retried. Re-running is free (the row is already
    // paid for), so allowing it from `done` would be an unlimited supply of free
    // analyses, and from `analyzing` it would re-dispatch a job that is still live.
    if (fileDoc.status !== "error")
      return res.status(400).json({ error: "Only a failed analysis can be retried" });

    FileMeta.update(fileDoc.id, { status: "pending" });

    res.json({ message: "File reset to pending" });
  } catch (err) {
    console.error("Retry error:", err);
    res.status(500).json({ error: "Failed to reset file status" });
  }
});

app.post("/api/initUser", verifyToken, async (req: any, res) => {
  const uid = req.user.uid;
  const email = req.user.email;

  try {
    // SQLite user record — used for file ownership / email lookups (no credits here).
    let user = User.findById(uid);
    if (!user) {
      user = User.create(uid, email);
    }

    // Ensure user credits are seeded idempotently via CreditBank
    const seedRes = await CreditBank.ensureUserSeeded(uid, email);
    const credits = seedRes.ok ? seedRes.balance : 0;

    res.json({ uid, email, credits });
  } catch (err) {
    console.error("Init user error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/me", verifyToken, async (req: AuthRequest, res: Response) => {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });
  try {
    const user = User.findById(req.user.uid);
    if (!user) return res.status(404).json({ error: "User not found" });
    const credits = await CreditBank.getBalance(req.user.uid);
    res.json({ uid: user.id, email: user.email, credits });
  } catch (err) {
    console.error("Get user error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/getCredits", verifyToken, async (req: AuthRequest, res: Response) => {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });

  try {
    const credits = await CreditBank.getBalance(req.user.uid);
    return res.json({ credits });
  } catch (err) {
    console.error("Get credits error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// NOTE: there is deliberately no client-callable "spend a credit" endpoint.
// Credits are now spent by the analyze routes above, on the server, as part of
// dispatching the work they pay for — a browser that simply never called such an
// endpoint used to get its analysis for nothing.


export { app, verifyToken };

if (require.main === module) {
  app.listen(3000, "0.0.0.0", () => {
    console.log("Backend running on http://localhost:3000");
    // Prices are listed in USD but charged in TWD; keep the conversion rate warm.
    // Non-blocking — checkout falls back to the last known rate if this fails.
    startFxRefresh();
    // Daily snapshot + reconciliation of every credit balance against the ledger.
    startCreditAudit();
    // Drop stored test accounts whose analysis was never run — a password is a
    // liability for exactly as long as it is kept.
    startCredentialSweep();
    // Storage hygiene: purge expired guest APKs and reports from S3 on schedule
    startStorageHygieneSchedule();
  });
}
