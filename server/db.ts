import Database from "better-sqlite3";
import fs from "fs";
import path from "path";

// Single-file SQLite database. The data/ dir must be a mounted volume in Docker
// so the DB survives container rebuilds (see docker-compose.yml).
const DB_PATH = process.env.SQLITE_PATH ?? path.join(__dirname, "data", "cmaa.db");

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

export const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id    TEXT PRIMARY KEY,   -- Firebase uid
    email TEXT NOT NULL
    -- Credit balance lives in Firestore (users/{uid}.credits) — not stored here.
  );

  CREATE TABLE IF NOT EXISTS file_meta (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user         TEXT NOT NULL REFERENCES users(id),
    filename     TEXT NOT NULL,
    analysisType TEXT NOT NULL,
    filePath     TEXT NOT NULL,   -- S3 key of the uploaded binary
    reportPath   TEXT NOT NULL,   -- S3 key of the analysis report
    hash         TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending','analyzing','done','error')),
    creditSpent  INTEGER NOT NULL DEFAULT 0,  -- 1 once a credit has paid for this analysis
    taskId       TEXT,
    uploadTime   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE (user, hash, analysisType)
  );

  -- The test account a dynamic analysis signs into the app with, so the engine
  -- can get past the login screen and enumerate what is behind it. Its own table
  -- rather than columns on file_meta: a secret that can be dropped in one
  -- statement, is never loaded by the paths that don't need it, and leaves no
  -- empty columns on the static rows that can never have one.
  -- Both values are sealed (AES-256-GCM, server/secretbox.ts) — the database
  -- alone is not a list of passwords.
  CREATE TABLE IF NOT EXISTS dynamic_credentials (
    fileId    INTEGER PRIMARY KEY REFERENCES file_meta(id) ON DELETE CASCADE,
    username  TEXT NOT NULL,   -- sealed
    password  TEXT NOT NULL,   -- sealed
    updatedAt TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  );

  CREATE TABLE IF NOT EXISTS guest_jobs (
    jobId              TEXT PRIMARY KEY,
    analysisType       TEXT NOT NULL CHECK (analysisType IN ('static','dynamic')),
    fileHash           TEXT NOT NULL,
    fileType           TEXT CHECK (fileType IN ('apk','ipa')),
    filename           TEXT,
    uploadPath         TEXT,      -- S3 key of the uploaded binary
    reportPath         TEXT,      -- S3 key of the PDF report
    status             TEXT NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending','uploaded','analyzing','done','error','expired')),
    downloadToken      TEXT,
    downloadsRemaining INTEGER NOT NULL DEFAULT 3,
    createdAt          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    expiresAt          TEXT NOT NULL
  );

  -- Unique only across real tokens — jobs awaiting a token (NULL) are not indexed.
  CREATE UNIQUE INDEX IF NOT EXISTS guest_jobs_downloadToken
    ON guest_jobs (downloadToken) WHERE downloadToken IS NOT NULL;
`);

// Add columns for guest_jobs if they do not exist
for (const [col, decl] of [
  ["isPaid", "INTEGER NOT NULL DEFAULT 0"],
  ["paidAt", "TEXT"],
  ["summaryPreview", "TEXT"],
  ["secretKey", "TEXT"],
  ["appUsername", "TEXT"],
  ["appPassword", "TEXT"],
  ["discardedAt", "TEXT"],
] as const) {
  const exists = (db.prepare("PRAGMA table_info(guest_jobs)").all() as {
    name: string;
  }[]).some((c) => c.name === col);
  if (!exists) db.exec(`ALTER TABLE guest_jobs ADD COLUMN ${col} ${decl}`);
}

// `file_meta.creditSpent` arrived when the charge moved from upload time to
// analysis time. Every row that predates the column was already paid for at
// upload, so they are backfilled as paid — deploying this must never charge
// someone a second time for an analysis they have already bought.
const fileMetaColumns = db.prepare("PRAGMA table_info(file_meta)").all() as { name: string }[];
if (!fileMetaColumns.some((c) => c.name === "creditSpent")) {
  db.exec(`
    ALTER TABLE file_meta ADD COLUMN creditSpent INTEGER NOT NULL DEFAULT 0;
    UPDATE file_meta SET creditSpent = 1;
  `);
}
