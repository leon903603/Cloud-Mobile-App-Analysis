import { db } from "../db";

export type FileStatus = "pending" | "analyzing" | "done" | "error";

export interface FileMetaRow {
  id: number;
  user: string; // users.id (Firebase uid)
  filename: string;
  analysisType: string;
  filePath: string;
  reportPath: string;
  hash: string;
  status: FileStatus;
  /** 1 once a credit has paid for this analysis. Re-running it is then free. */
  creditSpent: number;
  taskId: string | null;
  uploadTime: string; // ISO 8601
}

type Filter = Partial<Pick<FileMetaRow, "user" | "hash" | "analysisType">>;

function where(filter: Filter): { sql: string; values: unknown[] } {
  const keys = Object.keys(filter) as (keyof Filter)[];
  return {
    sql: keys.map((k) => `${k} = ?`).join(" AND "),
    values: keys.map((k) => filter[k]),
  };
}

const insertStmt = db.prepare(`
  INSERT INTO file_meta (user, filename, analysisType, filePath, reportPath, hash, status)
  VALUES (@user, @filename, @analysisType, @filePath, @reportPath, @hash, @status)
`);
const findByIdStmt = db.prepare("SELECT * FROM file_meta WHERE id = ?");
const claimStmt = db.prepare(
  "UPDATE file_meta SET status = 'analyzing' WHERE id = ? AND status = 'pending'"
);
const releaseStmt = db.prepare("UPDATE file_meta SET status = 'pending' WHERE id = ?");
const markCreditSpentStmt = db.prepare("UPDATE file_meta SET creditSpent = 1 WHERE id = ?");

export const FileMeta = {
  create(data: {
    user: string;
    filename: string;
    analysisType: string;
    filePath: string;
    reportPath: string;
    hash: string;
    status?: FileStatus;
  }): FileMetaRow {
    const info = insertStmt.run({ status: "pending", ...data });
    return findByIdStmt.get(info.lastInsertRowid) as FileMetaRow;
  },

  findById(id: number): FileMetaRow | undefined {
    return findByIdStmt.get(id) as FileMetaRow | undefined;
  },

  findOne(filter: Filter): FileMetaRow | undefined {
    const { sql, values } = where(filter);
    return db
      .prepare(`SELECT * FROM file_meta WHERE ${sql} LIMIT 1`)
      .get(...values) as FileMetaRow | undefined;
  },

  find(filter: Filter): FileMetaRow[] {
    const { sql, values } = where(filter);
    return db
      .prepare(`SELECT * FROM file_meta WHERE ${sql} ORDER BY uploadTime DESC, id DESC`)
      .all(...values) as FileMetaRow[];
  },

  /**
   * Move a row from `pending` to `analyzing` in a single statement. Returns
   * false if another request got there first — this is what stops a
   * double-clicked Analyze button from dispatching, and paying for, one
   * analysis twice.
   */
  claim(id: number): boolean {
    return claimStmt.run(id).changes === 1;
  },

  /** Give a claimed row back, for when the credit charge fails after claiming. */
  release(id: number): void {
    releaseStmt.run(id);
  },

  markCreditSpent(id: number): void {
    markCreditSpentStmt.run(id);
  },

  update(id: number, patch: Partial<Pick<FileMetaRow, "status" | "taskId">>): void {
    const keys = Object.keys(patch) as (keyof typeof patch)[];
    if (keys.length === 0) return;
    db.prepare(`UPDATE file_meta SET ${keys.map((k) => `${k} = ?`).join(", ")} WHERE id = ?`)
      .run(...keys.map((k) => patch[k]), id);
  },

  delete(id: number): void {
    db.prepare("DELETE FROM file_meta WHERE id = ?").run(id);
  },
};
